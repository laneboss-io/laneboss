package guidance

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// The dispatcher owns same-key pending public receipt serialization. This
// additional completed-reply read supports direct bound consumers, without
// awaiting the current handler's own still-pending public receipt.
func (s *Service) exactReply(ctx context.Context, scope api.Scope, request api.GuidanceRequest) (api.Guidance, bool, error) {
	if scope.Request.Method != "guidance.select" {
		return api.Guidance{}, false, nil
	}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, requestKey(scope))
	var typed *api.Error
	if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
		return api.Guidance{}, false, nil
	}
	if err != nil {
		return api.Guidance{}, false, err
	}
	if receipt.Reply == nil {
		return api.Guidance{}, false, nil
	}
	current, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.Guidance{}, true, err
	}
	if scope.PolicyGeneration != 0 && scope.PolicyGeneration != current.Generation {
		return api.Guidance{}, true, integrity("current policy differs from the authorization scope")
	}
	generation, err := api.PolicyGenerationForReplay(scope, current, receipt)
	if err != nil {
		return api.Guidance{}, true, err
	}
	if receipt.Reply.Error != nil {
		return api.Guidance{}, true, receipt.Reply.Error
	}
	if receipt.Operation.Status != "succeeded" {
		return api.Guidance{}, true, integrity("guidance exact receipt is not a completed operation")
	}
	history, err := s.deps.Store.PolicyAt(ctx, scope, generation)
	if err != nil {
		return api.Guidance{}, true, err
	}
	if history.Generation != generation || !validDigest(history.SHA256) {
		return api.Guidance{}, true, integrity("exact guidance receipt has no approved historical policy")
	}
	var result api.Guidance
	if err := api.DecodeObject(receipt.Reply.Result, &result); err != nil {
		return api.Guidance{}, true, integrity("guidance exact receipt has invalid result bytes")
	}
	if result.PolicyGeneration != generation || result.Target.LifeID != request.Target.LifeID ||
		result.Target.Run == 0 || result.Target.Run > request.Target.Run || result.Task != request.Task || result.LogicalTurnID != request.LogicalTurnID {
		return api.Guidance{}, true, integrity("guidance exact receipt differs from its authenticated request")
	}
	r, found, err := s.lookupClaim(ctx, scope, request)
	if err != nil {
		return api.Guidance{}, true, err
	}
	if !found {
		return api.Guidance{}, true, integrity("guidance exact receipt lost its retained selection")
	}
	if err := api.ValidateGuidanceReservation(r); err != nil {
		return api.Guidance{}, true, err
	}
	retained, err := validateCompletedSelection(r, request, generation)
	if err != nil {
		return api.Guidance{}, true, err
	}
	if !reflect.DeepEqual(*retained, result) {
		return api.Guidance{}, true, integrity("guidance exact reply changed its retained selection")
	}
	// Preserve the actual stored bytes; no selection, new reply or proof use.
	encoded, err := json.Marshal(*retained)
	if err != nil || string(encoded) != string(receipt.Reply.Result) {
		return api.Guidance{}, true, integrity("guidance exact receipt encoding changed")
	}
	return result, true, nil
}
