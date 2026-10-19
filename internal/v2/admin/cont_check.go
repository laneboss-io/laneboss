package admin

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// A continuation keeps its real internal request. It never borrows a public
// request, human proof or completed launch to authorize pre-execution work.
func (s *Service) contInput(ctx context.Context, scope api.Scope, record api.LaunchPlanRecord, cause api.InternalIntent, raw []byte) (input api.ContinuationRequest, err error) {
	r := record.Reservation
	previous := api.LifeRef{LifeID: r.Target.LifeID, Run: r.Target.Run - 1}
	legacy := false
	if api.DecodeObject(raw, &input) != nil {
		var original api.ContinuationClaimRequest
		if api.DecodeObject(raw, &original) != nil {
			return input, failure(api.CodeIntegrity, "continuation has no retained internal envelope")
		}
		c := original.Intent
		input = original.Request
		if c.Kind != api.InternalProfileContinue || c.Config != r.Config || c.RequestedBy != r.RequestedBy || c.CauseOperationID != r.OperationID || c.CauseRequestID != r.RequestID || c.Target != previous || c.CancellationEpoch != r.CancellationEpoch || c.LogicalTurnID != input.Swap.LogicalTurnID {
			return input, failure(api.CodeIntegrity, "retained continuation envelope changed its original cause")
		}
		legacy = true
	}
	if api.Digest(digestBytes(raw)) != r.RequestSHA256 || r.OriginalRequest.SHA256 != r.RequestSHA256 || cause.ID != "" && (cause.Config != r.Config || cause.Target != r.Target || cause.CauseOperationID != r.OperationID || cause.CauseRequestID != r.RequestID || cause.RequestedBy != r.RequestedBy || cause.CancellationEpoch != r.CancellationEpoch || cause.LogicalTurnID != input.Swap.LogicalTurnID) {
		return input, failure(api.CodeIntegrity, "continuation lost its original internal request or cause")
	}
	i, err := s.deps.Store.ContinuationIntent(ctx, scope, input.IntentID)
	if err != nil {
		return input, err
	}
	swap := input.Swap
	status := i.Status == "claimed" || i.Status == "completed" && (legacy || cause.ID == "" && record.Phase == "opened")
	if i.ID != input.IntentID || !status || i.OperationID != r.OperationID || i.Target != previous || i.ExpectedGeneration != r.BaseGeneration || i.CancellationEpoch != r.CancellationEpoch || i.LogicalTurnID != swap.LogicalTurnID || !reflect.DeepEqual(i.Swap, swap) || swap.OperationID != r.OperationID || swap.ExpectedGeneration != r.BaseGeneration || swap.CancellationEpoch != r.CancellationEpoch || swap.CausingRun != previous.Run || swap.ContinuationRun != r.Target.Run || swap.Limit.Target != previous || i.Eligibility.ID != swap.EligibilityID || (legacy || i.Status == "completed") && i.Slot == nil || i.Slot != nil && (i.Slot.ProfileGrantID != swap.ProfileGrantID || i.Slot.ProfileID != swap.ToProfileID) {
		return input, failure(api.CodeConflict, "continuation source lost its claimed run, profile or epoch")
	}
	return input, nil
}
