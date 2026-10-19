package api

import (
	"bytes"
	"reflect"
	"time"
)

func validDeferredMutation(tx Transaction, row publicWrites) bool {
	if tx.Deferred == nil {
		if row.deferred != "" {
			// Final apply success is sealed by CompleteEffect, never submitted
			// before publication in a new public transaction.
			return false
		}
		// A final receipt cannot accompany publication that has not run yet.
		for _, effect := range tx.Effects {
			if effect.ApplyChange != nil {
				return false
			}
		}
		return true
	}
	deferred := tx.Deferred
	if row.deferred == "" || tx.Reply != nil || len(tx.Effects) != 1 ||
		tx.Scope.Actor.Kind != "lane" || tx.Scope.Actor.Level != 6 || tx.Scope.Actor.LifeID == "" ||
		deferred.OperationID == "" || deferred.EffectID == "" ||
		!deferredRequest(tx.Scope.Config, tx.Scope.Request, tx.RawRequest, deferred.Key) {
		return false
	}
	effect := tx.Effects[0]
	if effect.ID != deferred.EffectID || effect.OperationID != deferred.OperationID ||
		effect.Context == nil || effect.Context.Kind != row.deferred ||
		effect.Context.CauseRequestID != tx.Scope.Request.RequestID || effect.Context.RequestedBy != tx.Scope.Actor {
		return false
	}
	// Only org.change.apply currently defers a final reply. The regular public
	// row and the normal guard/effect discriminants still apply to this union.
	var request ChangeApplyRequest
	if effect.ApplyChange == nil || DecodeObject(tx.Scope.Request.Params, &request) != nil ||
		*effect.ApplyChange != request || request.ChangeID == "" || request.ApprovalID == "" || request.ExpectedGeneration == 0 {
		return false
	}
	orgCAS, approval := false, false
	for _, compare := range tx.Compare {
		orgCAS = orgCAS || compare.Kind == CompareOrg && compare.ID != "" && compare.Generation == request.ExpectedGeneration
	}
	for _, guard := range tx.Guards {
		if use := guard.Approval; use != nil {
			if approval || use.ChangeID != request.ChangeID || use.ApprovalID != request.ApprovalID ||
				use.BaseGeneration != request.ExpectedGeneration || !bindingDigest.MatchString(string(use.ManifestSHA256)) {
				return false
			}
			approval = true
		}
	}
	// Presence is required by the shared public ApprovalUse guard check.
	return orgCAS
}

func deferredRequest(config string, request Request, raw []byte, key RequestKey) bool {
	if config == "" || request.Config != config || request.Protocol != Protocol || request.Schema != SchemaVersion ||
		request.RequestID == "" || key.IdempotencyKey == "" ||
		key != (RequestKey{Method: request.Method, IdempotencyKey: request.IdempotencyKey, RequestSHA256: request.RequestSHA256}) {
		return false
	}
	var original Request
	if DecodeObject(raw, &original) != nil || original.Protocol != request.Protocol || original.Schema != request.Schema ||
		original.Config != request.Config || original.Method != request.Method || original.RequestID != request.RequestID ||
		original.IdempotencyKey != request.IdempotencyKey || original.RequestSHA256 != request.RequestSHA256 ||
		original.Proof != nil || request.Proof != nil {
		return false
	}
	originalParams, err := CanonicalJSON(original.Params)
	if err != nil {
		return false
	}
	params, err := CanonicalJSON(request.Params)
	if err != nil || !bytes.Equal(originalParams, params) {
		return false
	}
	digest, err := RequestDigest(request)
	return err == nil && digest == key.RequestSHA256
}

// ValidateDeferredCompletion checks correlation and the closed result union.
// The store must also check the persisted reservation, actual current effect
// claim, approval consumption and publisher marker under its commit boundary.
// No Frame/Connection callback or external publication runs under that lock.
func ValidateDeferredCompletion(receipt MutationReceipt, lease EffectLease, outcome EffectOutcome) error {
	invalid := func() error {
		return &Error{Code: CodeInvalid, Message: "invalid deferred reply completion",
			Instead: "Complete the original guarded effect once under its current claim.", Owner: "lb-v2-service"}
	}
	if receipt.Deferred == nil || receipt.Reply != nil || outcome.Reply == nil ||
		(receipt.Operation.Status != "pending" && receipt.Operation.Status != "running") {
		return invalid()
	}
	deferred, effect := *receipt.Deferred, lease.Record.Effect
	var request Request
	if DecodeObject(receipt.RawRequest, &request) != nil ||
		!deferredRequest(receipt.Config, request, receipt.RawRequest, receipt.Key) ||
		deferred.Key != receipt.Key || deferred.OperationID != receipt.Operation.ID ||
		deferred != outcome.Reply.Deferred || deferred.EffectID != effect.ID ||
		effect.OperationID != deferred.OperationID || effect.Context == nil ||
		effect.Context.Config != receipt.Config || effect.Context.Kind != InternalOrgPublish ||
		effect.Context.RequestedBy != receipt.Actor || effect.Context.CauseOperationID != deferred.OperationID ||
		effect.Context.CauseRequestID != request.RequestID || effect.Context.EffectID != effect.ID ||
		request.Method != "org.change.apply" || effect.ApplyChange == nil ||
		lease.ClaimID == "" || lease.Record.ClaimID != lease.ClaimID || !EffectLeaseClaimed(lease) ||
		lease.Record.Generation == 0 || lease.Record.Outcome != nil ||
		lease.Record.ClaimantID == "" || lease.ExpiresAt == "" || lease.Record.ClaimExpiresAt != lease.ExpiresAt ||
		outcome.EffectID != effect.ID || outcome.ClaimID != lease.ClaimID ||
		outcome.ExpectedGeneration != lease.Record.Generation ||
		outcome.HelperLease != nil || outcome.Prepared != nil || outcome.Process != nil || outcome.Observation != nil ||
		outcome.Abort != nil || outcome.Release != nil || outcome.Delivery != nil || outcome.Bootstrap != nil ||
		outcome.Deployment != nil || outcome.Output != nil || outcome.LaunchPlan != nil {
		return invalid()
	}
	var apply ChangeApplyRequest
	if DecodeObject(request.Params, &apply) != nil || apply != *effect.ApplyChange {
		return invalid()
	}
	reply := outcome.Reply.Reply
	if (reply.Error == nil) == (len(reply.Result) == 0) {
		return invalid()
	}
	if reply.Error != nil {
		if outcome.Status != "failed" || outcome.Error == nil || outcome.Publication != nil ||
			!reflect.DeepEqual(reply.Error, outcome.Error) || reply.Error.OperationID != deferred.OperationID {
			return invalid()
		}
		return nil
	}
	var publication ChangeReceipt
	if outcome.Status != "succeeded" || outcome.Error != nil || outcome.Publication == nil ||
		DecodeObject(reply.Result, &publication) != nil || publication != *outcome.Publication ||
		publication.ID == "" || publication.ChangeID != apply.ChangeID || publication.ApprovalID != apply.ApprovalID ||
		publication.OldGeneration != apply.ExpectedGeneration || publication.NewGeneration != publication.OldGeneration+1 ||
		publication.NewGeneration == 0 || !bindingDigest.MatchString(string(publication.ManifestSHA256)) || publication.AppliedAt == "" {
		return invalid()
	}
	instant, err := time.Parse(time.RFC3339Nano, string(publication.AppliedAt))
	if err != nil || instant.UTC().Format(time.RFC3339Nano) != string(publication.AppliedAt) {
		return invalid()
	}
	return nil
}
