package store

import (
	"bytes"
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

// Native worker completion keeps its public dispatcher pending until the
// owning coordinator seals the exact reply. Historical verification reads
// that reply after the reservation has been atomically collected.
func (s *Service) reviewWaitsForReply(ctx context.Context, db queryer, operation api.ID) (bool, error) {
	var r reviewRecord
	if err := storedProjection(ctx, db, "review_job", operation, &r); absent(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if r.Test != nil {
		return false, nil
	}
	expectedMethod := api.Method("lane.review")
	if r.Preparation != nil {
		expectedMethod = "grants.test-child"
	}
	if r.Job.Intent.OperationID != operation || r.Request.Method != expectedMethod || r.Request.Config != s.deps.Config {
		return false, fault(api.CodeIntegrity, "review completion lost its original request")
	}
	receipt, err := s.lookupReceipt(ctx, db, r.Scope, requestKey(r.Request))
	if err != nil {
		return false, errors.Join(fault(api.CodeIntegrity, "review completion lost its original dispatcher receipt"), err)
	}
	var request api.Request
	if api.DecodeObject(receipt.RawRequest, &request) != nil || !sameValue(request, r.Request) || receipt.Operation.ID != operation || receipt.Actor != r.Scope.Actor {
		return false, fault(api.CodeIntegrity, "review completion changed its immutable dispatcher bytes")
	}
	return receipt.Reply == nil, nil
}

func (s *Service) ReviewOwnsEffect(ctx context.Context, scope api.Scope, effect api.Effect) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return false, err
	}
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return false, err
	}
	if effect.Worker == nil || effect.Worker.Kind != "export" && effect.Worker.Kind != "test" {
		return false, nil
	}
	var r reviewRecord
	if err := storedProjection(ctx, s.db, "review_job", effect.OperationID, &r); reviewMissing(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if effect.ID != r.Job.Lease.EffectID || effect.Context == nil || effect.Context.Target != r.Job.Lease.Target || effect.OperationID != r.Job.Intent.OperationID || !sameValue(*effect.Worker, r.Job.Plan) {
		return false, fault(api.CodeIntegrity, "retained review effect changed its original owner")
	}
	return true, nil
}

func (s *Service) ReviewAcknowledgement(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.WorkerResultReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, err := s.reviewRetirementClaim(ctx, scope, lease)
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	if r.Ack == nil {
		return api.WorkerResultReceipt{}, fault(api.CodePrerequisite, "original review worker has not submitted its authenticated result")
	}
	meta, raw, err := objectRow(ctx, s.db, r.Ack.Receipt.Result.ID)
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	if meta.Ref != r.Ack.Receipt.Result || !bytes.Equal(raw, r.Ack.Submission.Result) {
		return api.WorkerResultReceipt{}, fault(api.CodeIntegrity, "review acknowledgement lost its exact result bytes")
	}
	return r.Ack.Receipt, validateReviewOutput(r, raw)
}
