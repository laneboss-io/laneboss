package service

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

type changePublicationSource interface {
	ChangePublication(context.Context, api.Scope, api.EffectLease) (api.PublishChangeRequest, api.MutationReceipt, error)
}

func (s *Server) runChangePublication(ctx context.Context, scope api.Scope, lease api.EffectLease, runtime api.RuntimeServices) (api.EffectOutcome, error) {
	var zero api.EffectOutcome
	source, ok := s.deps.Store.(changePublicationSource)
	if !ok || !usableDependency(source) || !usableDependency(runtime.Publisher) {
		return zero, serviceError(api.CodePrerequisite, "org publication requires its original store reservation and pinned publisher")
	}
	request, pending, err := source.ChangePublication(ctx, scope, lease)
	if err != nil {
		return zero, err
	}
	if pending.Deferred == nil || pending.Reply != nil || request.Lease.ClaimID != lease.ClaimID || request.Lease.Record.Generation != lease.Record.Generation || pending.Deferred.EffectID != lease.Record.Effect.ID || pending.Deferred.OperationID != lease.Record.Effect.OperationID {
		return zero, serviceError(api.CodeIntegrity, "publication coordinator lost its exact original deferred request")
	}
	var receipt api.ChangeReceipt
	if lease.Record.Generation > 2 {
		receipt, err = runtime.Publisher.ReconcileChange(ctx, scope, request)
	} else {
		receipt, err = runtime.Publisher.PublishChange(ctx, scope, request)
	}
	if err != nil {
		if refusal := terminalPlanRefusal(err); refusal != nil {
			copy := *refusal
			copy.OperationID = pending.Operation.ID
			outcome := api.EffectOutcome{EffectID: lease.Record.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "failed", Error: &copy,
				Reply: &api.DeferredCompletion{Deferred: *pending.Deferred, Reply: api.RPCReply{Error: &copy}}}
			if err := api.ValidateDeferredCompletion(pending, lease, outcome); err != nil {
				return zero, err
			}
			return outcome, nil
		}
		return zero, err
	}
	if receipt.SimulatedPresence != (pending.SimulatedPresence || pending.Operation.SimulatedPresence) {
		return zero, serviceError(api.CodeIntegrity, "publication dropped original simulated authority provenance")
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return zero, err
	}
	outcome := api.EffectOutcome{EffectID: lease.Record.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "succeeded", Publication: &receipt,
		Reply: &api.DeferredCompletion{Deferred: *pending.Deferred, Reply: api.RPCReply{Result: raw}}}
	if err := api.ValidateDeferredCompletion(pending, lease, outcome); err != nil {
		return zero, err
	}
	return outcome, nil
}
