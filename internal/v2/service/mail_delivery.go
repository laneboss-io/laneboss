package service

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

type mailDeliveryCoordinator interface {
	ReconcileDelivery(context.Context, api.Scope, api.EffectLease) (api.ProcessObservation, error)
}

func (s *Server) runMailDelivery(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.EffectOutcome, error) {
	outcome := api.EffectOutcome{EffectID: lease.Record.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "succeeded"}
	s.mu.RLock()
	coordinator, ok := s.runtime.Delivery.(mailDeliveryCoordinator)
	s.mu.RUnlock()
	if !ok || !usableDependency(coordinator) {
		return outcome, api.NotImplemented("lb-v2-messaging", "installed logical-turn delivery coordinator")
	}
	observation, err := coordinator.ReconcileDelivery(ctx, scope, lease)
	if err != nil {
		return outcome, err
	}
	if lease.Record.Effect.Deliver == nil {
		return outcome, serviceError(api.CodeIntegrity, "mail coordinator received another effect payload")
	}
	output := lease.Record.Effect.Deliver.Content
	outcome.Observation, outcome.Output = &observation, &output
	return outcome, nil
}
