package service

import (
	"bytes"
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

type ownedFailureStore interface {
	FailOwnedEffect(context.Context, api.Scope, api.EffectLease, *api.Error, *api.ProcessObservation) (api.Commit, error)
}

// Private error diagnostics stay with the live attempt. The store persists
// every public outcome field, so readback compares those exact JSON values.
func sameOwnedOutcome(left, right api.EffectOutcome) bool {
	a, first := json.Marshal(left)
	b, second := json.Marshal(right)
	return first == nil && second == nil && bytes.Equal(a, b)
}

// Only a direct refusal from the failure writer may keep an owned attempt
// pending for containment. Joined storage failures remain fatal to this loop.
func ownedFailurePending(err error) bool {
	failure, ok := err.(*api.Error)
	return ok && failure.Code == api.CodeContainmentUnknown
}

func (s *Server) failOwnedEffect(ctx context.Context, scope api.Scope, lease api.EffectLease, outcome api.EffectOutcome, cause error) (api.EffectOutcome, error) {
	if lease.Record.Effect.Worker != nil && lease.Record.Effect.Worker.Kind == "archive" {
		observation, err := s.retireArchive(ctx, scope, lease)
		if err != nil {
			return outcome, err
		}
		outcome.Observation = observation
	}
	store, ok := s.deps.Store.(ownedFailureStore)
	if !ok {
		return outcome, api.NotImplemented("lb-v2-service", "owned terminal failure writer")
	}
	failure := *typedError(cause)
	if failure.Instead == "" {
		failure.Instead = "Preserve the workspace and inspect this failed operation before requesting another archive or cleanup."
	}
	if _, err := store.FailOwnedEffect(ctx, scope, lease, &failure, outcome.Observation); err != nil {
		return outcome, err
	}
	return api.EffectOutcome{EffectID: lease.Record.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "failed", Error: &failure, Observation: outcome.Observation}, nil
}
