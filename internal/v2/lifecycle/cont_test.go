package lifecycle

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// This is the planner dependency model. The SQLite port has separate live
// claim, immutable stage, stale, foreign and replay tests in store.
func (store *launchFixtureStore) KeepContinueSlot(ctx context.Context, scope api.Scope, q api.LaunchPlanRequest, slot api.CredentialSlot) (api.ContinuationIntent, error) {
	lease, ok := api.EffectLeaseFromContext(ctx)
	if !ok || !reflect.DeepEqual(lease, q.Lease) || lease.Record.ClaimantID != scope.Actor.ID {
		return api.ContinuationIntent{}, launchConflict()
	}
	r := store.plans[lease.Record.Effect.PlanLaunch.ReservationID].Reservation
	raw, ok := store.blobs[launchObjectID(r.ID, "result-credential-slot")]
	var stage launchStageResult
	var actual api.CredentialSlot
	if !ok || api.DecodeObject(raw, &stage) != nil || api.DecodeObject(stage.Value, &actual) != nil || actual != slot {
		return api.ContinuationIntent{}, launchConflict()
	}
	for id, intent := range store.continuations {
		if intent.OperationID == r.OperationID && intent.Status == "claimed" {
			if intent.Slot != nil && *intent.Slot != slot {
				return api.ContinuationIntent{}, launchConflict()
			}
			intent.Slot = &slot
			intent.Generation++
			store.continuations[id] = intent
			return intent, nil
		}
	}
	return api.ContinuationIntent{}, launchMissing()
}
