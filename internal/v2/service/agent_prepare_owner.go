package service

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// The agent planning owner retains its prepare child until the atomic binding
// and measured preparation completion. An expired child is recoverable work for
// that same owner, not authority for the generic dispatcher to invent a gate ID.
func retainedAgentPrepare(ctx context.Context, state api.StateStore, scope api.Scope, effect api.Effect) (bool, error) {
	if effect.HelperPrepare == nil {
		return false, nil
	}
	inventory, ok := state.(interface {
		LaunchInventory(context.Context) ([]api.LaunchPlanRecord, error)
	})
	if !ok {
		return false, nil
	}
	plans, err := inventory.LaunchInventory(ctx)
	if err != nil {
		return false, err
	}
	for _, plan := range plans {
		r := plan.Reservation
		if effect.ID != agentStageID(r.ID, "prepare-effect") {
			continue
		}
		if err := api.ValidateLaunchPlanRecord(plan); err != nil {
			return false, err
		}
		if plan.Plan == nil || plan.Handoff == nil || effect.Context == nil {
			return false, serviceError(api.CodeIntegrity, "retained agent prepare lost its original sealed plan")
		}
		parent, err := state.Effect(ctx, scope, plan.Handoff.Cause.EffectID)
		if err != nil {
			return false, err
		}
		if parent.Effect.PlanLaunch == nil || parent.Effect.PlanLaunch.ReservationID != r.ID || parent.Effect.Context == nil ||
			parent.Effect.OperationID != r.OperationID || parent.Effect.Context.Target != r.Target {
			return false, serviceError(api.CodeIntegrity, "retained agent prepare has no original planning owner")
		}
		cause := *parent.Effect.Context
		cause.ID, cause.Kind, cause.EffectID = agentStageID(r.ID, "prepare-cause"), api.InternalHelperPrepare, effect.ID
		expected := api.Effect{ID: effect.ID, OperationID: r.OperationID, Context: &cause,
			HelperPrepare: &api.HelperLaunchRequest{Cause: cause, LeaseID: plan.Plan.Lease.ID, PreparedSpecID: plan.Handoff.Spec.ID, SpecSHA256: plan.Handoff.SpecSHA256}}
		if !reflect.DeepEqual(effect, expected) {
			return false, serviceError(api.CodeIntegrity, "retained agent prepare changed its original causal selectors")
		}
		actual, err := state.Effect(ctx, scope, effect.ID)
		if err != nil {
			return false, err
		}
		if !reflect.DeepEqual(actual.Effect, effect) {
			return false, serviceError(api.CodeIntegrity, "retained agent prepare differs from its durable child")
		}
		return true, nil
	}
	return false, nil
}
