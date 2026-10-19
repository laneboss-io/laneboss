package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// seal runs only after the complete measured plan is committed. The service's
// original helper stages consume this handoff; a spec is never a prepared gate.
func (execution *planExecution) seal(ctx context.Context, plan api.LaunchPlan) error {
	if err := api.ValidateSpendCapture(plan); err != nil {
		return err
	}
	if err := execution.service.checkSpend(ctx, plan.Runner.Slot); err != nil {
		return err
	}
	r := plan.Reservation
	spec := api.LaunchSpec{Kind: "agent", PlanID: r.ID, Capture: &plan.Capture,
		ID: r.SpecID, Target: r.Target, LaunchID: r.LaunchID,
		Backend: plan.Inputs.Sources.Runtime.Backend, UIDLeaseID: plan.Lease.ID,
		Workspace: plan.Data.Workspace, Materialization: plan.Data.Materialization,
		Grants: plan.Inputs.Grants, Runner: &plan.Runner, Injection: plan.Injection,
		Budget: plan.Budget, EndpointGeneration: plan.Lease.EndpointGeneration,
		RuntimeManifest: plan.Inputs.Sources.Runtime.Manifest, PolicyGeneration: r.PolicyGeneration}
	if err := api.ValidateAgentLaunchSpec(spec, plan); err != nil {
		return failure(err)
	}
	original, err := execution.retain(ctx, "spec", "launch_spec", spec)
	if err != nil {
		return err
	}
	cause := execution.cause(api.InternalHelperRegister, "register-spec")
	handoff := api.PreparedSpecHandoff{Cause: cause, Config: r.Config, Spec: spec,
		Original: original, SpecSHA256: original.SHA256, OperationID: r.OperationID, RequestID: r.RequestID}
	next := execution.record
	next.Phase, next.Handoff = "spec_retained", &handoff
	return execution.save(ctx, next)
}

func (execution *planExecution) recovery(ctx context.Context, plan api.LaunchPlan) error {
	if err := api.ValidateSpendCapture(plan); err != nil {
		return err
	}
	if err := execution.service.checkSpend(ctx, plan.Runner.Slot); err != nil {
		return err
	}
	if execution.record.Handoff == nil {
		return integrity("launch restart has no retained spec handoff")
	}
	handoff := *execution.record.Handoff
	metadata, err := execution.service.deps.Store.ObjectMetadata(ctx, execution.scope, handoff.Original.ID)
	if err != nil {
		return failure(err)
	}
	if metadata.Origin != "service" || metadata.SourceOperationID != plan.Reservation.OperationID {
		return integrity("launch spec lost its original operation provenance")
	}
	raw, err := execution.service.readBlob(ctx, execution.scope, handoff.Original)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(handoff.Spec)
	if err != nil {
		return integrity("cannot encode the retained launch spec")
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		return failure(err)
	}
	if string(raw) != string(canonical) || digestOfBytes(raw) != handoff.SpecSHA256 ||
		api.ValidateAgentLaunchSpec(handoff.Spec, plan) != nil {
		return integrity("launch restart changed the exact retained spec")
	}
	recovery := api.LaunchRecovery{PlanID: plan.Reservation.ID, OriginalRequest: plan.Reservation.OriginalRequest,
		Handoff: handoff, Home: plan.Data.Home, Capture: plan.Capture}
	if execution.record.Phase == "bound" || execution.record.Phase == "opened" {
		if err := execution.boundTurn(ctx, plan); err != nil {
			return err
		}
		binding, err := execution.service.deps.Store.LaunchBinding(ctx, plan.Reservation.LaunchID)
		if err != nil {
			return failure(err)
		}
		if api.ValidateLaunchBindingPlan(binding, plan) != nil || binding.Recovery == nil ||
			!reflect.DeepEqual(*binding.Recovery, recovery) {
			return integrity("launch restart has no exact committed recovery binding")
		}
		if err := execution.credentialProjection(ctx, binding, plan); err != nil {
			return err
		}
	} else {
		_, err := execution.service.deps.Store.LaunchBinding(ctx, plan.Reservation.LaunchID)
		if err == nil {
			return integrity("unbound launch plan has a partial launch binding")
		}
		if !notFound(err) {
			return failure(err)
		}
	}
	if _, err := execution.retain(ctx, "recovery", "manifest", recovery); err != nil {
		return err
	}
	return execution.checkClaim(ctx)
}

func (execution *planExecution) boundTurn(ctx context.Context, plan api.LaunchPlan) error {
	s, r := execution.service, plan.Reservation
	lane, err := s.lane(ctx, execution.scope, r.Target, true)
	if err != nil {
		return err
	}
	turn, err := s.deps.Store.Turn(ctx, execution.scope, r.Target, execution.input.turn)
	if err != nil {
		return failure(err)
	}
	if lane.Cleaned || lane.LaunchID != r.LaunchID || lane.CancellationEpoch != r.CancellationEpoch ||
		lane.LogicalTurnID != execution.input.turn || lane.GrantSetID != r.GrantSetID || lane.PolicyGeneration != r.PolicyGeneration ||
		lane.Workspace != plan.Data.Workspace || turn.Target != r.Target || turn.LogicalTurnID != execution.input.turn ||
		turn.Task != lane.Task || turn.Prompt == nil || *turn.Prompt != plan.Runner.Prompt || turn.PolicyGeneration != r.PolicyGeneration {
		return integrity("launch recovery lost its committed lane and logical-turn snapshot")
	}
	return nil
}
