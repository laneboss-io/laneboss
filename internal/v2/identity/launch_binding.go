package identity

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// BindLaunch is an internal service port. Its store-returned handoff retains
// the genuine causal service actor separately from the original requester.
// Only that retained service identity scopes these private metadata reads;
// neither a request's recovery copy nor a parent's/child's lane scope does.
func (s *Service) retainedLaunchPlan(ctx context.Context, binding api.LaunchBindingRequest) (api.LaunchPlan, api.Scope, error) {
	if binding.Recovery == nil {
		return api.LaunchPlan{}, api.Scope{}, refusal(api.CodeIntegrity, "committed agent launch has no retained recovery binding")
	}
	recovery := binding.Recovery
	cause := recovery.Handoff.Cause
	if cause.Actor.Kind != "service" || !validID(cause.Actor.ID) || cause.Config != binding.Record.Config || !validID(recovery.PlanID) {
		return api.LaunchPlan{}, api.Scope{}, refusal(api.CodeIntegrity, "retained launch has no causal service identity")
	}
	scope := api.Scope{Config: binding.Record.Config, Actor: cause.Actor,
		EndpointGeneration: binding.Record.EndpointGeneration, PolicyGeneration: binding.Record.PolicyGeneration}
	retained, err := s.deps.Store.LaunchPlan(ctx, scope, recovery.PlanID)
	if err != nil {
		return api.LaunchPlan{}, api.Scope{}, err
	}
	if err := api.ValidateLaunchPlanRecord(retained); err != nil {
		return api.LaunchPlan{}, api.Scope{}, err
	}
	if retained.Plan == nil || retained.Handoff == nil || retained.Reservation.ID != recovery.PlanID ||
		retained.Phase != "bound" && retained.Phase != "opened" || !reflect.DeepEqual(*retained.Handoff, recovery.Handoff) {
		return api.LaunchPlan{}, api.Scope{}, refusal(api.CodeIntegrity, "identity binding has no matching bound launch plan")
	}
	if err := api.ValidateLaunchBindingPlan(binding, *retained.Plan); err != nil {
		return api.LaunchPlan{}, api.Scope{}, err
	}
	return *retained.Plan, scope, nil
}

func (s *Service) checkIdentityEvent(ctx context.Context, scope api.Scope, binding api.LaunchBindingRequest) error {
	return s.checkBoundEvent(ctx, scope, binding, binding.Recovery.Handoff)
}

func (s *Service) checkBoundEvent(ctx context.Context, scope api.Scope, binding api.LaunchBindingRequest, handoff api.PreparedSpecHandoff) error {
	return s.checkBoundEventActor(ctx, scope, binding, handoff, handoff.Cause.Actor)
}

func (s *Service) checkBoundEventActor(ctx context.Context, scope api.Scope, binding api.LaunchBindingRequest, handoff api.PreparedSpecHandoff, writer api.Actor) error {
	identity, record := binding.Identity, binding.Record
	page, err := s.deps.Store.Events(ctx, scope, api.EventTailRequest{LifeID: record.Target.LifeID,
		Run: record.Target.Run, Since: identity.CommittedSeq - 1})
	if err != nil {
		return err
	}
	for _, event := range page.Events {
		if event.Seq != identity.CommittedSeq {
			continue
		}
		var payload api.LaunchRecord
		if event.Schema != api.SchemaVersion || event.ID != identity.EventID || event.Kind != "identity.bound" ||
			event.Config != record.Config || event.LifeID != record.Target.LifeID || event.Run != record.Target.Run ||
			event.Actor.Kind != "service" || !validID(event.Actor.ID) || event.RequestedBy != handoff.Cause.RequestedBy ||
			event.Actor != writer ||
			event.RequestID != handoff.RequestID || event.OperationID != handoff.OperationID ||
			api.DecodeObject(event.Payload, &payload) != nil || !reflect.DeepEqual(payload, record) {
			return refusal(api.CodeIntegrity, "identity commit event differs from the retained launch")
		}
		return nil
	}
	return refusal(api.CodeIntegrity, "retained identity commit event is missing")
}

func (s *Service) checkPlanAuthority(ctx context.Context, scope api.Scope, plan api.LaunchPlan) error {
	lane, err := s.deps.Store.Lane(ctx, scope, plan.Reservation.Target)
	if err != nil {
		return err
	}
	// Later state observations may advance the same run's life revision. The
	// ready reservation must already be projected; authority still fences on
	// the exact run/launch, cancellation epoch, current grants and policy.
	if lane.Generation < plan.Reservation.Generation || lane.CancellationEpoch != plan.Reservation.CancellationEpoch {
		return refusal(api.CodeConflict, "launch plan life generation or cancellation fence is stale")
	}
	if lane.Level != plan.Reservation.Level || lane.Role != plan.Reservation.Role || lane.Session.Driver != plan.Reservation.Driver {
		return refusal(api.CodeConflict, "ready life differs from its reserved child pins")
	}
	grants, err := s.deps.Store.Grants(ctx, plan.Reservation.GrantSetID)
	if err != nil {
		return err
	}
	if !equalLaunchGrants(grants, plan.Inputs.Grants) {
		return refusal(api.CodeForbidden, "launch plan differs from the current issued grants")
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return err
	}
	if err := api.ValidateLaunchPolicyCurrent(plan.Reservation, grants, policy); err != nil {
		return err
	}
	if plan.Capture.Status == "refused" {
		if err := api.ValidateCapturePolicy(plan.Capture, policy); err != nil {
			return err
		}
	}
	return nil
}
