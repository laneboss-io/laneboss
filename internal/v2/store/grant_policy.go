package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.GrantPolicyReader = (*Service)(nil)

// GrantPolicy keeps the caller and its pinned read view intact. Target role,
// life and grant selectors are compared with protected records, never copied
// into the authenticated actor. Effect execution still owns its durable lease.
func (s *Service) GrantPolicy(ctx context.Context, scope api.Scope, request api.GrantPolicyRequest) (api.EffectivePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.EffectivePolicy{}, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return api.EffectivePolicy{}, err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" || scope.Frame != nil || scope.Request.Method != "" {
		return api.EffectivePolicy{}, fault(api.CodeForbidden, "grant policy selection requires the private service read scope")
	}
	db, err := s.reader(scope)
	if err != nil {
		return api.EffectivePolicy{}, err
	}
	if request.ReservationID != "" {
		var plan api.LaunchPlanRecord
		if err := storedProjection(ctx, db, "launch_plan", request.ReservationID, &plan); err != nil {
			return api.EffectivePolicy{}, err
		}
		if err := s.checkLaunchBytes(ctx, db, plan); err != nil {
			return api.EffectivePolicy{}, err
		}
		r := plan.Reservation
		if request.ReservationID != r.ID || request.Target != r.Target || request.GrantSetID != r.GrantSetID || request.Context != (api.RoleContext{Level: r.Level, Role: r.Role}) || request.PolicyGeneration != r.PolicyGeneration {
			return api.EffectivePolicy{}, fault(api.CodeForbidden, "grant policy selection differs from its retained reservation")
		}
	} else {
		var lane api.Lane
		if err := storedProjection(ctx, db, "lane", request.Target.LifeID, &lane); err != nil {
			return api.EffectivePolicy{}, err
		}
		if request.Target != (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) || request.GrantSetID != lane.GrantSetID || request.Context != (api.RoleContext{Level: lane.Level, Role: lane.Role}) || request.PolicyGeneration != lane.PolicyGeneration || lane.Cleaned {
			return api.EffectivePolicy{}, fault(api.CodeForbidden, "grant policy selection differs from its retained lane")
		}
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return api.EffectivePolicy{}, err
	}
	if policy.Generation == 0 || policy.Generation != request.PolicyGeneration {
		return api.EffectivePolicy{}, fault(api.CodeConflict, "grant policy selection is no longer current")
	}
	return policy, nil
}
