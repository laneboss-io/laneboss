package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// ProcessObservationAuthority is an installed, read-only control port. It
// authenticates the saved native handle and the current life/run under one
// writer fence. Completed launch authority cannot be used for gate mutation.
func (s *Service) ProcessObservationAuthority(ctx context.Context, handle api.ProcessHandle) (binding api.LaunchBindingRequest, completed bool, resultErr error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return binding, false, err
	}
	var saved struct {
		LaunchID api.ID
		Handle   api.ProcessHandle
	}
	if err := storedProjection(ctx, s.db, "launch_process", handle.ID, &saved); err != nil {
		return binding, false, err
	}
	if saved.Handle != handle {
		return binding, false, fault(api.CodeConflict, "process handle differs from retained helper evidence")
	}
	binding, err := s.launchBinding(ctx, s.db, saved.LaunchID)
	if err != nil {
		return binding, false, err
	}
	r := binding.Record
	if r.Actor.Kind != "lane" {
		// Fixed workers retain the existing stage-claim route; a completed
		// agent launch never grants standing worker observation authority.
		return binding, false, nil
	}
	if r.Config != s.deps.Config || r.Target != handle.Target || binding.Recovery == nil {
		return binding, false, fault(api.CodeForbidden, "process observation differs from its retained agent owner")
	}
	if r.ContainmentID != handle.ContainmentID || r.ProcessGeneration != handle.Generation {
		allowAndLog("process_observation_owner")
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", r.Target.LifeID, &lane); err != nil {
		return binding, false, err
	}
	if lane.LifeID != r.Target.LifeID || lane.Run != r.Target.Run || lane.LaunchID != r.ID || lane.Cleaned {
		return binding, false, fault(api.CodeConflict, "process observation has no live life/run binding")
	}
	var current api.LaunchRecord
	if err := storedProjection(ctx, s.db, "launch", r.ID, &current); err != nil {
		return binding, false, err
	}
	// Revocation closes identity/transport, not the service's responsibility
	// to measure the same containment before marking, archiving or collecting.
	// All immutable identity fields must still match the original binding.
	r.Revoked = current.Revoked
	if !sameValue(current, r) {
		return binding, false, fault(api.CodeConflict, "process observation launch ownership changed")
	}
	var endpoint api.EndpointProjection
	if err := storedProjection(ctx, s.db, "endpoint", r.ID, &endpoint); err != nil {
		return binding, false, err
	}
	e := endpoint.Binding
	if e.Config != r.Config || e.Class != api.EndpointLane || e.LaunchID != r.ID || e.Target == nil || *e.Target != r.Target || e.EndpointGeneration != r.EndpointGeneration || endpoint.Revoked != current.Revoked {
		return binding, false, fault(api.CodeConflict, "process observation endpoint ownership changed")
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", binding.Recovery.PlanID, &plan); err != nil {
		return binding, false, err
	}
	if plan.Handoff == nil || plan.Plan == nil {
		return binding, false, fault(api.CodeIntegrity, "process observation lost its retained launch plan")
	}
	stage, err := effectRow(ctx, s.db, plan.Handoff.Cause.EffectID)
	if err != nil {
		return binding, false, err
	}
	if stage.Effect.PlanLaunch == nil || stage.Effect.PlanLaunch.ReservationID != plan.Reservation.ID || stage.Effect.OperationID != plan.Reservation.OperationID || stage.Effect.Context == nil || stage.Effect.Context.Target != r.Target {
		return binding, false, fault(api.CodeIntegrity, "process observation launch stage changed its retained owner")
	}
	if stage.Outcome == nil || stage.Outcome.Status != "succeeded" {
		return binding, false, nil
	}
	o := stage.Outcome
	if stage.State != api.EffectCompleted || o.EffectID != stage.Effect.ID || o.ClaimID != stage.ClaimID || o.Error != nil ||
		plan.Phase != "opened" || o.Process == nil || *o.Process != handle || o.LaunchPlan == nil || !sameValue(*o.LaunchPlan, *plan.Plan) {
		return binding, false, fault(api.CodeConflict, "process observation has no successful completed launch")
	}
	return binding, true, nil
}
