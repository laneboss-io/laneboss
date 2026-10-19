package secrets

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func (s *Service) loopOriginal(ctx context.Context, launch *credentialLaunch, raw []byte) error {
	r := launch.record.Reservation
	if err := api.CheckLoopInput(r, raw); err != nil {
		return err
	}
	loop := r.Loop
	binding, err := s.deps.Store.LaunchBinding(ctx, r.PreviousLaunchID)
	if err != nil {
		return err
	}
	if binding.Recovery == nil || binding.Record.ID != r.PreviousLaunchID || binding.Record.Target != loop.Selector.Target {
		return wire.Error(api.CodeIntegrity, "loop credentials lost their previous recovery binding")
	}
	prior, err := s.deps.Store.LaunchPlan(ctx, s.deps.ServiceScope, binding.Recovery.PlanID)
	if err != nil {
		return err
	}
	if prior.Plan == nil {
		return wire.Error(api.CodeIntegrity, "loop credentials lost their previous plan")
	}
	if err := api.ValidateLaunchBindingPlan(binding, *prior.Plan); err != nil {
		return err
	}
	lane, err := s.deps.Store.Lane(ctx, s.deps.ServiceScope, loop.Selector.Target)
	if err != nil {
		return err
	}
	home := binding.Recovery.Home
	if lane.Cleaned || lane.Generation != r.BaseGeneration || lane.LaunchID != r.PreviousLaunchID || lane.CancellationEpoch != r.CancellationEpoch ||
		lane.Session != loop.PreviousSession || lane.BudgetRemaining != loop.BudgetRemaining || lane.LogicalTurnID != loop.PreviousLogicalTurnID ||
		lane.Level != r.Level || lane.Role != r.Role || lane.Session.Driver != r.Driver || lane.PolicyGeneration != r.PolicyGeneration ||
		lane.State != "idle" && lane.State != "verifying" || home.RootID != loop.PreviousHome.RootID || home.Home != loop.PreviousHome.Home || home.Generation < loop.PreviousHome.Generation {
		return wire.Error(api.CodeConflict, "loop credential input changed its retained private history")
	}
	launch.profile, launch.model = lane.ProfileGrantID, lane.Model
	if !wire.ID(string(launch.profile)) || launch.model == "" {
		return wire.Error(api.CodeIntegrity, "loop credentials lack their retained profile or model")
	}
	return nil
}
