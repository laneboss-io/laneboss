package grants

import (
	"context"
	"reflect"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func (s *Service) parentCreation(ctx context.Context, scope api.Scope, reservation api.LaunchReservation, parent api.Lane) error {
	request := api.EventTailRequest{LifeID: parent.LifeID, Run: 1, Since: reservation.StarterEventSeq - 1}
	for pages := 0; pages < 32; pages++ {
		page, err := s.deps.Store.Events(ctx, scope, request)
		if err != nil {
			return err
		}
		for _, event := range page.Events {
			if event.Seq != reservation.StarterEventSeq {
				continue
			}
			if event.Schema != api.SchemaVersion || event.Config != reservation.Config || event.Origin != "service" ||
				event.Actor.Kind != "service" || event.LifeID != parent.LifeID || event.Run != 1 ||
				(event.Kind != "lane.created" && event.Kind != "lane.adopted") || event.ParentLifeID != parent.ParentLifeID ||
				event.RootLifeID != parent.RootLifeID || !slices.Equal(event.StarterChain, parent.StarterChain) ||
				event.StarterEventSeq != parent.StarterEventSeq {
				return refused("reserved starter edge is not the parent's authentic creation event")
			}
			var created api.LaunchEvent
			if err := api.DecodeObject(event.Payload, &created); err != nil {
				return err
			}
			if created.Lane.LifeID != parent.LifeID || created.Lane.Run != 1 ||
				created.Lane.Level != parent.Level || created.Lane.Role != parent.Role ||
				created.Lane.RootLifeID != parent.RootLifeID || created.Lane.ParentLifeID != parent.ParentLifeID ||
				!slices.Equal(created.Lane.StarterChain, parent.StarterChain) || created.GrantSetID != parent.GrantSetID {
				return refused("starter creation payload belongs to another life or grant set")
			}
			return nil
		}
		if page.Complete {
			return refused("reserved starter creation event is absent")
		}
		if page.Cursor == "" || page.Cursor == request.Cursor {
			return integrity("starter event cursor did not advance")
		}
		request.Cursor = page.Cursor
	}
	return lstate.Error(api.CodeBudget, "starter event verification exceeds its fixed service page bound")
}

func (s *Service) resolveRetained(ctx context.Context, state *lstate.State) (api.GrantSet, error) {
	r := state.Record.Reservation
	var budget api.Budget
	// These typed bodies carry no replacement grant request. The reservation
	// store separately enforces the original continuation/epoch claims.
	switch {
	case r.Loop != nil:
		budget = r.Loop.BudgetRemaining
	case r.Mode == "resume":
		var request api.ResumeRequest
		if state.Request.Method != "lane.resume" {
			return api.GrantSet{}, integrity("resume reservation retained a different request method")
		}
		if err := api.DecodeObject(state.Request.Params, &request); err != nil {
			return api.GrantSet{}, err
		}
		if request.Target.LifeID != r.Target.LifeID || request.Target.Run+1 != r.Target.Run || request.ExpectedGeneration != r.BaseGeneration {
			return api.GrantSet{}, conflict("resume request differs from its reserved life, run or base")
		}
		budget = request.Budget
	case r.Mode == "turn":
		var request api.TurnRequest
		if state.Request.Method != "lane.turn" {
			return api.GrantSet{}, integrity("turn reservation retained a different request method")
		}
		if err := api.DecodeObject(state.Request.Params, &request); err != nil {
			return api.GrantSet{}, err
		}
		if request.Target.LifeID != r.Target.LifeID || request.Target.Run+1 != r.Target.Run || request.ExpectedGeneration != r.BaseGeneration {
			return api.GrantSet{}, conflict("turn request differs from its reserved life, run or base")
		}
		budget = request.Budget
	case r.Mode == "continue":
		// Continue retains its causal public request. Its dedicated reservation
		// transaction checks the current durable continuation and swap fences.
		spec := api.Methods[state.Request.Method]
		if err := api.DecodeObject(state.Request.Params, reflect.New(spec.Request).Interface()); err != nil {
			return api.GrantSet{}, err
		}
	default:
		return api.GrantSet{}, integrity("unknown retained-life reservation mode")
	}
	if r.Mode != "continue" {
		if err := manifest.Budget(budget); err != nil {
			return api.GrantSet{}, err
		}
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, r.PreviousLaunchID)
	if err != nil {
		return api.GrantSet{}, err
	}
	if binding.Recovery == nil {
		return api.GrantSet{}, integrity("retained launch has no original recovery binding")
	}
	previous, err := s.deps.Store.LaunchPlan(ctx, state.Scope, binding.Recovery.PlanID)
	if err != nil {
		return api.GrantSet{}, err
	}
	if err := api.ValidateLaunchPlanRecord(previous); err != nil {
		return api.GrantSet{}, err
	}
	if previous.Plan == nil || previous.Handoff == nil || previous.Phase != "bound" && previous.Phase != "opened" {
		return api.GrantSet{}, integrity("retained launch lost its committed plan or handoff")
	}
	if err := api.ValidateLaunchBindingPlan(binding, *previous.Plan); err != nil {
		return api.GrantSet{}, err
	}
	if previous.Reservation.Level != r.Level || previous.Reservation.Role != r.Role || previous.Reservation.Driver != r.Driver {
		return api.GrantSet{}, conflict("retained reservation changed its stored level, role or driver")
	}
	if previous.Plan.Capture.Status != "registered" {
		return api.GrantSet{}, refused("retained launch cannot continue without registered outside capture")
	}
	old := binding.Record
	if old.ID != r.PreviousLaunchID || old.Config != r.Config || old.Target.LifeID != r.Target.LifeID ||
		old.Target.Run+1 != r.Target.Run || r.Loop == nil && old.GrantSetID != r.GrantSetID || old.ParentLifeID != r.ParentLifeID ||
		old.RootLifeID != r.RootLifeID || old.StarterEventSeq != r.StarterEventSeq || !slices.Equal(old.StarterChain, r.StarterChain) {
		return api.GrantSet{}, conflict("retained reservation differs from the previous life binding")
	}
	lane, err := s.deps.Store.Lane(ctx, state.Scope, api.LifeRef{LifeID: r.Target.LifeID})
	if err != nil {
		return api.GrantSet{}, err
	}
	priorRun := lane.Run+1 == r.Target.Run && lane.Generation == r.BaseGeneration && lane.LaunchID == r.PreviousLaunchID
	currentRun := lane.Run == r.Target.Run && lane.Generation == r.Generation && lane.LaunchID == r.LaunchID &&
		(state.Record.Phase == "bound" || state.Record.Phase == "opened")
	expectedSet := r.GrantSetID
	if r.Loop != nil && priorRun {
		expectedSet = old.GrantSetID
	}
	if lane.Cleaned || !priorRun && !currentRun || lane.GrantSetID != expectedSet || lane.ParentLifeID != r.ParentLifeID ||
		lane.RootLifeID != r.RootLifeID || !slices.Equal(lane.StarterChain, r.StarterChain) || lane.StarterEventSeq != r.StarterEventSeq ||
		lane.Level != r.Level || lane.Role != r.Role || lane.Session.Driver != r.Driver {
		return api.GrantSet{}, conflict("retained life changed since launch reservation")
	}
	if priorRun && lane.State != "verifying" && lane.State != "idle" && lane.State != "accepted" && lane.State != "profile_wait" {
		return api.GrantSet{}, conflict("retained life is no longer quiescent and eligible")
	}
	if r.Mode != "continue" && r.RequestedBy.Kind == "lane" {
		if err := s.retainedStarter(ctx, state, lane); err != nil {
			return api.GrantSet{}, err
		}
	}
	data := previous.Plan.Data
	if lane.Workspace.ID != data.Workspace.ID || lane.Workspace.ProjectID != data.Workspace.ProjectID ||
		lane.Workspace.Base != data.Workspace.Base || lane.Workspace.Branch != data.Workspace.Branch ||
		lane.Workspace.LogicalCWD != data.Workspace.LogicalCWD || lane.Session.HomeID != data.Home.Home.ID ||
		lane.Session.HistoryID != data.Home.Home.HistoryID || lane.Session.ID != previous.Plan.Runner.Session.ID ||
		lane.Session.Driver != previous.Plan.Runner.Driver || lane.Session.LogicalCWD != data.Workspace.LogicalCWD || lane.Session.VendorID == "" {
		return api.GrantSet{}, conflict("retained workspace, home or private session changed")
	}
	if _, err := s.launchPolicy(ctx, state.Scope, r); err != nil {
		return api.GrantSet{}, err
	}
	grants, err := s.deps.Store.Grants(ctx, r.GrantSetID)
	if err != nil {
		return api.GrantSet{}, err
	}
	if grants.ID != r.GrantSetID || grants.LifeID != r.Target.LifeID || grants.ParentLifeID != r.ParentLifeID || grants.PolicyGeneration != r.PolicyGeneration {
		return api.GrantSet{}, conflict("retained grants differ from their reserved life and policy")
	}
	if r.Loop != nil {
		if grants.Generation != r.Loop.GrantGeneration || lane.Session != r.Loop.PreviousSession || lane.BudgetRemaining != budget ||
			binding.Recovery.Home.RootID != r.Loop.PreviousHome.RootID || binding.Recovery.Home.Home != r.Loop.PreviousHome.Home {
			return api.GrantSet{}, conflict("loop grant snapshot lost its retained input fences")
		}
		if err := checkedSeal(grants, s.deps.Clock.Now()); err != nil {
			return api.GrantSet{}, err
		}
		if priorRun {
			ceiling, err := s.deps.Store.Grants(ctx, old.GrantSetID)
			if err != nil {
				return api.GrantSet{}, err
			}
			ceiling, err = s.revalidateScope(ctx, state.Scope, ceiling, func(ctx context.Context, current api.GrantSet) (api.GrantSet, error) {
				return s.currentAfterScope(ctx, state.Scope, current)
			})
			if err != nil {
				return api.GrantSet{}, err
			}
			ceiling.ID, ceiling.Generation, ceiling.SHA256 = grants.ID, grants.Generation, grants.SHA256
			if !reflect.DeepEqual(ceiling, grants) {
				return api.GrantSet{}, refused("loop widened or replaced its retained grant ceiling")
			}
		} else {
			grants, err = s.revalidateScope(ctx, state.Scope, grants, func(ctx context.Context, current api.GrantSet) (api.GrantSet, error) {
				return s.currentAfterScope(ctx, state.Scope, current)
			})
		}
	} else {
		grants, err = s.revalidateScope(ctx, state.Scope, grants, func(ctx context.Context, current api.GrantSet) (api.GrantSet, error) {
			return s.currentAfterScope(ctx, state.Scope, current)
		})
	}
	if err != nil {
		return api.GrantSet{}, err
	}
	if r.Mode != "continue" {
		if err := s.checkSources(ctx, state.Scope, grants, budget.DiskBytes); err != nil {
			return api.GrantSet{}, err
		}
	}
	if state.Record.Inputs != nil && !reflect.DeepEqual(state.Record.Inputs.Grants, grants) {
		return api.GrantSet{}, conflict("retained sourced grants no longer match current ceilings")
	}
	return grants, nil
}
