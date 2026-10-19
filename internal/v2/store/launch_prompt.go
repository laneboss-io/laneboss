package store

import (
	"context"
	"database/sql"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/templates"
)

func launchPromptStartPins(r api.LaunchReservation, plan api.LaunchPlanRecord, input api.StartRequest) error {
	if input.Level != r.Level || input.Role != r.Role || input.Driver != r.Driver ||
		input.ExpectedPolicyGeneration != r.PolicyGeneration || plan.Inputs == nil || input.ProjectID != plan.Inputs.Sources.Project.ProjectID {
		return fault(api.CodeForbidden, "launch prompt start differs from its reserved pins")
	}
	return nil
}

func launchPromptAdoptPins(r api.LaunchReservation, input api.AdoptRequest) error {
	if input.Level != r.Level || input.Role != r.Role || input.Driver != r.Driver || input.ExpectedPolicyGeneration != r.PolicyGeneration {
		return fault(api.CodeForbidden, "launch prompt adoption differs from its reserved pins")
	}
	return nil
}

func launchPromptResumePins(r api.LaunchReservation, input api.ResumeRequest, previous api.Lane) error {
	if input.Target.LifeID != r.Target.LifeID || input.Target.Run+1 != r.Target.Run || input.ExpectedGeneration != r.BaseGeneration {
		return fault(api.CodeForbidden, "launch prompt resume differs from its reserved run")
	}
	if previous.Level != r.Level || previous.Role != r.Role || previous.Session.Driver != r.Driver {
		return fault(api.CodeForbidden, "launch prompt resume differs from its previous lane pins")
	}
	return nil
}

func launchPromptTurnPins(r api.LaunchReservation, input api.TurnRequest, previous api.Lane) error {
	if input.Target.LifeID != r.Target.LifeID || input.Target.Run+1 != r.Target.Run || input.ExpectedGeneration != r.BaseGeneration {
		return fault(api.CodeForbidden, "launch prompt turn differs from its reserved run")
	}
	if previous.Level != r.Level || previous.Role != r.Role || previous.Session.Driver != r.Driver {
		return fault(api.CodeForbidden, "launch prompt turn differs from its previous lane pins")
	}
	return nil
}

func launchPromptTrigger(mode string, mailIDs []api.ID) (api.Trigger, []api.ID, error) {
	ids := append([]api.ID{}, mailIDs...)
	if ids == nil {
		ids = []api.ID{}
	}
	switch mode {
	case "start", "adopt":
		return api.Trigger{Kind: mode, MailIDs: []api.ID{}, CausingSeqs: []api.Sequence{}}, []api.ID{}, nil
	case "resume":
		return api.Trigger{Kind: "manual", MailIDs: []api.ID{}, CausingSeqs: []api.Sequence{}}, []api.ID{}, nil
	case "turn":
		kind := "idle"
		if len(ids) > 0 {
			kind = "mail"
		}
		return api.Trigger{Kind: kind, MailIDs: append([]api.ID{}, ids...), CausingSeqs: []api.Sequence{}}, ids, nil
	default:
		return api.Trigger{}, nil, fault(api.CodeInvalid, "launch prompt has no valid turn trigger")
	}
}

// The caller holds the store lock. All selected fields come from the retained
// plan and exact original input; the public caller's identity is never copied
// into the service scope, including when its read view is pinned.
func (s *Service) launchPrompt(ctx context.Context, db queryer, scope api.Scope, request api.LaunchPromptRequest) (result api.LaunchPromptInput, err error) {
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	if scope.Actor.Kind != "service" || !internalScope(scope) || scope.Frame != nil || scope.Request.Method != "" || scope.Request.Proof != nil {
		return result, fault(api.CodeForbidden, "launch prompt requires its private service scope")
	}
	// The caller's read view may be intentionally pinned for stable input
	// rendering, but claim and launch-authority freshness are live fences. A
	// writer transaction must remain on its own connection to avoid self-lock.
	var live queryer = s.db
	if scope.ReadView == nil {
		if _, ok := db.(*sql.Tx); ok {
			live = db
		}
	}
	current, err := effectRow(ctx, live, request.Lease.Record.Effect.ID)
	if err != nil {
		return result, err
	}
	if !sameValue(current, request.Lease.Record) || current.State != api.EffectClaimed || current.Outcome != nil ||
		current.ClaimantID != scope.Actor.ID || current.ClaimID != request.Lease.ClaimID || current.ClaimExpiresAt != request.Lease.ExpiresAt ||
		!future(current.ClaimExpiresAt, s.deps.Clock.Now()) || current.Effect.PlanLaunch == nil || current.Effect.Context == nil ||
		current.Effect.PlanLaunch.ReservationID != request.ReservationID {
		return result, fault(api.CodeConflict, "launch prompt claim is stale or foreign")
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", request.ReservationID, &plan); err != nil {
		return result, err
	}
	if scope.ReadView != nil {
		var livePlan api.LaunchPlanRecord
		if err := storedProjection(ctx, s.db, "launch_plan", request.ReservationID, &livePlan); err != nil {
			return result, err
		}
		if !sameValue(livePlan, plan) {
			return result, fault(api.CodeConflict, "launch prompt plan changed after its pinned read view")
		}
	}
	if err := s.checkLaunchBytes(ctx, db, plan); err != nil {
		return result, err
	}
	if scope.ReadView != nil {
		var head api.LaunchPlanRecord
		if err := storedProjection(ctx, live, "launch_plan", request.ReservationID, &head); err != nil {
			return result, err
		}
		if !sameValue(head, plan) {
			return result, fault(api.CodeConflict, "launch prompt pinned view differs from its live plan")
		}
	}
	r, cause := plan.Reservation, current.Effect.Context
	if r.ID != request.ReservationID || r.Config != scope.Config || plan.Phase != "sourced" || plan.Inputs == nil ||
		cause.Kind != api.InternalLaunchPlan || cause.Target != r.Target || cause.RequestedBy != r.RequestedBy || cause.CauseOperationID != r.OperationID ||
		cause.CauseRequestID != r.RequestID || cause.CancellationEpoch != r.CancellationEpoch || !wire.ValidID(string(cause.LogicalTurnID)) {
		return result, fault(api.CodeForbidden, "launch prompt differs from its retained planning cause")
	}
	if err := s.currentLaunch(ctx, live, plan); err != nil {
		return result, err
	}
	if err := storedProjection(ctx, db, "grants", r.GrantSetID, &result.Grants); err != nil {
		return result, err
	}
	if !sameValue(result.Grants, plan.Inputs.Grants) {
		return result, fault(api.CodeIntegrity, "launch prompt grants differ from sourced inputs")
	}
	if err := storedProjection(ctx, db, "policy", api.ID(r.Config), &result.Policy); err != nil {
		return result, err
	}
	if result.Policy.Generation != r.PolicyGeneration || scope.PolicyGeneration != 0 && scope.PolicyGeneration != r.PolicyGeneration {
		return result, fault(api.CodeConflict, "launch prompt policy generation changed")
	}
	lane := api.Lane{LifeID: r.Target.LifeID, Run: r.Target.Run, Generation: r.Generation, Level: r.Level, Role: r.Role,
		State: "preparing", ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID, StarterChain: append([]api.ID{}, r.StarterChain...),
		StarterEventSeq: r.StarterEventSeq, GrantSetID: r.GrantSetID, LaunchID: r.LaunchID, PolicyGeneration: r.PolicyGeneration,
		CancellationEpoch: r.CancellationEpoch, LogicalTurnID: cause.LogicalTurnID,
		Workspace: api.Workspace{ProjectID: plan.Inputs.Sources.Project.ProjectID, LogicalCWD: "/work/main"}, Session: api.Session{Driver: r.Driver}}
	if r.Mode == "continue" {
		return result, fault(api.CodeForbidden, "continuation reuses its original prompt instead of preparing another")
	}
	receipt, err := s.reservationReceipt(ctx, db, plan)
	if err != nil {
		return result, err
	}
	var frame api.Request
	if r.Loop == nil {
		frame, err = wire.DecodeRequest(receipt.RawRequest)
		if err != nil {
			return result, err
		}
	}
	trigger, turnMailIDs, triggerErr := launchPromptTrigger(r.Mode, nil)
	if triggerErr != nil {
		return result, triggerErr
	}
	switch r.Mode {
	case "start":
		var input api.StartRequest
		if err := api.DecodeObject(frame.Params, &input); err != nil {
			return result, err
		}
		if err := launchPromptStartPins(r, plan, input); err != nil {
			return result, err
		}
		lane.Name, lane.Task, lane.BudgetRemaining = input.Lane, input.Task, input.Budget
	case "adopt":
		var input api.AdoptRequest
		if err := api.DecodeObject(frame.Params, &input); err != nil {
			return result, err
		}
		if err := launchPromptAdoptPins(r, input); err != nil {
			return result, err
		}
		lane.Name, lane.Task, lane.BudgetRemaining = input.Lane, input.Task, input.Budget
	case "resume", "turn":
		var previous api.Lane
		if err := storedProjection(ctx, db, "lane", r.Target.LifeID, &previous); err != nil {
			return result, err
		}
		if previous.Run+1 != r.Target.Run || previous.Generation != r.BaseGeneration || previous.LaunchID != r.PreviousLaunchID ||
			previous.Level != r.Level || previous.Role != r.Role || previous.Session.Driver != r.Driver {
			return result, fault(api.CodeConflict, "launch prompt previous life changed")
		}
		lane.Name, lane.Task, lane.Workspace, lane.Session, lane.BudgetRemaining = previous.Name, previous.Task, previous.Workspace, previous.Session, previous.BudgetRemaining
		if r.Loop != nil {
			loop := r.Loop
			if previous.Session != loop.PreviousSession || previous.BudgetRemaining != loop.BudgetRemaining || cause.LogicalTurnID != loop.LogicalTurnID {
				return result, fault(api.CodeConflict, "loop prompt lost its retained session or budget")
			}
			lane.Task, lane.BudgetRemaining = *loop.Setting.IdleMessage, loop.BudgetRemaining
			trigger = api.Trigger{Kind: "loop", MailIDs: []api.ID{}, CausingRun: loop.Selector.Target.Run,
				CausingSeqs: []api.Sequence{loop.Selector.SettingSeq, loop.Selector.EndSeq}}
		} else if r.Mode == "resume" {
			var input api.ResumeRequest
			if err := api.DecodeObject(frame.Params, &input); err != nil {
				return result, err
			}
			if err := launchPromptResumePins(r, input, previous); err != nil {
				return result, err
			}
			lane.BudgetRemaining = input.Budget
		} else {
			var input api.TurnRequest
			if err := api.DecodeObject(frame.Params, &input); err != nil {
				return result, err
			}
			if err := launchPromptTurnPins(r, input, previous); err != nil {
				return result, err
			}
			trigger, turnMailIDs, triggerErr = launchPromptTrigger(r.Mode, input.MailIDs)
			if triggerErr != nil {
				return result, triggerErr
			}
			lane.BudgetRemaining = input.Budget
		}
	default:
		return result, fault(api.CodeForbidden, "launch prompt has no retained public launch input")
	}
	result.Reservation, result.Lane = r, lane
	if err := storedProjection(ctx, db, "turn", cause.LogicalTurnID, &result.Turn); err != nil {
		if !absent(err) {
			return result, err
		}
		result.Turn = api.TurnSnapshot{Target: r.Target, LogicalTurnID: cause.LogicalTurnID, Task: lane.Task, PolicyGeneration: r.PolicyGeneration,
			Generation: 1, Status: "prepared", MailIDs: turnMailIDs, CreatedAt: receipt.RecordedAt, Trigger: trigger}
	}
	if result.Turn.Target != r.Target || result.Turn.Task != lane.Task || result.Turn.PolicyGeneration != r.PolicyGeneration || result.Turn.LogicalTurnID != cause.LogicalTurnID {
		return result, fault(api.CodeConflict, "launch prompt turn differs from retained task or policy")
	}
	if r.Loop != nil && (!sameValue(result.Turn.Trigger, trigger) || len(result.Turn.MailIDs) != 0) {
		return result, fault(api.CodeConflict, "loop prompt changed its exact causal trigger")
	}
	// The approved head is compiled for the configuration's default role.
	// Resolve the reserved role from the same verified canonical source view;
	// legacy projections must still pass the exact context check below.
	result.Policy, err = s.storedRolePolicy(ctx, db, result.Policy, lane)
	if err != nil {
		return result, err
	}
	if result.Policy.Context != (api.RoleContext{Level: r.Level, Role: r.Role}) {
		return result, fault(api.CodeConflict, "launch prompt approved policy belongs to another role")
	}
	return result, nil
}

func (s *Service) LaunchBriefingInput(ctx context.Context, scope api.Scope, request api.LaunchPromptRequest) (result api.BriefingInput, resultErr error) {
	s.mu.RLock()
	if err := s.available(); err != nil {
		s.mu.RUnlock()
		return result, err
	}
	db, err := s.reader(scope)
	if err != nil {
		s.mu.RUnlock()
		return result, err
	}
	prompt, err := s.launchPrompt(ctx, db, scope, request)
	var snapshot api.OrgSnapshot
	if err == nil {
		err = storedProjection(ctx, db, "org", api.ID(scope.Config), &snapshot)
	}
	s.mu.RUnlock()
	if err != nil {
		return result, err
	}
	sources, err := s.TemplateSources(ctx, scope, api.TemplateSourceRequest{OrgID: snapshot.Ref.OrgID, Generation: snapshot.Ref.Generation, Context: prompt.Policy.Context})
	if err != nil {
		return result, err
	}
	// Groups are built from the complete authorized projection inventory; the
	// preparing reservation itself is not advertised as a running agent.
	lanes, err := s.Lanes(ctx, scope, api.ListRequest{Limit: 200})
	if err != nil {
		return result, err
	}
	if lanes.Cursor != "" {
		return result, fault(api.CodeBudget, "launch briefing lane inventory exceeds its bounded page")
	}
	groups, err := templates.GroupLanes(lanes.Lanes)
	if err != nil {
		return result, err
	}
	result = api.BriefingInput{Mode: "lane", Lane: &prompt.Lane, Task: &prompt.Lane.Task, GrantSet: &prompt.Grants,
		Policy: prompt.Policy, Sources: sources, Groups: groups, Checks: []api.Capability{{Name: "reservation", Available: prompt.Reservation.ID == request.ReservationID}, {Name: "grants", Available: prompt.Grants.ID == prompt.Reservation.GrantSetID}, {Name: "approved_sources", Available: sources.Snapshot == snapshot.Ref}}}
	return result, nil
}
