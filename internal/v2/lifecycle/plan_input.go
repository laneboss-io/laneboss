package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (execution *planExecution) original(ctx context.Context) error {
	s, r := execution.service, execution.record.Reservation
	if execution.record.Phase != "opened" {
		if err := execution.starter(ctx); err != nil {
			return err
		}
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, execution.scope, r.OriginalRequest.ID)
	if err != nil {
		return failure(err)
	}
	class := "launch_request"
	if r.Loop != nil {
		class = "manifest"
	}
	if metadata.Origin != "service" || metadata.SourceOperationID != r.OperationID ||
		metadata.ACL.Config != r.Config || metadata.ACL.Owner.Kind != "service" || !validID(metadata.ACL.Owner.ID) ||
		metadata.ACL.Audience != "owner" || len(metadata.ACL.Participants) != 0 || metadata.ACL.LifeID != r.Target.LifeID ||
		r.OriginalRequest.Class != class || r.OriginalRequest.Bytes > api.MaxFrameBytes {
		return integrity("reserved original input has no service operation provenance")
	}
	raw, err := s.readBlob(ctx, execution.scope, r.OriginalRequest)
	if err != nil {
		return err
	}
	execution.input.turn = execution.lease.Record.Effect.Context.LogicalTurnID
	if !validID(execution.input.turn) {
		return integrity("launch effect lost its reserved logical turn")
	}
	if r.Loop != nil {
		if err := execution.loopInput(raw); err != nil {
			return err
		}
	} else if r.Mode == "continue" {
		var request api.ContinuationRequest
		if api.DecodeObject(raw, &request) != nil || request.Swap.OperationID != r.OperationID ||
			request.Swap.ContinuationRun != r.Target.Run || request.Swap.Limit.Target.LifeID != r.Target.LifeID ||
			request.Swap.ExpectedGeneration != r.BaseGeneration || request.Swap.CancellationEpoch != r.CancellationEpoch ||
			request.Swap.LogicalTurnID != execution.input.turn {
			return integrity("continued launch differs from its retained continuation input")
		}
		intent, err := s.deps.Store.ContinuationIntent(ctx, execution.scope, request.IntentID)
		if err != nil {
			return failure(err)
		}
		if intent.OperationID != r.OperationID || !reflect.DeepEqual(intent.Swap, request.Swap) ||
			intent.Status != "claimed" || intent.LogicalTurnID != execution.input.turn {
			return problem(api.CodeConflict, "continuation has no current claimed intent", "Reconcile its original claim and retained slot.")
		}
		if digestOfBytes(raw) != r.OriginalRequest.SHA256 {
			return integrity("continued launch input changed")
		}
		execution.input.profile = request.Swap.ProfileGrantID
		execution.input.slot = intent.Slot
	} else {
		var request api.Request
		if api.DecodeObject(raw, &request) != nil || request.Config != r.Config || request.Method != api.Method("lane."+r.Mode) ||
			request.RequestID != r.RequestID || request.RequestSHA256 != r.RequestSHA256 {
			return integrity("launch original request differs from its reservation")
		}
		digest, err := api.RequestDigest(request)
		if err != nil || digest != r.RequestSHA256 {
			return integrity("launch original request digest changed")
		}
		if err := ValidateInput(request.Method, request.Params); err != nil {
			return err
		}
		execution.input.request = request
		switch r.Mode {
		case "start":
			var value api.StartRequest
			if err := api.DecodeObject(request.Params, &value); err != nil {
				return failure(err)
			}
			execution.input.task, execution.input.budget = value.Task, value.Budget
			execution.input.role, execution.input.driver = api.RoleContext{Level: value.Level, Role: value.Role}, value.Driver
			execution.input.profile, execution.input.model, execution.input.effort = value.ProfileGrantID, value.Model, value.Effort
		case "adopt":
			var value api.AdoptRequest
			if err := api.DecodeObject(request.Params, &value); err != nil {
				return failure(err)
			}
			execution.input.task, execution.input.budget = value.Task, value.Budget
			execution.input.role, execution.input.driver = api.RoleContext{Level: value.Level, Role: value.Role}, value.Driver
			execution.input.profile, execution.input.model, execution.input.effort = value.ProfileGrantID, value.Model, value.Effort
		case "resume":
			var value api.ResumeRequest
			if err := api.DecodeObject(request.Params, &value); err != nil {
				return failure(err)
			}
			if value.Target.LifeID != r.Target.LifeID || value.Target.Run+1 != r.Target.Run || value.ExpectedGeneration != r.BaseGeneration {
				return integrity("resume input differs from its reserved run")
			}
			execution.input.message, execution.input.budget = &value.Message, value.Budget
		case "turn":
			var value api.TurnRequest
			if err := api.DecodeObject(request.Params, &value); err != nil {
				return failure(err)
			}
			if value.Target.LifeID != r.Target.LifeID || value.Target.Run+1 != r.Target.Run || value.ExpectedGeneration != r.BaseGeneration {
				return integrity("turn input differs from its reserved run")
			}
			execution.input.message, execution.input.mail, execution.input.budget = value.IdleMessage, value.MailIDs, value.Budget
		}
	}
	if r.Target.Run > 1 {
		target, generation, launch := api.LifeRef{LifeID: r.Target.LifeID, Run: r.Target.Run - 1}, r.BaseGeneration, r.PreviousLaunchID
		if execution.record.Phase == "bound" || execution.record.Phase == "opened" {
			target, generation, launch = r.Target, r.Generation, r.LaunchID
		}
		lane, err := s.lane(ctx, execution.scope, target, true)
		if err != nil {
			return err
		}
		sameGeneration := lane.Generation == generation
		if execution.record.Phase == "opened" {
			sameGeneration = lane.Generation >= generation
		}
		if lane.Cleaned || !sameGeneration || lane.LaunchID != launch ||
			lane.CancellationEpoch != r.CancellationEpoch || !validSession(lane.Session) {
			return problem(api.CodeConflict, "retained launch life or session changed", "Retain the original reservation and reconcile private history.")
		}
		binding, err := s.deps.Store.LaunchBinding(ctx, r.PreviousLaunchID)
		if err != nil {
			return failure(err)
		}
		if binding.Recovery == nil {
			return integrity("retained launch has no recovery binding")
		}
		if binding.Record.Revoked {
			binding, err = s.historicalBinding(ctx, execution.scope, lane, binding)
			if err != nil {
				return err
			}
		}
		previous, err := s.deps.Store.LaunchPlan(ctx, execution.scope, binding.Recovery.PlanID)
		if err != nil {
			return failure(err)
		}
		if previous.Plan == nil || api.ValidateLaunchPlanRecord(previous) != nil ||
			api.ValidateLaunchBindingPlan(binding, *previous.Plan) != nil || binding.Record.ID != r.PreviousLaunchID ||
			binding.Record.Target != (api.LifeRef{LifeID: r.Target.LifeID, Run: r.Target.Run - 1}) ||
			binding.Recovery.Home.Home.ID != lane.Session.HomeID || binding.Recovery.Home.Home.HistoryID != lane.Session.HistoryID ||
			previous.Plan.Data.Workspace.ID != lane.Workspace.ID || previous.Plan.Runner.Session.Driver != lane.Session.Driver {
			return integrity("retained launch recovery does not match its private session")
		}
		if r.Mode == "continue" && binding.Recovery.Capture.Status != "registered" {
			return problem(api.CodeUnsupported, "capture-dependent continuation has no registered primary capture",
				"Preserve the run; LP-CAPTURE-IO-1 must define and verify its actual vendor limit records.")
		}
		execution.input.previous = &binding
		execution.input.previousPlan = previous.Plan
		execution.input.task, execution.input.role, execution.input.driver = lane.Task,
			api.RoleContext{Level: lane.Level, Role: lane.Role}, lane.Session.Driver
		execution.input.model, execution.input.effort = lane.Model, lane.Effort
		if r.Mode != "continue" {
			execution.input.profile = lane.ProfileGrantID
		} else {
			execution.input.budget = lane.BudgetRemaining
		}
		if loop := r.Loop; loop != nil {
			home := binding.Recovery.Home
			expectedTurn := loop.PreviousLogicalTurnID
			if execution.record.Phase == "bound" || execution.record.Phase == "opened" {
				expectedTurn = loop.LogicalTurnID
			}
			if home.RootID != loop.PreviousHome.RootID || home.Home != loop.PreviousHome.Home || home.Generation < loop.PreviousHome.Generation ||
				lane.Workspace.ID != loop.PreviousHome.Home.WorkspaceID || lane.Session != loop.PreviousSession ||
				lane.BudgetRemaining != loop.BudgetRemaining || lane.LogicalTurnID != expectedTurn {
				return integrity("loop input changed its retained session, home or budget")
			}
			if execution.record.Phase == "bound" || execution.record.Phase == "opened" {
				if lane.Task != *loop.Setting.IdleMessage {
					return integrity("loop input changed its retained task")
				}
				turn, err := s.deps.Store.Turn(ctx, execution.scope, r.Target, execution.input.turn)
				if err != nil {
					return failure(err)
				}
				if turn.Target != r.Target || turn.LogicalTurnID != execution.input.turn || turn.Task != *loop.Setting.IdleMessage {
					return integrity("loop input changed its retained turn task")
				}
			}
			execution.input.task, execution.input.message, execution.input.mail = *loop.Setting.IdleMessage, nil, nil
			execution.input.budget = loop.BudgetRemaining
		}
	}
	if execution.input.role.Level != r.Level || execution.input.role.Role != r.Role || execution.input.driver != r.Driver {
		return integrity("launch input changed the reserved role or driver pins")
	}
	// The request/current life are comparison inputs. Only reserved pins are
	// carried forward to templates, sources and adapters.
	execution.input.role = api.RoleContext{Level: r.Level, Role: r.Role}
	execution.input.driver = r.Driver
	if !validBudget(execution.input.budget) || !validBlob(execution.input.task) {
		return integrity("launch lost its retained task or budget")
	}
	return execution.currentPolicy(ctx)
}

func (execution *planExecution) sourceInputs(ctx context.Context) (api.LaunchInputs, error) {
	s, r := execution.service, execution.record.Reservation
	if absent(s.deps.Grants) {
		return api.LaunchInputs{}, api.NotImplemented("lb-v2-grants", "GrantResolver.Resolve")
	}
	grants, err := s.deps.Grants.Resolve(ctx, execution.scope, api.GrantResolveRequest{ReservationID: r.ID})
	if err != nil {
		return api.LaunchInputs{}, failure(err)
	}
	expires, expiryErr := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt))
	if grants.ID != r.GrantSetID || grants.LifeID != r.Target.LifeID || grants.ParentLifeID != r.ParentLifeID ||
		grants.Revoked || !validDigest(grants.SHA256) || !validGeneration(grants.Generation) ||
		grants.PolicyGeneration != r.PolicyGeneration || expiryErr != nil || !s.deps.Clock.Now().Before(expires) {
		return api.LaunchInputs{}, integrity("resolved grants differ from the reserved launch")
	}
	retained, lookupErr := s.deps.Store.Grants(ctx, grants.ID)
	if lookupErr != nil && !notFound(lookupErr) {
		return api.LaunchInputs{}, failure(lookupErr)
	}
	if lookupErr == nil && !reflect.DeepEqual(retained, grants) {
		return api.LaunchInputs{}, integrity("issued launch grants changed on replay")
	}
	if notFound(lookupErr) {
		event, err := execution.event("grants.issued", api.GrantEvent{GrantSet: grants})
		if err != nil {
			return api.LaunchInputs{}, err
		}
		if err := execution.transact(ctx, api.StateWrites{Grants: []api.GrantSet{grants}}, nil, []api.Event{event},
			[]api.Compare{{Kind: api.CompareGrants, ID: grants.ID, Generation: 0}}); err != nil {
			return api.LaunchInputs{}, err
		}
	}
	// The new life is still a reservation and has no current Lane projection.
	// Reopen the original reservation and both ceilings after issuance; generic
	// life revalidation applies only after the ready lane has been committed.
	current, err := s.deps.Grants.Resolve(ctx, execution.scope, api.GrantResolveRequest{ReservationID: r.ID})
	if err != nil {
		return api.LaunchInputs{}, failure(err)
	}
	if !reflect.DeepEqual(current, grants) {
		return api.LaunchInputs{}, problem(api.CodeConflict, "reserved grants require a new validation", "Preserve this reservation until its current grants are reconciled.")
	}
	if absent(s.deps.Sources) {
		return api.LaunchInputs{}, api.NotImplemented("lb-v2-admin", "ResolveLaunchSources")
	}
	sources, err := s.deps.Sources.ResolveLaunchSources(ctx, api.LaunchSourceRequest{ReservationID: r.ID, GrantSetID: grants.ID, Claim: api.PlanningClaim(r.ID, execution.lease)})
	if err != nil {
		return api.LaunchInputs{}, failure(err)
	}
	inputs := api.LaunchInputs{Grants: grants, Sources: sources}
	next := api.LaunchPlanRecord{Reservation: r, Generation: execution.record.Generation, Phase: "sourced", Inputs: &inputs}
	if err := api.ValidateLaunchPlanRecord(next); err != nil {
		return api.LaunchInputs{}, failure(err)
	}
	if sources.Runtime.Driver != execution.input.driver {
		return api.LaunchInputs{}, integrity("enrolled runtime differs from the retained driver")
	}
	if previous := execution.input.previousPlan; previous != nil &&
		(sources.Runtime != previous.Inputs.Sources.Runtime || sources.Project != previous.Inputs.Sources.Project) {
		return api.LaunchInputs{}, problem(api.CodeConflict, "retained runtime or project enrollment changed",
			"Use an explicitly supported migration before changing the private session's enrolled pins.")
	}
	if r.Mode == "start" {
		var request api.StartRequest
		if err := json.Unmarshal(execution.input.request.Params, &request); err != nil {
			return api.LaunchInputs{}, failure(err)
		}
		if sources.Project.ProjectID != request.ProjectID {
			return api.LaunchInputs{}, integrity("source resolver selected a different logical project")
		}
	}
	if execution.record.Inputs != nil && !reflect.DeepEqual(*execution.record.Inputs, inputs) {
		return api.LaunchInputs{}, integrity("pinned launch inputs changed after source selection")
	}
	return inputs, nil
}
