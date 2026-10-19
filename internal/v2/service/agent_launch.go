package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// agentLaunchStore is intentionally small.  The service drives the agent
// stages through the single durable store; IDs and in-memory flights never
// establish authority.
type agentLaunchStore interface {
	LaunchBinding(context.Context, api.ID) (api.LaunchBindingRequest, error)
	RecordLaunchObservation(context.Context, api.ID, api.LaunchReconciliation) error
}

type agentLaunchInput struct {
	task     api.BlobRef
	name     string
	model    string
	effort   string
	level    int
	role     string
	trigger  api.Trigger
	guidance api.ID
	template api.TemplateRef
	swap     *api.ProfileSwap
}

func agentStageID(reservation api.ID, stage string) api.ID {
	return api.ID(digestAgentBytes([]byte("agent-stage\x00" + string(reservation) + "\x00" + stage)))
}

func launchStageID(reservation api.ID, stage string) api.ID {
	return api.ID(digestAgentBytes([]byte("launch\x00" + string(reservation) + "\x00" + stage)))
}

func digestAgentBytes(value []byte) string {
	// The store's object/effect IDs are opaque stable pins.  SHA-256 keeps the
	// derived ID within the wire ID grammar and avoids a caller-selected path.
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func (s *Server) reconcileAgentLaunch(ctx context.Context, scope api.Scope, lease api.EffectLease, plan api.LaunchPlan, runtime api.RuntimeServices) (_ api.LaunchPlan, _ api.ProcessHandle, resultErr error) {
	check := "agent_record"
	defer func() { api.ObserveHelperReason(ctx, resultErr, check) }()
	store, ok := runtime.Store.(agentLaunchStore)
	if !ok {
		return api.LaunchPlan{}, api.ProcessHandle{}, serviceError(api.CodePrerequisite, "agent launch requires the single store's durable binding and observation ports")
	}
	if plan.Reservation.ID == "" || plan.Reservation.OperationID == "" || plan.Reservation.Target.LifeID == "" {
		return api.LaunchPlan{}, api.ProcessHandle{}, serviceError(api.CodeIntegrity, "agent launch plan has incomplete retained identity")
	}
	record, err := runtime.Store.LaunchPlan(ctx, scope, plan.Reservation.ID)
	if err != nil {
		return api.LaunchPlan{}, api.ProcessHandle{}, err
	}
	if record.Plan == nil || !reflect.DeepEqual(*record.Plan, plan) {
		return api.LaunchPlan{}, api.ProcessHandle{}, serviceError(api.CodeIntegrity, "agent launch plan changed before native staging")
	}
	if record.Phase == "failed" || record.Handoff == nil {
		return api.LaunchPlan{}, api.ProcessHandle{}, serviceError(api.CodeConflict, "agent launch has no current retained spec handoff")
	}

	if record.Phase == "spec_retained" {
		check = "agent_prepare"
		prepared, prepareLease, err := s.prepareAgent(ctx, scope, lease, record, runtime)
		if err != nil {
			return api.LaunchPlan{}, api.ProcessHandle{}, err
		}
		check = "agent_bind"
		if _, err := s.bindAgent(ctx, scope, lease, prepareLease, record, plan, prepared); err != nil {
			return api.LaunchPlan{}, api.ProcessHandle{}, err
		}
		check = "agent_child_done"
		if err := s.completePreparedChild(ctx, scope, prepareLease, prepared); err != nil {
			return api.LaunchPlan{}, api.ProcessHandle{}, err
		}
		record, err = runtime.Store.LaunchPlan(ctx, scope, plan.Reservation.ID)
		if err != nil {
			return api.LaunchPlan{}, api.ProcessHandle{}, err
		}
		if record.Phase != "bound" || record.Plan == nil || record.Handoff == nil {
			return api.LaunchPlan{}, api.ProcessHandle{}, serviceError(api.CodeIntegrity, "agent prepare did not retain its bound launch plan")
		}
		plan = *record.Plan
	}
	if record.Phase == "bound" {
		check = "agent_bound_child"
		binding, err := s.Binding(ctx, plan.Reservation.LaunchID)
		if err != nil {
			return api.LaunchPlan{}, api.ProcessHandle{}, err
		}
		if err := s.finishPreparedChild(ctx, scope, lease, record, binding.Prepared); err != nil {
			return api.LaunchPlan{}, api.ProcessHandle{}, err
		}
	}

	check = "agent_binding"
	binding, err := s.Binding(ctx, plan.Reservation.LaunchID)
	if err != nil {
		return api.LaunchPlan{}, api.ProcessHandle{}, err
	}
	check = "agent_binding_plan"
	if err := api.ValidateLaunchBindingPlan(binding, plan); err != nil {
		return api.LaunchPlan{}, api.ProcessHandle{}, err
	}
	if record.Phase == "opened" {
		check = "agent_recover"
		actual, err := runtime.Helper.ReconcileGate(ctx, api.HelperReconcileRequest{LeaseID: plan.Lease.ID, LaunchID: binding.Record.ID, PreparedID: binding.Prepared.ID, OperationID: plan.Reservation.OperationID})
		if err != nil {
			return api.LaunchPlan{}, api.ProcessHandle{}, err
		}
		if actual.Process == nil || actual.ConsumedPermit == nil {
			return api.LaunchPlan{}, api.ProcessHandle{}, serviceError(api.CodeContainmentUnknown, "opened launch lost its measured process or consumed identity permit")
		}
		if err := store.RecordLaunchObservation(ctx, binding.Record.ID, actual); err != nil {
			return api.LaunchPlan{}, api.ProcessHandle{}, err
		}
		return plan, *actual.Process, nil
	}

	permit := api.LaunchPermit{LaunchID: binding.Record.ID, PreparedID: binding.Prepared.ID, RecordSHA256: binding.Identity.RecordSHA256, CommittedSeq: binding.Identity.CommittedSeq}
	openCtx := api.WithEffectLease(ctx, lease)
	check = "agent_open"
	process, err := runtime.Launcher.Launch(openCtx, binding.Prepared, permit)
	if err != nil {
		return api.LaunchPlan{}, api.ProcessHandle{}, err
	}
	check = "agent_observe"
	actual, err := runtime.Helper.ReconcileGate(openCtx, api.HelperReconcileRequest{LeaseID: plan.Lease.ID, LaunchID: binding.Record.ID, PreparedID: binding.Prepared.ID, OperationID: plan.Reservation.OperationID})
	if err != nil {
		return api.LaunchPlan{}, api.ProcessHandle{}, err
	}
	if actual.Process == nil || *actual.Process != process || actual.ConsumedPermit == nil || *actual.ConsumedPermit != permit {
		return api.LaunchPlan{}, api.ProcessHandle{}, serviceError(api.CodeContainmentUnknown, "opened gate lacks its measured process and consumed identity permit")
	}
	check = "agent_measure"
	if err := store.RecordLaunchObservation(openCtx, binding.Record.ID, actual); err != nil {
		return api.LaunchPlan{}, api.ProcessHandle{}, err
	}
	check = "agent_publish"
	opened, err := s.publishOpened(ctx, scope, lease, record, plan, binding, process)
	if err != nil {
		return api.LaunchPlan{}, api.ProcessHandle{}, err
	}
	return opened, process, nil
}

func (s *Server) prepareAgent(ctx context.Context, scope api.Scope, parent api.EffectLease, record api.LaunchPlanRecord, runtime api.RuntimeServices) (api.PreparedLaunch, api.EffectLease, error) {
	if record.Handoff == nil || record.Plan == nil {
		return api.PreparedLaunch{}, api.EffectLease{}, serviceError(api.CodeIntegrity, "agent prepare requires its retained spec and plan")
	}
	r := record.Reservation
	effectID := agentStageID(r.ID, "prepare-effect")
	cause := api.InternalIntent{ID: agentStageID(r.ID, "prepare-cause"), Kind: api.InternalHelperPrepare, Config: r.Config,
		Actor: parent.Record.Effect.Context.Actor, RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID,
		EffectID: effectID, Target: r.Target, LogicalTurnID: parent.Record.Effect.Context.LogicalTurnID, CancellationEpoch: r.CancellationEpoch}
	request := api.HelperLaunchRequest{Cause: cause, LeaseID: record.Plan.Lease.ID, PreparedSpecID: record.Handoff.Spec.ID, SpecSHA256: record.Handoff.SpecSHA256}
	effect := api.Effect{ID: effectID, OperationID: r.OperationID, Context: &cause, HelperPrepare: &request}
	child, err := s.ensureAgentPrepareEffect(ctx, scope, parent, effect)
	if err != nil {
		return api.PreparedLaunch{}, api.EffectLease{}, err
	}
	if child.Record.Outcome != nil {
		return api.PreparedLaunch{}, api.EffectLease{}, serviceError(api.CodeContainmentUnknown, "prepared child completed before its atomic bound launch transition")
	}
	prepareCtx := api.WithPrepareLease(api.WithPlanningLease(api.WithEffectLease(ctx, parent), parent), child)
	prepared, err := runtime.Launcher.Prepare(prepareCtx, record.Handoff.Spec)
	if err != nil {
		return api.PreparedLaunch{}, api.EffectLease{}, err
	}
	if prepared.Target != r.Target || prepared.SpecSHA256 != record.Handoff.SpecSHA256 || prepared.ContainmentID != record.Plan.Lease.ContainmentID || prepared.EndpointGeneration != record.Plan.Lease.EndpointGeneration || prepared.ID == "" || prepared.GateID == "" || prepared.ProcessGeneration == "" {
		return api.PreparedLaunch{}, api.EffectLease{}, serviceError(api.CodeIntegrity, "helper prepared gate differs from the retained launch allocation")
	}
	return prepared, child, nil
}

func childLease(record api.EffectRecord) api.EffectLease {
	return api.EffectLease{Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt}
}

func (s *Server) completePreparedChild(ctx context.Context, scope api.Scope, lease api.EffectLease, prepared api.PreparedLaunch) error {
	if lease.Record.Outcome != nil {
		if lease.Record.Outcome.Prepared == nil || *lease.Record.Outcome.Prepared != prepared {
			return serviceError(api.CodeIntegrity, "prepared child outcome changed its measured gate")
		}
		return nil
	}
	if _, err := s.deps.Store.CompleteEffect(ctx, scope, api.EffectOutcome{EffectID: lease.Record.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "succeeded", Prepared: &prepared}); err != nil {
		return err
	}
	completed, err := s.deps.Store.Effect(ctx, scope, lease.Record.Effect.ID)
	if err != nil {
		return err
	}
	if completed.Outcome == nil || completed.Outcome.Prepared == nil || *completed.Outcome.Prepared != prepared {
		return serviceError(api.CodeIntegrity, "prepared child did not retain its measured gate")
	}
	return nil
}

func (s *Server) finishPreparedChild(ctx context.Context, scope api.Scope, parent api.EffectLease, record api.LaunchPlanRecord, prepared api.PreparedLaunch) error {
	effectID := agentStageID(record.Reservation.ID, "prepare-effect")
	child, err := s.deps.Store.Effect(ctx, scope, effectID)
	if err != nil {
		return err
	}
	if child.Outcome != nil {
		if child.Outcome.Prepared == nil || *child.Outcome.Prepared != prepared {
			return serviceError(api.CodeIntegrity, "bound launch retained a different prepared child outcome")
		}
		return nil
	}
	var lease api.EffectLease
	if child.State == api.EffectClaimed {
		expires, parseErr := time.Parse(time.RFC3339Nano, string(child.ClaimExpiresAt))
		if parseErr != nil || expires.After(s.deps.Clock.Now()) && child.ClaimantID != scope.Actor.ID {
			return serviceError(api.CodeConflict, "bound launch prepare child is claimed by another current executor")
		}
		if parseErr == nil && expires.After(s.deps.Clock.Now()) && child.ClaimantID == scope.Actor.ID {
			lease = childLease(child)
		}
	}
	if lease.ClaimID == "" {
		var err error
		lease, err = s.deps.Store.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: child.Effect.ID, ExpectedGeneration: child.Generation, ClaimantID: scope.Actor.ID, Deadline: parent.ExpiresAt})
		if err != nil {
			return err
		}
	}
	return s.completePreparedChild(ctx, scope, lease, prepared)
}

func (s *Server) ensureAgentPrepareEffect(ctx context.Context, scope api.Scope, parent api.EffectLease, effect api.Effect) (api.EffectLease, error) {
	record, err := s.deps.Store.Effect(ctx, scope, effect.ID)
	if err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
			return api.EffectLease{}, err
		}
		internal := *effect.Context
		internal.Actor = scope.Actor
		internal.ID = agentStageID(effect.Context.Target.LifeID, "prepare-intent-"+string(parent.ClaimID))
		if _, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: scope, Internal: &internal, Effects: []api.Effect{effect}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: effect.Context.Target.LifeID, Epoch: effect.Context.CancellationEpoch}}}}); err != nil {
			return api.EffectLease{}, err
		}
		record, err = s.deps.Store.Effect(ctx, scope, effect.ID)
		if err != nil {
			return api.EffectLease{}, err
		}
	}
	if !reflect.DeepEqual(record.Effect, effect) {
		return api.EffectLease{}, serviceError(api.CodeIntegrity, "prepare child changed its retained causal input")
	}
	if record.Outcome != nil {
		return childLease(record), nil
	}
	if record.State == api.EffectClaimed {
		expires, parseErr := time.Parse(time.RFC3339Nano, string(record.ClaimExpiresAt))
		if parseErr != nil || expires.After(s.deps.Clock.Now()) && record.ClaimantID != scope.Actor.ID {
			return api.EffectLease{}, serviceError(api.CodeConflict, "prepare child is claimed by another current executor")
		}
		if expires.After(s.deps.Clock.Now()) && record.ClaimantID == scope.Actor.ID {
			return childLease(record), nil
		}
	}
	lease, err := s.deps.Store.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: record.Generation, ClaimantID: scope.Actor.ID, Deadline: parent.ExpiresAt})
	if err != nil {
		return api.EffectLease{}, err
	}
	return lease, nil
}

func (s *Server) bindAgent(ctx context.Context, scope api.Scope, parent api.EffectLease, prepare api.EffectLease, record api.LaunchPlanRecord, plan api.LaunchPlan, prepared api.PreparedLaunch) (_ api.LaunchBindingRequest, resultErr error) {
	check := "agent_binding"
	defer func() { api.ObserveHelperReason(ctx, resultErr, check) }()
	store, ok := s.deps.Store.(interface {
		LaunchBinding(context.Context, api.ID) (api.LaunchBindingRequest, error)
	})
	if !ok {
		return api.LaunchBindingRequest{}, serviceError(api.CodePrerequisite, "agent binding requires the store's durable launch binding port")
	}
	binding, err := store.LaunchBinding(ctx, record.Reservation.LaunchID)
	if err == nil {
		if err := api.ValidateLaunchBindingPlan(binding, plan); err != nil {
			return api.LaunchBindingRequest{}, err
		}
		return binding, nil
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
		return api.LaunchBindingRequest{}, err
	}
	r := record.Reservation
	check = "agent_input"
	input, err := s.agentLaunchInput(ctx, scope, plan)
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	lane, baseGeneration, err := s.agentLane(ctx, scope, plan, input)
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	turn, err := s.agentTurn(ctx, scope, plan, input, lane)
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	check = "agent_endpoint"
	endpoint, err := wire.LaneEndpointBinding(s.deps.Binding, record.Handoff.Spec, plan.Lease)
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	actorID := api.ID(digestAgentBytes([]byte("lane-actor\x00" + string(r.LaunchID))))
	launch := api.LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target, ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID,
		StarterChain: append([]api.ID{}, r.StarterChain...), StarterEventSeq: r.StarterEventSeq,
		Actor: api.Actor{Kind: "lane", ID: actorID, LifeID: r.Target.LifeID, Level: r.Level, Role: r.Role}, UIDLeaseID: plan.Lease.ID, HostUID: plan.Lease.UID,
		ProcessGeneration: prepared.ProcessGeneration, ContainmentID: plan.Lease.ContainmentID, GrantSetID: r.GrantSetID, GrantsSHA256: plan.Inputs.Grants.SHA256,
		PolicyGeneration: r.PolicyGeneration, EndpointGeneration: plan.Lease.EndpointGeneration}
	recovery := api.LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: *record.Handoff, Home: plan.Data.Home, Capture: plan.Capture}
	binding = api.LaunchBindingRequest{Record: launch, Prepared: prepared, Recovery: &recovery}
	bound := record
	bound.Generation = record.Generation + 1
	bound.Phase = "bound"
	bound.Plan = &plan
	bound.Handoff = record.Handoff
	events := []api.Event{}
	identity, err := agentEvent(r, scope.Actor, "identity.bound", turn.LogicalTurnID, launch, s.deps.Clock.Now())
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	events = append(events, identity)
	preparedEvent, err := agentEvent(r, scope.Actor, "launch.prepared", turn.LogicalTurnID, launchEventPayload(lane, plan, r, turn, input), s.deps.Clock.Now())
	if err != nil {
		return api.LaunchBindingRequest{}, err
	}
	events = append(events, preparedEvent)
	if r.Target.Run == 1 {
		kind := api.EventKind("lane.created")
		if r.Mode == "adopt" {
			kind = "lane.adopted"
		}
		created, err := agentEvent(r, scope.Actor, kind, turn.LogicalTurnID, launchEventPayload(lane, plan, r, turn, input), s.deps.Clock.Now())
		if err != nil {
			return api.LaunchBindingRequest{}, err
		}
		events = append(events, created)
	}
	cause := api.InternalIntent{ID: agentStageID(r.ID, "bind-"+string(prepare.ClaimID)), Kind: api.InternalHelperPrepare, Config: r.Config, Actor: scope.Actor,
		RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: prepare.Record.Effect.ID, Target: r.Target,
		LogicalTurnID: parent.Record.Effect.Context.LogicalTurnID, CancellationEpoch: r.CancellationEpoch}
	check = "agent_bind_tx"
	if _, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: scope, Internal: &cause,
		Writes: api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{bound}, IdentityBindings: []api.LaunchBindingRequest{binding}, Endpoints: []api.EndpointProjection{{Binding: endpoint, Generation: 1}}, Lanes: []api.Lane{lane}, Turns: []api.TurnSnapshot{turn}},
		Events: events, Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: record.Generation}, {Kind: api.CompareLane, ID: r.Target.LifeID, Generation: baseGeneration}},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}); err != nil {
		return api.LaunchBindingRequest{}, err
	}
	check = "agent_bind_read"
	return store.LaunchBinding(ctx, r.LaunchID)
}

func (s *Server) publishOpened(ctx context.Context, scope api.Scope, parent api.EffectLease, record api.LaunchPlanRecord, plan api.LaunchPlan, binding api.LaunchBindingRequest, process api.ProcessHandle) (_ api.LaunchPlan, resultErr error) {
	check := "agent_publish"
	defer func() { api.ObserveHelperReason(ctx, resultErr, check) }()
	current, err := s.deps.Store.LaunchPlan(ctx, scope, record.Reservation.ID)
	if err != nil {
		return api.LaunchPlan{}, err
	}
	if current.Phase == "opened" {
		return *current.Plan, nil
	}
	if current.Phase != "bound" || current.Plan == nil {
		return api.LaunchPlan{}, serviceError(api.CodeConflict, "opened publication requires the retained bound plan")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, current.Reservation.Target)
	if err != nil {
		return api.LaunchPlan{}, err
	}
	if lane.LaunchID != binding.Record.ID || process.Target != binding.Record.Target {
		return api.LaunchPlan{}, serviceError(api.CodeIntegrity, "opened process differs from the bound lane identity")
	}
	if process.ContainmentID != binding.Record.ContainmentID || process.Generation != binding.Record.ProcessGeneration {
		allowAndLog("opened_process_identity")
	}
	r := current.Reservation
	running := lane
	running.Generation++
	running.State, running.Containment = "running", "running"
	opened := current
	opened.Generation = current.Generation + 1
	opened.Phase = "opened"
	opened.Plan = current.Plan
	turn, err := s.deps.Store.Turn(ctx, scope, r.Target, lane.LogicalTurnID)
	if err != nil {
		return api.LaunchPlan{}, err
	}
	input, err := s.agentLaunchInput(ctx, scope, *current.Plan)
	if err != nil {
		return api.LaunchPlan{}, err
	}
	eventPayload := launchEventPayload(running, *current.Plan, r, turn, input)
	started, err := agentEvent(r, scope.Actor, "lane.started", turn.LogicalTurnID, eventPayload, s.deps.Clock.Now())
	if err != nil {
		return api.LaunchPlan{}, err
	}
	cause := api.InternalIntent{ID: agentStageID(r.ID, "open-"+string(parent.ClaimID)), Kind: api.InternalHelperOpen, Config: r.Config, Actor: scope.Actor,
		RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: parent.Record.Effect.ID, Target: r.Target,
		LogicalTurnID: parent.Record.Effect.Context.LogicalTurnID, CancellationEpoch: r.CancellationEpoch}
	check = "agent_open_tx"
	if _, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: scope, Internal: &cause, Writes: api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{opened}, Lanes: []api.Lane{running}}, Events: []api.Event{started},
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: current.Generation}, {Kind: api.CompareLane, ID: r.Target.LifeID, Generation: lane.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}); err != nil {
		return api.LaunchPlan{}, err
	}
	retained, err := s.deps.Store.LaunchPlan(ctx, scope, r.ID)
	if err != nil {
		return api.LaunchPlan{}, err
	}
	if retained.Phase != "opened" || retained.Plan == nil || !reflect.DeepEqual(*retained.Plan, plan) {
		return api.LaunchPlan{}, serviceError(api.CodeIntegrity, "opened publication did not retain its exact launch plan")
	}
	return *retained.Plan, nil
}

func (s *Server) agentLaunchInput(ctx context.Context, scope api.Scope, plan api.LaunchPlan) (agentLaunchInput, error) {
	r := plan.Reservation
	input := agentLaunchInput{level: r.Level, role: r.Role, model: "", effort: "", trigger: api.Trigger{Kind: r.Mode, MailIDs: []api.ID{}, CausingSeqs: []api.Sequence{}}}
	if r.Mode == "start" || r.Mode == "adopt" {
		raw, err := s.readAgentObject(ctx, scope, r.OriginalRequest)
		if err != nil {
			return input, err
		}
		var request api.Request
		if err := api.DecodeObject(raw, &request); err != nil {
			return input, err
		}
		if r.Mode == "start" {
			var start api.StartRequest
			if err := api.DecodeObject(request.Params, &start); err != nil {
				return input, err
			}
			input.task, input.name, input.model, input.effort, input.level, input.role = start.Task, start.Lane, start.Model, start.Effort, start.Level, start.Role
		} else {
			var adopt api.AdoptRequest
			if err := api.DecodeObject(request.Params, &adopt); err != nil {
				return input, err
			}
			input.task, input.name, input.model, input.effort, input.level, input.role = adopt.Task, adopt.Lane, adopt.Model, adopt.Effort, adopt.Level, adopt.Role
		}
	} else {
		prior, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: r.Target.LifeID, Run: r.Target.Run - 1})
		if err != nil {
			return input, err
		}
		input.task, input.name, input.model, input.effort, input.level, input.role = prior.Task, prior.Name, prior.Model, prior.Effort, prior.Level, prior.Role
		if r.Mode == "continue" {
			raw, err := s.readAgentObject(ctx, scope, r.OriginalRequest)
			if err != nil {
				return input, err
			}
			var request api.ContinuationRequest
			if api.DecodeObject(raw, &request) != nil || request.Swap.OperationID != r.OperationID || request.Swap.CausingRun != prior.Run || request.Swap.ContinuationRun != r.Target.Run || request.Swap.LogicalTurnID != prior.LogicalTurnID || request.Swap.ProfileGrantID != plan.Runner.Slot.ProfileGrantID || request.Swap.ToProfileID != plan.Runner.Slot.ProfileID || request.Swap.ExpectedGeneration != r.BaseGeneration || request.Swap.CancellationEpoch != r.CancellationEpoch || request.Swap.Limit.Target != (api.LifeRef{LifeID: prior.LifeID, Run: prior.Run}) {
				return input, serviceError(api.CodeIntegrity, "continued open lost its retained quota cause")
			}
			input.swap, input.trigger.Kind = &request.Swap, "profile_limit"
		}
		if r.Mode == "turn" {
			input.trigger.Kind = "turn"
		}
	}
	raw, err := s.readAgentObject(ctx, scope, plan.Runner.Prompt)
	if err != nil {
		return input, err
	}
	var prompt struct {
		GuidanceID api.ID `json:"guidance_id"`
	}
	if err := json.Unmarshal(raw, &prompt); err != nil {
		return input, err
	}
	input.guidance = prompt.GuidanceID
	briefingID := r.ID
	previous := r.PreviousLaunchID
	if r.Mode == "continue" {
		for n := 0; ; n++ {
			if n >= 128 {
				return input, serviceError(api.CodeIntegrity, "continued briefing ancestry exceeds its bound")
			}
			binding, err := s.deps.Store.LaunchBinding(ctx, previous)
			if err != nil {
				return input, err
			}
			if binding.Recovery == nil {
				return input, serviceError(api.CodeIntegrity, "continued briefing has no previous recovery")
			}
			retained, err := s.deps.Store.LaunchPlan(ctx, scope, binding.Recovery.PlanID)
			if err != nil {
				return input, err
			}
			if retained.Plan == nil || retained.Plan.Runner.Prompt != plan.Runner.Prompt {
				return input, serviceError(api.CodeIntegrity, "continued briefing changed its original prompt")
			}
			briefingID = retained.Reservation.ID
			if retained.Reservation.Mode != "continue" {
				break
			}
			previous = retained.Reservation.PreviousLaunchID
		}
	}
	briefing, err := s.agentBriefing(ctx, scope, briefingID)
	if err != nil {
		return input, err
	}
	input.template = briefing.Template
	return input, nil
}

func (s *Server) agentBriefing(ctx context.Context, scope api.Scope, reservation api.ID) (api.Briefing, error) {
	meta, err := s.deps.Store.ObjectMetadata(ctx, scope, launchStageID(reservation, "result-briefing"))
	if err != nil {
		return api.Briefing{}, err
	}
	raw, err := s.readAgentObject(ctx, scope, meta.Ref)
	if err != nil {
		return api.Briefing{}, err
	}
	var result struct {
		Schema string          `json:"schema"`
		Input  api.Digest      `json:"input"`
		Value  json.RawMessage `json:"value"`
	}
	if err := api.DecodeObject(raw, &result); err != nil || result.Schema != "laneboss.launch-stage.v2" || len(result.Value) == 0 {
		return api.Briefing{}, serviceError(api.CodeIntegrity, "retained launch briefing stage is not complete")
	}
	var briefing api.Briefing
	if err := api.DecodeObject(result.Value, &briefing); err != nil {
		return api.Briefing{}, err
	}
	return briefing, nil
}

func (s *Server) agentLane(ctx context.Context, scope api.Scope, plan api.LaunchPlan, input agentLaunchInput) (api.Lane, api.Generation, error) {
	r := plan.Reservation
	base := api.Generation(0)
	var lane api.Lane
	if r.Target.Run > 1 {
		prior, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: r.Target.LifeID, Run: r.Target.Run - 1})
		if err != nil {
			return lane, 0, err
		}
		base = prior.Generation
		lane = prior
		lane.Run = r.Target.Run
	} else {
		lane = api.Lane{Name: input.name, Level: input.level, Role: input.role, Model: input.model, Effort: input.effort, Task: input.task, Counters: api.TaskCounters{}, RootLifeID: r.RootLifeID, ParentLifeID: r.ParentLifeID, StarterChain: append([]api.ID{}, r.StarterChain...), StarterEventSeq: r.StarterEventSeq}
	}
	lane.LifeID, lane.LaunchID, lane.Generation, lane.State = r.Target.LifeID, r.LaunchID, r.Generation, "preparing"
	lane.CancellationEpoch, lane.Run = r.CancellationEpoch, r.Target.Run
	lane.LogicalTurnID = ""
	if parentTurn, ok := api.EffectLeaseFromContext(ctx); ok && parentTurn.Record.Effect.Context != nil {
		lane.LogicalTurnID = parentTurn.Record.Effect.Context.LogicalTurnID
	}
	lane.ProfileGrantID, lane.GrantSetID, lane.PolicyGeneration = plan.Runner.Slot.ProfileGrantID, r.GrantSetID, r.PolicyGeneration
	lane.BudgetRemaining, lane.Workspace, lane.Session, lane.Containment, lane.Cleaned = plan.Budget, plan.Data.Workspace, plan.Runner.Session, "prepared", false
	return lane, base, nil
}

func (s *Server) agentTurn(ctx context.Context, scope api.Scope, plan api.LaunchPlan, input agentLaunchInput, lane api.Lane) (api.TurnSnapshot, error) {
	target := api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}
	turn, err := s.deps.Store.Turn(ctx, scope, target, lane.LogicalTurnID)
	if err == nil {
		prompt := plan.Runner.Prompt
		if turn.Prompt == nil || *turn.Prompt != prompt {
			turn.Prompt = &prompt
			turn.Status = "prepared"
			turn.Generation++
		}
		return turn, nil
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
		return api.TurnSnapshot{}, err
	}
	prompt := plan.Runner.Prompt
	return api.TurnSnapshot{Target: target, LogicalTurnID: lane.LogicalTurnID, Task: lane.Task, Prompt: &prompt, Trigger: input.trigger,
		PolicyGeneration: lane.PolicyGeneration, Generation: 1, GuidanceID: input.guidance, MailIDs: append([]api.ID{}, input.trigger.MailIDs...), Status: "prepared",
		CreatedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))}, nil
}

func (s *Server) readAgentObject(ctx context.Context, scope api.Scope, ref api.BlobRef) ([]byte, error) {
	if ref.ID == "" || ref.Bytes <= 0 || ref.Bytes > api.MaxChunkBytes {
		return nil, serviceError(api.CodeIntegrity, "agent launch object reference is invalid")
	}
	chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Limit: int(ref.Bytes)})
	if err != nil {
		return nil, err
	}
	if chunk.ObjectID != ref.ID || chunk.Offset != 0 || int64(len(chunk.Data)) != ref.Bytes || chunk.SHA256 != ref.SHA256 {
		return nil, serviceError(api.CodeIntegrity, "agent launch object read-back changed its retained bytes")
	}
	return append([]byte{}, chunk.Data...), nil
}

func agentEvent(r api.LaunchReservation, actor api.Actor, kind api.EventKind, logicalTurn api.ID, payload any, now time.Time) (api.Event, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return api.Event{}, err
	}
	id := agentStageID(r.ID, "event-"+string(kind))
	return api.Event{Schema: api.SchemaVersion, ID: id, Config: r.Config, Kind: kind, Actor: actor, RequestedBy: r.RequestedBy, OperationID: r.OperationID, RequestID: r.RequestID,
		LifeID: r.Target.LifeID, Run: r.Target.Run, LogicalTurnID: logicalTurn, ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID,
		StarterChain: append([]api.ID{}, r.StarterChain...), StarterEventSeq: r.StarterEventSeq, RecordedAt: api.Timestamp(now.UTC().Format(time.RFC3339Nano)),
		RequestedAt: api.Timestamp(now.UTC().Format(time.RFC3339Nano)), ObservedAt: api.Timestamp(now.UTC().Format(time.RFC3339Nano)), Origin: "service", Payload: data}, nil
}

func launchEventPayload(lane api.Lane, plan api.LaunchPlan, r api.LaunchReservation, turn api.TurnSnapshot, input agentLaunchInput) api.LaunchEvent {
	event := api.LaunchEvent{Task: lane.Task, LaunchID: r.LaunchID, Lane: lane, GrantSetID: r.GrantSetID, GrantsSHA256: plan.Inputs.Grants.SHA256,
		PolicyGeneration: r.PolicyGeneration, PromptTemplate: input.template, TaskSHA256: lane.Task.SHA256, Prompt: plan.Runner.Prompt, BoundaryBackend: plan.Inputs.Sources.Runtime.Backend,
		EndpointGeneration: plan.Lease.EndpointGeneration, TaskSecretNames: append([]string{}, plan.Injection.TaskSecretNames...), TaskSecretFileNames: append([]string{}, plan.Injection.TaskSecretFileNames...),
		SecretGrantIDs: append([]api.ID{}, plan.Injection.GrantIDs...), SecretSourceVersions: append([]string{}, plan.Injection.SourceVersions...), InjectionOutcome: plan.Injection.Outcome, Trigger: turn.Trigger}
	if input.swap != nil {
		event.ProfileContinuationOf, event.ProfileSwap, event.Trigger = input.swap.CausingRun, input.swap, input.trigger
	}
	return event
}
