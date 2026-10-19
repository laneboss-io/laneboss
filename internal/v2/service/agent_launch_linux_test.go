//go:build linux

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The launcher/helper below are narrow component boundaries.  The reservation,
// plan, child claim, identity binding, observation, lane transition and event
// journal all come from the real store and service owner.
type agentOwnerLauncher struct {
	state           *planningPolicyStore
	missingPrepared bool
}

func (l *agentOwnerLauncher) Probe(context.Context) (api.IsolationCapabilities, error) {
	return api.IsolationCapabilities{Backend: "linux-bwrap-landlock", Available: true, Checks: []api.Capability{{Name: "fixture", Available: true}}}, nil
}

func (l *agentOwnerLauncher) Prepare(ctx context.Context, spec api.LaunchSpec) (api.PreparedLaunch, error) {
	parent, ok := api.EffectLeaseFromContext(ctx)
	if !ok {
		return api.PreparedLaunch{}, api.NotImplemented("test", "parent planning lease")
	}
	scope := api.Scope{Config: "launch-fixture", Actor: api.Actor{Kind: "service", ID: parent.Record.ClaimantID}, Source: "worker"}
	record, err := l.state.LaunchPlan(ctx, scope, spec.PlanID)
	if err != nil || record.Plan == nil {
		return api.PreparedLaunch{}, err
	}
	if l.missingPrepared {
		return api.PreparedLaunch{}, nil
	}
	return api.PreparedLaunch{ID: api.ID("prepared-" + string(spec.LaunchID)), SpecSHA256: record.Handoff.SpecSHA256, Target: spec.Target,
		ContainmentID: record.Plan.Lease.ContainmentID, ProcessGeneration: "owner-process-" + string(spec.LaunchID), EndpointGeneration: record.Plan.Lease.EndpointGeneration, GateID: api.ID("gate-" + string(spec.LaunchID))}, nil
}

func (l *agentOwnerLauncher) Launch(_ context.Context, prepared api.PreparedLaunch, permit api.LaunchPermit) (api.ProcessHandle, error) {
	return api.ProcessHandle{ID: api.ID("process-" + string(permit.LaunchID)), Target: prepared.Target, ContainmentID: prepared.ContainmentID, Generation: prepared.ProcessGeneration}, nil
}

func (*agentOwnerLauncher) Observe(context.Context, api.ProcessHandle) (api.ProcessObservation, error) {
	return api.ProcessObservation{}, api.NotImplemented("test", "observe")
}
func (*agentOwnerLauncher) Stop(context.Context, api.ProcessHandle, string) (api.ProcessObservation, error) {
	return api.ProcessObservation{}, api.NotImplemented("test", "stop")
}
func (*agentOwnerLauncher) Abort(context.Context, api.PreparedLaunch) error {
	return api.NotImplemented("test", "abort")
}
func (*agentOwnerLauncher) Collect(context.Context, api.ID, api.ProcessObservation) error {
	return api.NotImplemented("test", "collect")
}

type agentOwnerHelper struct {
	api.HelperControl
	state        *planningPolicyStore
	permitOffset api.Sequence
	omitPermit   bool
	omitProcess  bool
}

func (h *agentOwnerHelper) ReconcileGate(ctx context.Context, request api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	binding, err := h.state.LaunchBinding(ctx, request.LaunchID)
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	process := api.ProcessHandle{ID: api.ID("process-" + string(binding.Record.ID)), Target: binding.Record.Target, ContainmentID: binding.Prepared.ContainmentID, Generation: binding.Prepared.ProcessGeneration}
	survivors := uint64(1)
	now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	var processPtr *api.ProcessHandle
	if !h.omitProcess {
		processPtr = &process
	}
	permit := api.LaunchPermit{LaunchID: binding.Record.ID, PreparedID: binding.Prepared.ID, RecordSHA256: binding.Identity.RecordSHA256, CommittedSeq: binding.Identity.CommittedSeq + h.permitOffset}
	var permitPtr *api.LaunchPermit
	if !h.omitPermit {
		permitPtr = &permit
	}
	return api.LaunchReconciliation{Prepared: &binding.Prepared, Process: processPtr,
		Observation: api.ProcessObservation{Handle: process, State: "running", Survivors: &survivors, PromptStatus: "written", ObservedAt: now},
		GateState:   "consumed", ConsumedPermit: permitPtr}, nil
}

func TestAgentOwnerRetainedToOpened(t *testing.T) {
	f, reservation, effect := scopePlanningFixture(t)
	state := &planningPolicyStore{Service: f.State, effect: effect.ID}
	planner := successfulScopePlanner(t, state, f, effect)
	host := launchServer(t, f)
	host.deps.Store = state
	launcher := &agentOwnerLauncher{state: state}
	helper := &agentOwnerHelper{state: state}
	host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: planner, Helper: helper, Worker: state.sourcePorts, Launcher: launcher}
	scope := api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: fx.ID(t)}, Source: "worker"}
	lease, err := state.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal("planning claim failed", err)
	}
	outcome, err := host.runEffect(context.Background(), scope, lease)
	if err != nil {
		t.Fatal("agent owner did not drive the retained plan", err)
	}
	if outcome.LaunchPlan == nil || outcome.Process == nil {
		t.Fatal("owner omitted measured opened plan or process")
	}
	if _, err := state.CompleteEffect(context.Background(), scope, outcome); err != nil {
		t.Fatal("parent planning completion failed", err)
	}
	retained, err := state.LaunchPlan(context.Background(), scope, reservation.ID)
	if err != nil || retained.Phase != "opened" {
		t.Fatal("owner did not retain opened phase", err)
	}
	binding, err := state.LaunchBinding(context.Background(), reservation.LaunchID)
	if err != nil || binding.Prepared.ID == "" || binding.Identity.CommittedSeq == 0 {
		t.Fatal("owner did not retain committed identity binding", err)
	}
	child, err := state.Effect(context.Background(), scope, agentStageID(reservation.ID, "prepare-effect"))
	if err != nil || child.Outcome == nil || child.Outcome.Prepared == nil {
		t.Fatal("owner did not complete its durable prepare child", err)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
}

type agentOwnerAttempt struct {
	f           *fx.Fixture
	state       *planningPolicyStore
	planner     *lifecycle.Service
	host        *Server
	launcher    *agentOwnerLauncher
	helper      *agentOwnerHelper
	scope       api.Scope
	lease       api.EffectLease
	reservation api.LaunchReservation
}

func newAgentOwnerAttempt(t *testing.T) *agentOwnerAttempt {
	t.Helper()
	f, reservation, effect := scopePlanningFixture(t)
	state := &planningPolicyStore{Service: f.State, effect: effect.ID}
	planner := successfulScopePlanner(t, state, f, effect)
	host := launchServer(t, f)
	host.deps.Store = state
	launcher := &agentOwnerLauncher{state: state}
	helper := &agentOwnerHelper{state: state}
	host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: planner, Helper: helper, Worker: state.sourcePorts, Launcher: launcher}
	scope := api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: fx.ID(t)}, Source: "worker"}
	lease, err := state.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal("planning claim failed", err)
	}
	t.Cleanup(func() {
		if err := host.Close(); err != nil {
			t.Error(err)
		}
	})
	return &agentOwnerAttempt{f: f, state: state, planner: planner, host: host, launcher: launcher, helper: helper, scope: scope, lease: lease, reservation: reservation}
}

func (a *agentOwnerAttempt) run(t *testing.T) error {
	t.Helper()
	_, err := a.host.runEffect(context.Background(), a.scope, a.lease)
	return err
}

func expectAgentOwnerCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("owner control returned %v, want %s", err, code)
	}
}

func TestAgentOwnerControls(t *testing.T) {
	t.Run("missing-prepared-receipt", func(t *testing.T) {
		a := newAgentOwnerAttempt(t)
		a.launcher.missingPrepared = true
		expectAgentOwnerCode(t, a.run(t), api.CodeIntegrity)
	})
	t.Run("missing-consumed-permit", func(t *testing.T) {
		a := newAgentOwnerAttempt(t)
		a.helper.omitPermit = true
		expectAgentOwnerCode(t, a.run(t), api.CodeContainmentUnknown)
	})
	t.Run("replayed-permit", func(t *testing.T) {
		a := newAgentOwnerAttempt(t)
		a.helper.permitOffset = 1
		expectAgentOwnerCode(t, a.run(t), api.CodeContainmentUnknown)
	})
	t.Run("stale-parent-claim", func(t *testing.T) {
		a := newAgentOwnerAttempt(t)
		a.lease.Record.Generation--
		expectAgentOwnerCode(t, a.run(t), api.CodeConflict)
	})
}

func TestAgentOwnerForeignPrepareClaim(t *testing.T) {
	a := newAgentOwnerAttempt(t)
	policy, err := a.state.Policy(context.Background(), a.scope)
	if err != nil {
		t.Fatal(err)
	}
	a.scope.PolicyGeneration = policy.Generation
	plan, err := a.planner.PlanLaunch(context.Background(), a.scope, api.LaunchPlanRequest{Lease: a.lease})
	if err != nil {
		t.Fatal("retained plan setup failed", err)
	}
	r := plan.Reservation
	record, err := a.state.LaunchPlan(context.Background(), a.scope, r.ID)
	if err != nil || record.Handoff == nil {
		t.Fatal("retained handoff setup failed", err)
	}
	effectID := agentStageID(r.ID, "prepare-effect")
	cause := api.InternalIntent{ID: agentStageID(r.ID, "prepare-cause"), Kind: api.InternalHelperPrepare, Config: r.Config,
		Actor: a.lease.Record.Effect.Context.Actor, RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID,
		EffectID: effectID, Target: r.Target, LogicalTurnID: a.lease.Record.Effect.Context.LogicalTurnID, CancellationEpoch: r.CancellationEpoch}
	effect := api.Effect{ID: effectID, OperationID: r.OperationID, Context: &cause, HelperPrepare: &api.HelperLaunchRequest{Cause: cause, LeaseID: plan.Lease.ID, PreparedSpecID: r.SpecID, SpecSHA256: record.Handoff.SpecSHA256}}
	foreign := a.scope
	foreign.Actor.ID = fx.ID(t)
	emit := cause
	emit.Actor = foreign.Actor
	emit.ID = agentStageID(r.ID, "foreign-prepare-intent")
	if _, err := a.state.Transact(context.Background(), api.Transaction{Scope: foreign, Internal: &emit, Effects: []api.Effect{effect}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}); err != nil {
		t.Fatal("foreign prepare effect setup failed", err)
	}
	if _, err := a.state.ClaimEffect(context.Background(), foreign, api.EffectClaimRequest{EffectID: effectID, ExpectedGeneration: 1, ClaimantID: foreign.Actor.ID, Deadline: fx.Expiry()}); err != nil {
		t.Fatal("foreign prepare claim setup failed", err)
	}
	expectAgentOwnerCode(t, a.run(t), api.CodeConflict)
}

// This exercises retained input lookup only. The store tests own genuine
// continuation selection/claim/completion; no process is launched here.
func TestContInput(t *testing.T) {
	f := fx.New(t)
	f.Reserve(t)
	f.Source(t)
	f.PlanSetup = func(p *api.LaunchPlan) {
		p.Runner.Prompt = f.Retain(t, "prompt", fx.JSON(t, map[string]any{"guidance_id": fx.ID(t)}), f.Execution.Actor, f.Reservation.Target.LifeID)
	}
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	ctx := context.Background()
	template := api.TemplateRef{ID: fx.ID(t), SourceSHA256: fx.Digest([]byte(fx.ID(t))), Generation: 1, RenderedSHA256: f.Plan.Runner.Prompt.SHA256}
	briefing := api.Briefing{Template: template, Markdown: f.Plan.Runner.Prompt, PolicyGeneration: f.Reservation.PolicyGeneration,
		Sources: []api.SourceRef{}, Checks: []api.Capability{}, LaneGroups: api.LaneGroups{Running: []api.ID{}, Ended: []api.ID{}, Accepted: []api.ID{}, Lost: []api.ID{}, Idle: []api.ID{}, Others: []api.ID{}}}
	stage := fx.JSON(t, map[string]any{"schema": "laneboss.launch-stage.v2", "input": fx.Digest(fx.JSON(t, f.Reservation.ID)), "value": briefing})
	cause := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{
		ObjectKey: launchStageID(f.Reservation.ID, "result-briefing"), Class: "manifest", Bytes: stage, SHA256: fx.Digest(stage), Origin: "service",
		ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, LifeID: f.Reservation.Target.LifeID, Audience: "owner", Generation: 1}}}); err != nil {
		t.Fatal(err)
	}
	plan := f.Plan
	r := plan.Reservation
	r.ID, r.Mode, r.PreviousLaunchID = fx.ID(t), "continue", f.Reservation.LaunchID
	r.Target.Run++
	r.BaseGeneration = f.Lane.Generation
	request := api.ContinuationRequest{IntentID: fx.ID(t), Swap: api.ProfileSwap{OperationID: r.OperationID, CausingRun: f.Lane.Run, ContinuationRun: r.Target.Run,
		ProfileGrantID: f.Plan.Runner.Slot.ProfileGrantID, FromProfileID: f.Plan.Runner.Slot.ProfileID, ToProfileID: f.Plan.Runner.Slot.ProfileID,
		ExpectedGeneration: r.BaseGeneration, CancellationEpoch: r.CancellationEpoch, LogicalTurnID: f.Lane.LogicalTurnID, Limit: api.LimitSignal{Target: f.Reservation.Target}}}
	r.OriginalRequest = f.Retain(t, "launch_request", fx.JSON(t, request), f.Execution.Actor, r.Target.LifeID)
	plan.Reservation = r
	f.Opened(t)
	f.Ended(t)
	host := launchServer(t, f)
	input, err := host.agentLaunchInput(ctx, f.Execution, plan)
	if err != nil || input.template != template || input.trigger.Kind != "profile_limit" {
		t.Fatal("continued open lost the original briefing or quota cause", err)
	}
	event := launchEventPayload(f.Lane, plan, r, api.TurnSnapshot{}, input)
	if event.ProfileSwap == nil || *event.ProfileSwap != request.Swap || event.ProfileContinuationOf != request.Swap.CausingRun || event.Trigger.Kind != "profile_limit" {
		t.Fatal("continued launch event omitted the actual swap")
	}
}
