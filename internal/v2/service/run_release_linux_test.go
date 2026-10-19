//go:build linux

package service

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The process port supplies an explicit terminal observation; the reservation,
// launch, stop, release claim, completion and journal are the real components.
type endedRunLauncher struct {
	api.Launcher
	observation api.ProcessObservation
}

func (l *endedRunLauncher) Observe(context.Context, api.ProcessHandle) (api.ProcessObservation, error) {
	return l.observation, nil
}

func (l *endedRunLauncher) Stop(ctx context.Context, handle api.ProcessHandle, reason string) (api.ProcessObservation, error) {
	if reason == "" {
		return api.ProcessObservation{}, serviceError(api.CodeInvalid, "component stop requires its recorded reason")
	}
	return l.Observe(ctx, handle)
}

type measuredRunHelper struct {
	*drainHelperFixture
	requests []api.HelperReleaseRequest
	receipt  api.ReleaseReceipt
	failure  error
}

func (h *measuredRunHelper) Release(ctx context.Context, request api.HelperReleaseRequest) (api.ReleaseReceipt, error) {
	if err := ctx.Err(); err != nil {
		return api.ReleaseReceipt{}, err
	}
	if h.ack == nil {
		return api.ReleaseReceipt{}, serviceError(api.CodeContainmentUnknown, "release has no committed capture drain acknowledgement")
	}
	h.requests = append(h.requests, request)
	return h.receipt, h.failure
}

func stoppedRun(t *testing.T, clocks ...api.Clock) (*fx.Fixture, *Server, api.EffectLease, api.ProcessObservation) {
	t.Helper()
	var f *fx.Fixture
	if len(clocks) == 0 {
		f = fx.Ready(t, true)
	} else {
		deps := store.Dependencies{Config: "launch-fixture", Directory: privateHostDirectory(t), Clock: clocks[0]}
		state, err := store.New(deps)
		if err != nil {
			t.Fatal(err)
		}
		f = fx.NewIn(t, state, deps)
		t.Cleanup(func() {
			if err := f.State.Close(); err != nil {
				t.Error(err)
			}
		})
		f.Reserve(t)
		f.Source(t)
		f.BuildPlan(t, true)
		f.Spec(t)
		f.Bind(t)
	}
	f.Opened(t)
	s := launchServer(t, f)
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: &authFixture{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	s.runtime.Lifecycle = coordinator
	s.deps.Clock = f.Deps.Clock
	ended := f.Observation(t, "exited").Observation
	s.runtime.Launcher = &endedRunLauncher{observation: ended}
	cause := f.Intent(t, api.InternalLifecycleEffect)
	cause.ID, cause.EffectID, cause.CauseOperationID, cause.CauseRequestID = fx.ID(t), fx.ID(t), fx.ID(t), fx.ID(t)
	cause.RequestedBy = f.Execution.Actor
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Stop: &f.Process}
	claim := claimControl(t, f, effect)
	return f, s, claim, ended
}

func normalRelease(t *testing.T, f *fx.Fixture, s *Server, stop api.EffectLease) api.Effect {
	t.Helper()
	ctx := context.Background()
	outcome, err := s.runEffect(ctx, f.Execution, stop)
	if err != nil {
		t.Fatal("real stopped run could not queue release", err)
	}
	// A lost stop-completion reply must reuse the exact stage and end.
	stamp, err := time.Parse(time.RFC3339Nano, string(outcome.Observation.ObservedAt))
	if err != nil {
		t.Fatal(err)
	}
	s.runtime.Launcher.(*endedRunLauncher).observation.ObservedAt = api.Timestamp(stamp.Add(time.Nanosecond).UTC().Format(time.RFC3339Nano))
	again, err := s.runEffect(ctx, f.Execution, stop)
	if err != nil || again.Observation == nil || again.Observation.Handle != outcome.Observation.Handle {
		t.Fatal("current stop attempt did not replay its pinned end", err)
	}
	outcome = again
	if _, err := f.State.CompleteEffect(ctx, f.Execution, outcome); err != nil {
		t.Fatal(err)
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil || len(effects) != 1 || effects[0].HelperRelease == nil {
		t.Fatal("normal ended run has no single durable release", err)
	}
	return effects[0]
}

func runReceipt(t *testing.T, effect api.Effect) api.ReleaseReceipt {
	t.Helper()
	zero := uint64(0)
	observation := effect.HelperRelease.Observation
	observation.ObservedAt = api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	return api.ReleaseReceipt{ID: fx.ID(t), LeaseID: effect.HelperRelease.LeaseID, ContainmentID: observation.Handle.ContainmentID,
		Backend: "linux-bwrap-landlock", OperationID: effect.OperationID, EffectID: effect.ID, Quiescence: observation,
		LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: observation.ObservedAt}
}

func TestRunReleaseReclaimedReceipt(t *testing.T) {
	clock := &planReconcileClock{}
	f, s, stop, _ := stoppedRun(t, clock)
	effect := normalRelease(t, f, s, stop)
	ctx := context.Background()
	helper := &measuredRunHelper{drainHelperFixture: runDrainHelper(t, f, *effect.HelperRelease), receipt: runReceipt(t, effect)}
	s.runtime.Helper = helper
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
		ClaimantID: f.Execution.Actor.ID, Deadline: api.Timestamp(clock.Now().Add(time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"claim", "generation", "effect", "actor"} {
		bad, scope := claim, f.Execution
		switch mode {
		case "claim":
			bad.ClaimID = fx.ID(t)
		case "generation":
			bad.Record.Generation++
		case "effect":
			bad.Record.Effect.OperationID = fx.ID(t)
		case "actor":
			scope.Actor.ID = fx.ID(t)
		}
		if _, err := s.runEffect(ctx, scope, bad); err == nil || len(helper.requests) != 0 {
			t.Fatal("release executed a stale or foreign attempt", mode, err)
		} else {
			codeIs(t, err, api.CodeConflict)
		}
	}
	first, err := s.runEffect(ctx, f.Execution, claim)
	if err != nil || first.Release == nil {
		t.Fatal("first release did not obtain its measured receipt", err)
	}
	// Lose only the service completion, then expire and reclaim the actual row.
	clock.advance(2 * time.Second)
	if _, err := s.runEffect(ctx, f.Execution, claim); err == nil || len(helper.requests) != 1 {
		t.Fatal("expired release claim retained execution rights", err)
	}
	scope := f.Execution
	scope.Actor.ID = fx.ID(t)
	second, err := f.State.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: claim.Record.Generation,
		ClaimantID: scope.Actor.ID, Deadline: api.Timestamp(clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := s.runEffect(ctx, scope, second)
	firstRequest, secondRequest := *effect.HelperRelease, *effect.HelperRelease
	firstRequest.Cause.Actor, secondRequest.Cause.Actor = f.Execution.Actor, scope.Actor
	if err != nil || outcome.Release == nil || !reflect.DeepEqual(*outcome.Release, helper.receipt) || len(helper.requests) != 2 ||
		!reflect.DeepEqual(helper.requests[0], firstRequest) || !reflect.DeepEqual(helper.requests[1], secondRequest) {
		t.Fatal("reclaimed release did not reconcile the same measured helper receipt", err)
	}
	for _, mode := range []string{"target", "generation", "containment", "exit", "jobs", "time", "operation", "lease"} {
		bad := *outcome.Release
		switch mode {
		case "target":
			bad.Quiescence.Handle.Target.Run++
		case "generation":
			bad.Quiescence.Handle.Generation += "-foreign"
		case "containment":
			bad.ContainmentID, bad.Quiescence.Handle.ContainmentID = fx.ID(t), fx.ID(t)
		case "exit":
			code := 7
			bad.Quiescence.ExitCode = &code
		case "jobs":
			bad.QueuedJobs = nil
		case "time":
			bad.ObservedAt = fx.Expiry()
		case "operation":
			bad.OperationID = fx.ID(t)
		case "lease":
			bad.LeaseID = fx.ID(t)
		}
		changed := outcome
		changed.Release = &bad
		if _, err := f.State.CompleteEffect(ctx, scope, changed); err == nil {
			t.Fatal("release accepted an unrelated or unmeasured receipt", mode)
		}
	}
	if _, err := f.State.CompleteEffect(ctx, scope, first); err == nil {
		t.Fatal("old release completion replaced the reclaimed attempt")
	} else {
		codeIs(t, err, api.CodeConflict)
	}
	foreign := scope
	foreign.Actor.ID = fx.ID(t)
	if _, err := f.State.CompleteEffect(ctx, foreign, outcome); err == nil {
		t.Fatal("foreign claimant committed the release receipt")
	} else {
		codeIs(t, err, api.CodeForbidden)
	}
	if _, err := f.State.CompleteEffect(ctx, scope, outcome); err != nil {
		t.Fatal("reclaimed measured release did not commit", err)
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal("release journal did not verify on reopen", err)
	}
	retained, err := f.State.Effect(ctx, scope, effect.ID)
	if err != nil || retained.Outcome == nil || !reflect.DeepEqual(*retained.Outcome, outcome) || !reflect.DeepEqual(retained.Effect, effect) {
		t.Fatal("restart lost the exact release pin or receipt", err)
	}
}

func TestRunReleasePrerequisites(t *testing.T) {
	for _, mode := range []string{"drain_pending", "missing_helper"} {
		t.Run(mode, func(t *testing.T) {
			clock := &planReconcileClock{}
			f, s, stop, _ := stoppedRun(t, clock)
			effect := normalRelease(t, f, s, stop)
			helper := &measuredRunHelper{drainHelperFixture: runDrainHelper(t, f, *effect.HelperRelease), receipt: runReceipt(t, effect), failure: serviceError(api.CodeContainmentUnknown, "component capture drain is pending")}
			if mode == "drain_pending" {
				s.runtime.Helper = helper
			}
			if result := s.reconcileEffect(context.Background(), effect, make(effectRetries)); result != attemptNext || s.fault != nil {
				t.Fatal("release prerequisite stopped unrelated reconciliation", s.fault)
			}
			current, err := f.State.Effect(context.Background(), f.Execution, effect.ID)
			if err != nil || !reflect.DeepEqual(current.Effect, effect) {
				t.Fatal("refusal changed the original release stage", err)
			}
			if mode == "missing_helper" {
				if current.State != api.EffectFailed || current.Outcome == nil || current.Outcome.Release != nil || current.Outcome.Error == nil || current.Outcome.Error.Code != api.CodePrerequisite {
					t.Fatal("missing helper did not retain its typed refusal")
				}
				return
			}
			if current.State != api.EffectClaimed || current.Outcome != nil || len(helper.requests) != 1 {
				t.Fatal("pending drain became a fabricated release completion")
			}
			firstRequest := *effect.HelperRelease
			firstRequest.Cause.Actor = api.Actor{Kind: "service", ID: current.ClaimantID}
			clock.advance(31 * time.Second)
			helper.failure = nil
			if result := s.reconcileEffect(context.Background(), effect, make(effectRetries)); result != attemptNext || s.fault != nil {
				t.Fatal("release did not continue after actual prerequisite recovery", s.fault)
			}
			current, err = f.State.Effect(context.Background(), f.Execution, effect.ID)
			secondRequest := *effect.HelperRelease
			secondRequest.Cause.Actor = api.Actor{Kind: "service", ID: current.ClaimantID}
			if err != nil || current.State != api.EffectCompleted || current.Outcome == nil || current.Outcome.Release == nil || len(helper.requests) != 2 ||
				!reflect.DeepEqual(helper.requests[0], firstRequest) || !reflect.DeepEqual(helper.requests[1], secondRequest) {
				t.Fatal("recovered drain did not complete the same release stage", err)
			}
		})
	}
}

func checkReleasedRun(t *testing.T, f *fx.Fixture, s *Server, measured api.ProcessObservation, requester api.Actor) {
	t.Helper()
	ctx := context.Background()
	launcher := &endedRunLauncher{observation: measured}
	launcher.observation.ObservedAt = api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: &authFixture{}, Clock: f.Deps.Clock, Dispatch: s, Launcher: launcher})
	if err != nil {
		t.Fatal(err)
	}
	scope := f.LaneScope(t)
	scope.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: scope.Config, Method: "lane.check",
		RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, f.Reservation.Target)}
	scope.Request.RequestSHA256, err = api.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	raw := fx.JSON(t, scope.Request)
	scope.Frame = &fx.Frame{Raw: raw}
	receipt, won, err := f.State.ReserveMutation(ctx, api.RequestReservation{Scope: scope, RawRequest: raw, Deadline: fx.Expiry()})
	if err != nil || !won {
		t.Fatal("natural check did not obtain its real reservation", err)
	}
	// A correct reply cannot launder a caller's changed observation event.
	changed := measured
	wrongExit := 7
	changed.ExitCode = &wrongExit
	forged := f.Event(t, "run.observed", changed)
	forged.OperationID, forged.RequestID, forged.RequestedBy = receipt.Operation.ID, scope.Request.RequestID, scope.Actor
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: scope, RawRequest: raw, Events: []api.Event{forged}, Reply: &api.RPCReply{Result: fx.JSON(t, measured)}}); err == nil {
		t.Fatal("check accepted an invented observation beside a valid retained reply")
	}
	handler := func(ctx context.Context, scope api.Scope, _ json.RawMessage) (json.RawMessage, error) {
		observed, err := coordinator.LaneCheck(ctx, scope, f.Reservation.Target)
		if err != nil {
			return nil, err
		}
		return fx.JSON(t, observed), nil
	}
	for i := 0; i < 2; i++ {
		if _, err := s.invokeOwnedMutation(ctx, scope, receipt, handler); err != nil {
			t.Fatal("real natural end/check replay failed", err)
		}
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil || len(effects) != 1 || effects[0].HelperRelease == nil || !reflect.DeepEqual(effects[0].HelperRelease.Observation, measured) || effects[0].Context.RequestedBy != requester {
		t.Fatal("natural end did not atomically retain its measured release", err)
	}
	lane, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil || lane.State != "verifying" || lane.Containment != "quiescent" {
		t.Fatal("natural release preceded its actual run end", err)
	}
}

func TestNaturalRunReleaseStage(t *testing.T) {
	t.Run("natural", func(t *testing.T) {
		f := fx.Ready(t, true)
		f.Opened(t)
		s := launchServer(t, f)
		measured := f.Observation(t, "exited")
		if err := f.State.RecordLaunchObservation(context.Background(), f.Reservation.LaunchID, measured); err != nil {
			t.Fatal(err)
		}
		checkReleasedRun(t, f, s, measured.Observation, f.Binding.Record.Actor)
	})
	t.Run("stop_reply_lost", func(t *testing.T) {
		f, s, stop, _ := stoppedRun(t)
		effect := normalRelease(t, f, s, stop)
		checkReleasedRun(t, f, s, effect.HelperRelease.Observation, effect.Context.RequestedBy)
	})
}

func TestRunReleaseAfterDecision(t *testing.T) {
	f, s, stop, _ := stoppedRun(t)
	effect := normalRelease(t, f, s, stop)
	ctx := context.Background()
	lane, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil {
		t.Fatal(err)
	}
	next := lane
	next.State, next.Generation, next.CancellationEpoch = "abandoned", lane.Generation+1, lane.CancellationEpoch+1
	cause := *effect.Context
	cause.ID, cause.Kind, cause.CauseOperationID, cause.CauseRequestID, cause.EffectID = fx.ID(t), api.InternalLifecycleEffect, fx.ID(t), fx.ID(t), fx.ID(t)
	cause.Actor = f.Execution.Actor
	event := f.Event(t, "lane.state", api.StateEvent{From: lane.State, To: next.State, Generation: next.Generation})
	event.OperationID, event.RequestID, event.RequestedBy = cause.CauseOperationID, cause.CauseRequestID, cause.RequestedBy
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Lanes: []api.Lane{next}}, Events: []api.Event{event},
		Compare: []api.Compare{{Kind: api.CompareLane, ID: lane.LifeID, Generation: lane.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: lane.CancellationEpoch}}}}); err != nil {
		t.Fatal("terminal decision did not commit through the real writer", err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal("terminal decision stranded the ended run release", err)
	}
	// Exercise the same current-claim/cancellation transaction the actual
	// administrator client performs before calling its native release owner.
	fence := *effect.Context
	fence.Actor, fence.ID = f.Execution.Actor, fx.ID(t)
	if _, err := f.State.Transact(api.WithEffectLease(ctx, claim), api.Transaction{Scope: f.Execution, Internal: &fence,
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: fence.CancellationEpoch}}}}); err != nil {
		t.Fatal("ended run release lost its authenticated helper fence", err)
	}
	foreign := fence
	foreign.ID = fx.ID(t)
	foreign.Target.Run++
	if _, err := f.State.Transact(api.WithEffectLease(ctx, claim), api.Transaction{Scope: f.Execution, Internal: &foreign,
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: foreign.CancellationEpoch}}}}); err == nil {
		t.Fatal("terminal release recovery accepted a foreign run")
	} else {
		codeIs(t, err, api.CodeForbidden)
	}
	s.runtime.Helper = &measuredRunHelper{drainHelperFixture: runDrainHelper(t, f, *effect.HelperRelease), receipt: runReceipt(t, effect)}
	outcome, err := s.runEffect(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal("terminal release did not retain its original request", err)
	}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, outcome); err != nil {
		t.Fatal("terminal release could not commit its measured receipt", err)
	}
}

func TestNormalRunReleaseStage(t *testing.T) {
	f, s, stop, ended := stoppedRun(t)
	ctx := context.Background()
	outcome, err := s.runEffect(ctx, f.Execution, stop)
	if err != nil {
		t.Fatal("normal stop could not retain its end and release stage", err)
	}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, outcome); err != nil {
		t.Fatal("stop completion failed", err)
	}
	pending, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil || len(pending) != 1 || pending[0].HelperRelease == nil {
		t.Fatal("normal stopped run has no durable HelperRelease stage", err)
	}
	effect := pending[0]
	request := *effect.HelperRelease
	if request.LeaseID != f.Plan.Lease.ID || request.Observation.Handle != f.Process || !reflect.DeepEqual(request.Observation, ended) ||
		request.Cause.Kind != api.InternalHelperRelease || request.Cause.RequestedBy != stop.Record.Effect.Context.RequestedBy ||
		request.Cause.CauseOperationID != stop.Record.Effect.OperationID || request.Cause != *effect.Context {
		t.Fatal("release lost the original run, lease or stop cause")
	}
	// Replaying the same current stop attempt cannot create another release.
	if _, err := s.runEffect(ctx, f.Execution, stop); err == nil {
		t.Fatal("completed stop replay retained live execution authority")
	}
	zero := uint64(0)
	measured := ended
	measured.ObservedAt = api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	helper := &measuredRunHelper{drainHelperFixture: runDrainHelper(t, f, request), receipt: api.ReleaseReceipt{ID: fx.ID(t), LeaseID: request.LeaseID, ContainmentID: f.Process.ContainmentID,
		Backend: f.Plan.Inputs.Sources.Runtime.Backend, OperationID: effect.OperationID, EffectID: effect.ID, Quiescence: measured,
		LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: measured.ObservedAt}}
	s.runtime.Helper = helper
	if result := s.reconcileEffect(ctx, effect, make(effectRetries)); result != attemptNext {
		t.Fatal("real reconciler did not complete the measured release")
	}
	retained, err := f.State.Effect(ctx, f.Execution, effect.ID)
	if err != nil || retained.State != api.EffectCompleted || retained.Outcome == nil || retained.Outcome.Release == nil || !reflect.DeepEqual(*retained.Outcome.Release, helper.receipt) || len(helper.requests) != 1 {
		t.Fatal("release did not retain its actual measured receipt", err)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: f.Process.Target.LifeID, Run: f.Process.Target.Run})
	if err != nil {
		t.Fatal(err)
	}
	releases, ends := 0, 0
	for _, event := range page.Events {
		if event.Kind == "lane.ended" {
			ends++
		}
		if event.Kind == "helper.released" {
			var receipt api.ReleaseReceipt
			if api.DecodeObject(event.Payload, &receipt) != nil || !reflect.DeepEqual(receipt, helper.receipt) || event.OperationID != effect.OperationID || event.RequestedBy != request.Cause.RequestedBy {
				t.Fatal("release event replaced the helper measurement or requester")
			}
			releases++
		}
	}
	if releases != 1 || ends != 1 {
		t.Fatal("normal run did not commit exactly one measured end and release")
	}
	if commit, err := f.State.CompleteEffect(ctx, api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: retained.ClaimantID}}, *retained.Outcome); err != nil || !commit.Replayed {
		t.Fatal("exact measured completion did not replay", err)
	}
}
