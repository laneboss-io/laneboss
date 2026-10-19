//go:build linux && laneboss_root_canary && laneboss_gate_integration

package service

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// This tagged driver is called by the administrator's root canary in its
// unprivileged child. Only the private test transport replaces installed IPC;
// the writer, lifecycle, reconciler, stage authorization and native helper run
// their production code. No account, model service or host installer is used.
func ExerciseNaturalReleaseCanary(t *testing.T, exchange func(string, any, any) error) {
	exerciseNaturalReleaseCanary(t, exchange, false)
}

func ExerciseStoppedCaptureCanary(t *testing.T, exchange func(string, any, any) error) {
	exerciseNaturalReleaseCanary(t, exchange, true)
}

func exerciseNaturalReleaseCanary(t *testing.T, exchange func(string, any, any) error, monitorStop bool, sealDelegation ...bool) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("natural release writer must remain unprivileged")
	}
	ctx := context.Background()
	var identity struct {
		UID    uint32
		Config string
	}
	if err := exchange("identity", api.Empty{}, &identity); err != nil {
		t.Fatal(err)
	}
	f := fx.New(t, identity.Config)
	f.Reserve(t)
	f.Source(t)
	f.CaptureSetup = func(binding api.CaptureBinding) api.CaptureBinding {
		var actual api.CaptureBinding
		if err := exchange("capture", binding, &actual); err != nil {
			t.Fatal("native capture setup failed", err)
		}
		return actual
	}
	f.BuildPlanForIdentity(t, true, identity.UID, identity.UID)
	f.Spec(t)
	f.PrepareJob(t)
	policy, err := f.State.Policy(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	input := struct {
		Plan       api.LaunchPlan
		Handoff    api.PreparedSpecHandoff
		Prepared   api.PreparedLaunch
		Request    api.HelperLaunchRequest
		Allocation api.HelperLeaseRequest
		Worker     api.WorkerLease
		Policy     api.EffectivePolicy
	}{f.Plan, *f.Record.Handoff, f.Prepared, *f.PreparedClaim.Record.Effect.HelperPrepare, f.Allocation, f.WorkerLease, policy}
	if err := exchange("prepare", input, &f.Prepared); err != nil {
		t.Fatal("native gate preparation failed", err)
	}
	f.Bind(t)
	var opened api.LaunchReconciliation
	if err := exchange("open", f.Binding, &opened); err != nil {
		t.Fatal("native gate did not open", err)
	}
	f.Opened(t, opened)
	if monitorStop {
		exerciseStoppedCaptureMonitor(t, f, exchange)
		return
	}
	var delegated *fx.Fixture
	if len(sealDelegation) != 0 && sealDelegation[0] {
		delegated = sealedCanaryChild(t, f)
	}
	var ended api.LaunchReconciliation
	if err := exchange("end", api.Empty{}, &ended); err != nil {
		t.Fatal("actual lane did not end naturally", err)
	}
	if ended.Observation.ExitCode == nil || *ended.Observation.ExitCode != 0 || ended.Observation.Signal != nil {
		t.Fatal("natural canary did not measure its real successful exit")
	}
	if err := f.State.RecordLaunchObservation(ctx, f.Reservation.LaunchID, ended); err != nil {
		t.Fatal(err)
	}
	h := &nativeReleaseTransport{fixture: f, exchange: exchange}
	observer := &nativeReleaseObserver{transport: h}
	auth := &canaryCheckAuthority{fixture: f}
	host := &Server{options: Options{Config: f.Deps.Config}, deps: Dependencies{Store: f.State, Clock: f.Deps.Clock}, controller: fx.ID(t)}
	host.runtime = api.RuntimeServices{Store: f.State, Helper: h, Launcher: observer}
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: auth, Clock: f.Deps.Clock, Dispatch: host, Launcher: observer})
	if err != nil {
		t.Fatal(err)
	}
	host.runtime.Lifecycle = coordinator
	scope := f.LaneScope(t)
	scope.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: scope.Config, Method: "lane.check", RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, f.Reservation.Target)}
	scope.Request.RequestSHA256, err = api.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	raw := fx.JSON(t, scope.Request)
	scope.Frame = &fx.Frame{Raw: raw}
	reservation, won, err := f.State.ReserveMutation(ctx, api.RequestReservation{Scope: scope, RawRequest: raw, Deadline: fx.Expiry()})
	if err != nil || !won {
		t.Fatal("natural end reservation failed", err)
	}
	_, err = host.invokeOwnedMutation(ctx, scope, reservation, func(ctx context.Context, scope api.Scope, _ json.RawMessage) (json.RawMessage, error) {
		value, err := coordinator.LaneCheck(ctx, scope, f.Reservation.Target)
		if err != nil {
			return nil, err
		}
		return json.Marshal(value)
	})
	if err != nil {
		t.Fatal("real natural end did not commit", err)
	}
	if delegated != nil {
		if seal, err := f.State.VerifyDelegationLease(ctx, f.Execution, f.Lane.LifeID, delegated.Lane.GrantSetID); err != nil || seal == "" {
			t.Fatal("native parent end did not preserve its sealed prior child scope", err)
		}
	}
	pending, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil || len(pending) != 1 || pending[0].HelperRelease == nil {
		t.Fatal("natural end did not retain exactly one HelperRelease", err)
	}
	effect := pending[0]
	var ready bool
	// Open native pipes must defer this same effect, including when a prior
	// child delegation needs its sealed authority preserved across recovery.
	if result := host.reconcileEffect(ctx, effect, make(effectRetries)); result != attemptNext || host.fault != nil {
		t.Fatal("native drain refusal halted reconciliation", host.fault)
	}
	current, err := f.State.Effect(ctx, f.Execution, effect.ID)
	if err != nil || current.State != api.EffectClaimed || current.Outcome != nil || !reflect.DeepEqual(current.Effect, effect) {
		t.Fatal("native drain refusal was not retryable", err)
	}
	f.Claim = api.EffectLease{Record: current, ClaimID: current.ClaimID, ExpiresAt: current.ClaimExpiresAt}
	if err := exchange("unblock", api.Empty{}, &ready); err != nil || !ready {
		t.Fatal("native capture did not finish after closing its actual writers", err)
	}
	f.ExpireClaim(t)
	host.deps.Store, host.runtime.Store = f.State, f.State
	// ExpireClaim reopens the writer. Rebuild its dependent coordinator just
	// as service construction does; an old writer cannot authorize collection.
	coordinator, err = lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: auth, Clock: f.Deps.Clock, Dispatch: host, Launcher: observer})
	if err != nil {
		t.Fatal("release coordinator rebind failed", err)
	}
	host.runtime.Lifecycle = coordinator
	midClaim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: current.Generation, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal("mid-drain claim failed", err)
	}
	if err := host.DrainReleaseCaptures(api.WithEffectLease(ctx, midClaim), *effect.HelperRelease); err != nil {
		t.Fatal("mid-drain capture drain failed", err)
	}
	claimScope := api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: midClaim.Record.ClaimantID}, Source: "service"}
	drainReceipt, err := f.State.CaptureDrainReceipt(ctx, claimScope, midClaim, f.Plan.Capture.ID)
	if err != nil || drainReceipt.EffectID != effect.ID {
		t.Fatal("mid-drain capture receipt missing from store", err)
	}
	f.ExpireClaim(t)
	host.deps.Store, host.runtime.Store = f.State, f.State
	coordinator, err = lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: auth, Clock: f.Deps.Clock, Dispatch: host, Launcher: observer})
	if err != nil {
		t.Fatal("mid-drain restart coordinator rebind failed", err)
	}
	host.runtime.Lifecycle = coordinator
	if result := host.reconcileEffect(ctx, effect, make(effectRetries)); result != attemptNext || host.fault != nil {
		t.Fatal("reclaimed mid-drain release failed", host.fault)
	}
	current, err = f.State.Effect(ctx, f.Execution, effect.ID)
	if err != nil || current.State != api.EffectCompleted || current.Outcome == nil || current.Outcome.Release == nil {
		t.Fatal("natural native release did not commit its measured receipt", err)
	}
	receipt := *current.Outcome.Release
	if err := api.ValidateReleaseReceipt(receipt); err != nil || receipt.LeaseID != f.Plan.Lease.ID || receipt.EffectID != effect.ID || receipt.OperationID != effect.OperationID || receipt.Quiescence.Handle != f.Process || receipt.Quiescence.ExitCode == nil || *receipt.Quiescence.ExitCode != 0 {
		t.Fatal("native release receipt lost its measured run or zero resource counts", err)
	}
	claimScope = api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: current.ClaimantID}, Source: "service"}
	commit, err := f.State.CompleteEffect(ctx, claimScope, *current.Outcome)
	if err != nil || !commit.Replayed {
		t.Fatal("exact release completion did not replay", err)
	}
	if err := exchange("verify", receipt, &ready); err != nil || !ready {
		t.Fatal("native teardown or exact helper replay failed", err)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: f.Process.Target.LifeID, Run: f.Process.Target.Run})
	if err != nil || !page.Complete {
		t.Fatal("natural canary event history is incomplete", err)
	}
	counts := map[api.EventKind]int{}
	var endSeq, drainSeq, releaseSeq api.Sequence
	for _, event := range page.Events {
		counts[event.Kind]++
		switch event.Kind {
		case "lane.ended":
			endSeq = event.Seq
		case "capture.closed":
			drainSeq = event.Seq
		case "capture.appended":
			var captured api.CaptureRecord
			if err := api.DecodeObject(event.Payload, &captured); err != nil || captured.Data.Bytes <= 0 {
				t.Fatal("real lane output was not retained", err)
			}
		case "helper.released":
			releaseSeq = event.Seq
			var saved api.ReleaseReceipt
			if err := api.DecodeObject(event.Payload, &saved); err != nil || !reflect.DeepEqual(saved, receipt) {
				t.Fatal("release event changed the native measured receipt", err)
			}
		}
	}
	if counts["lane.ended"] != 1 || counts["helper.released"] != 1 || counts["capture.closed"] != len(f.Plan.Capture.Streams) || counts["capture.appended"] != 1 || !(endSeq < drainSeq && drainSeq < releaseSeq) {
		t.Fatal("natural end, exact capture drain and measured release ordering differs", counts)
	}
	verified, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verified.OK {
		t.Fatal("natural end/drain/release journal did not verify", err)
	}
	if delegated != nil {
		seal, err := f.State.VerifyDelegationLease(ctx, f.Execution, f.Lane.LifeID, delegated.Lane.GrantSetID)
		if err != nil || seal == "" {
			t.Fatal("native parent end did not preserve its sealed prior child scope", err)
		}
		if _, err := f.State.VerifyDelegationLease(ctx, f.Execution, f.Lane.LifeID, f.Lane.GrantSetID); err == nil {
			t.Fatal("native parent lease widened to the parent's own grant set")
		}
	}
}

func exerciseStoppedCaptureMonitor(t *testing.T, f *fx.Fixture, exchange func(string, any, any) error) {
	t.Helper()
	ctx := context.Background()
	cause := f.Intent(t, api.InternalLifecycleEffect)
	cause.ID, cause.EffectID, cause.CauseOperationID, cause.CauseRequestID = fx.ID(t), fx.ID(t), fx.ID(t), fx.ID(t)
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Stop: &f.Process}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal(err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	stop := cause
	stop.Kind = api.InternalHelperStop
	if _, err := admin.CheckLaunchStageAuthority(api.WithEffectLease(ctx, claim), f.State, f.Deps.Config, stop, api.InternalHelperStop); err != nil {
		t.Fatal("stop lost its real retained claim", err)
	}
	request := api.HelperStopRequest{Cause: stop, Target: api.HelperObserveRequest{LeaseID: f.Plan.Lease.ID, Handle: f.Process}, OperationID: effect.OperationID, EffectID: effect.ID, Reason: "capture monitor transition"}
	var ended api.ProcessObservation
	if err := exchange("capture-stop-fence", request, &ended); err != nil || ended.State != "exited" {
		t.Fatal("real stop did not retain its credential revocation fence", err)
	}
	h := &nativeReleaseTransport{fixture: f, exchange: exchange}
	host := &Server{options: Options{Config: f.Deps.Config}, deps: Dependencies{Store: f.State, Clock: f.Deps.Clock}, controller: fx.ID(t), verified: true, bound: true}
	host.runtime = api.RuntimeServices{Store: f.State, Helper: h}
	for _, phase := range []string{"before_eof", "after_eof"} {
		if phase == "after_eof" {
			var ready bool
			if err := exchange("unblock", api.Empty{}, &ready); err != nil || !ready {
				t.Fatal("capture producer did not finish actual EOF", err)
			}
		}
		if err := host.reconcileLaunches(ctx, host.runtime); err != nil {
			t.Fatal("capture monitor rejected the correlated revoked lease before release pinned EOF", phase, err)
		}
	}
	var valid bool
	if err := exchange("capture-monitor-controls", api.Empty{}, &valid); err != nil || !valid {
		t.Fatal("read-only capture transition lost its native refusal controls", err)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: f.Process.Target.LifeID, Run: f.Process.Target.Run})
	if err != nil || !page.Complete {
		t.Fatal(err)
	}
	for _, event := range page.Events {
		if event.Kind == "capture.gap" || event.Kind == "helper.released" || event.Kind == "capture.closed" {
			t.Fatal("read-only monitor fabricated a failure, acknowledgement or release", event.Kind)
		}
	}
}

type canaryCheckAuthority struct {
	api.Authenticator
	fixture *fx.Fixture
}

func (a *canaryCheckAuthority) Authorize(ctx context.Context, scope api.Scope, request api.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var target api.LifeRef
	if request.Method != "lane.check" || request.Config != a.fixture.Deps.Config || scope.Actor != a.fixture.Binding.Record.Actor || api.DecodeObject(request.Params, &target) != nil || target != a.fixture.Reservation.Target {
		return serviceError(api.CodeForbidden, "canary public check changed its retained author or run")
	}
	return nil
}

type nativeReleaseTransport struct {
	api.HelperControl
	fixture  *fx.Fixture
	exchange func(string, any, any) error
}

type nativeReleaseObserver struct {
	api.Launcher
	transport *nativeReleaseTransport
}

func (h *nativeReleaseTransport) ReconcileCapture(ctx context.Context, binding api.CaptureBinding) (api.CaptureBinding, error) {
	var value api.CaptureBinding
	if err := ctx.Err(); err != nil {
		return value, err
	}
	err := h.exchange("reconcile_capture", binding, &value)
	return value, err
}

func (h *nativeReleaseTransport) ReconcileGate(ctx context.Context, request api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	var value api.LaunchReconciliation
	if err := ctx.Err(); err != nil {
		return value, err
	}
	err := h.exchange("reconcile_gate", request, &value)
	return value, err
}

func (o *nativeReleaseObserver) Observe(ctx context.Context, handle api.ProcessHandle) (api.ProcessObservation, error) {
	return o.transport.Observe(ctx, handle)
}

type canaryDrainQuery struct {
	Release  api.HelperReleaseRequest  `json:"release"`
	Claim    api.EffectLease           `json:"claim"`
	Snapshot *api.CaptureDrainSnapshot `json:"snapshot,omitempty"`
	Receipt  *api.CaptureDrainReceipt  `json:"receipt,omitempty"`
	StreamID api.ID                    `json:"stream_id,omitempty"`
	Offset   int64                     `json:"offset"`
}

func (h *nativeReleaseTransport) query(ctx context.Context, release api.HelperReleaseRequest) (canaryDrainQuery, error) {
	if _, err := admin.CheckLaunchStageAuthority(ctx, h.fixture.State, h.fixture.Deps.Config, release.Cause, api.InternalHelperRelease); err != nil {
		return canaryDrainQuery{}, err
	}
	claim, ok := api.EffectLeaseFromContext(ctx)
	if !ok || claim.Record.Effect.HelperRelease == nil || !reflect.DeepEqual(*claim.Record.Effect.HelperRelease, release) {
		return canaryDrainQuery{}, serviceError(api.CodeForbidden, "native canary lost its exact release claim")
	}
	return canaryDrainQuery{Release: release, Claim: claim}, nil
}

func (h *nativeReleaseTransport) Observe(ctx context.Context, handle api.ProcessHandle) (api.ProcessObservation, error) {
	var value api.ProcessObservation
	if err := ctx.Err(); err != nil {
		return value, err
	}
	err := h.exchange("observe", api.HelperObserveRequest{LeaseID: h.fixture.Plan.Lease.ID, Handle: handle}, &value)
	return value, err
}

func (h *nativeReleaseTransport) CaptureDrains(ctx context.Context, release api.HelperReleaseRequest) ([]api.CaptureDrainSnapshot, error) {
	q, err := h.query(ctx, release)
	if err != nil {
		return nil, err
	}
	var value []api.CaptureDrainSnapshot
	err = h.exchange("capture_drain_snapshot", q, &value)
	return value, err
}

func (h *nativeReleaseTransport) ReadCaptureDrain(ctx context.Context, release api.HelperReleaseRequest, pin api.CaptureDrainSnapshot, stream api.ID, offset int64) (api.BlobChunk, error) {
	q, err := h.query(ctx, release)
	if err != nil {
		return api.BlobChunk{}, err
	}
	q.Snapshot, q.StreamID, q.Offset = &pin, stream, offset
	var value api.BlobChunk
	err = h.exchange("capture_drain_read", q, &value)
	return value, err
}

func (h *nativeReleaseTransport) AcknowledgeCaptureDrain(ctx context.Context, release api.HelperReleaseRequest, pin api.CaptureDrainSnapshot, receipt api.CaptureDrainReceipt) error {
	q, err := h.query(ctx, release)
	if err != nil {
		return err
	}
	scope := api.Scope{Config: h.fixture.Deps.Config, Actor: api.Actor{Kind: "service", ID: q.Claim.Record.ClaimantID}, Source: "service"}
	actual, err := h.fixture.State.CaptureDrainReceipt(ctx, scope, q.Claim, pin.Binding.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, receipt) || api.ValidateCaptureDrainReceipt(pin, receipt) != nil {
		return serviceError(api.CodeIntegrity, "native canary acknowledgement is not the actual store receipt")
	}
	q.Snapshot, q.Receipt = &pin, &receipt
	var discharged bool
	if err := h.exchange("capture_drain_ack", q, &discharged); err != nil {
		return err
	}
	if !discharged {
		return serviceError(api.CodeContainmentUnknown, "native capture discharge was not acknowledged")
	}
	return nil
}

func (h *nativeReleaseTransport) Release(ctx context.Context, release api.HelperReleaseRequest) (api.ReleaseReceipt, error) {
	if _, err := h.query(ctx, release); err != nil {
		return api.ReleaseReceipt{}, err
	}
	var value api.ReleaseReceipt
	err := h.exchange("release", release, &value)
	return value, err
}
