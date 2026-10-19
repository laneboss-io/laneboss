//go:build linux

package admin_test

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	servicehost "laneboss.io/laneboss/internal/v2/service"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Identity and native process facts are explicit component inputs. Every
// request reservation, stop transition, end, release cause and archive epoch
// comes from the production lifecycle and SQLite writer, including reopen.
type codexEpochIdentity struct {
	api.Authenticator
	actor api.Actor
}

func (i *codexEpochIdentity) Authorize(ctx context.Context, scope api.Scope, request api.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	digest, err := api.RequestDigest(request)
	if err != nil || scope.Actor != i.actor || request.Config != scope.Config || digest != request.RequestSHA256 {
		return &api.Error{Code: api.CodeForbidden, Message: "component request differs from its retained controller"}
	}
	return nil
}

type codexEpochNative struct {
	api.Launcher
	archivejob.Native
	state       *store.Service
	observation api.ProcessObservation
	probe       *admin.StopArchiveEpochProbe
	intent      archivejob.Intent
	fence       *archivejob.EpochFence
	stops       int
	causes      []api.InternalIntent
	stopFailure error
	freezeError error
}

type codexEpochClock struct{ advance atomic.Int64 }

func (c *codexEpochClock) Now() time.Time { return time.Now().Add(time.Duration(c.advance.Load())) }

func (n *codexEpochNative) Stop(ctx context.Context, handle api.ProcessHandle, reason string) (api.ProcessObservation, error) {
	if err := ctx.Err(); err != nil {
		return api.ProcessObservation{}, err
	}
	if handle != n.observation.Handle || reason == "" {
		return api.ProcessObservation{}, &api.Error{Code: api.CodeConflict, Message: "component stop changed the original process or reason"}
	}
	cause, claim, err := n.state.LaunchControlIntent(ctx, api.InternalHelperStop, handle.ID)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if claim.Effect.Stop == nil || *claim.Effect.Stop != handle {
		return api.ProcessObservation{}, &api.Error{Code: api.CodeConflict, Message: "component stop lost its original writer claim"}
	}
	n.causes = append(n.causes, cause)
	if err := n.probe.Stop(cause); err != nil {
		return api.ProcessObservation{}, err
	}
	n.stops++
	return n.observation, n.stopFailure
}

func (n *codexEpochNative) Observe(ctx context.Context, handle api.ProcessHandle) (api.ProcessObservation, error) {
	if err := ctx.Err(); err != nil {
		return api.ProcessObservation{}, err
	}
	if handle != n.observation.Handle {
		return api.ProcessObservation{}, &api.Error{Code: api.CodeContainmentUnknown, Message: "component observed another process"}
	}
	return n.observation, nil
}

func (n *codexEpochNative) FreezeArchive(ctx context.Context, intent archivejob.Intent, lane api.Lane) (archivejob.Snapshot, error) {
	n.intent = intent
	var err error
	n.fence, err = n.probe.Probe(ctx, n.state, intent, lane)
	n.freezeError = err
	if err != nil {
		return archivejob.Snapshot{}, err
	}
	// This regression measures the real writer-to-native epoch boundary. It
	// deliberately stops before privileged filesystem freeze or worker launch.
	return archivejob.Snapshot{}, &api.Error{Code: api.CodePrerequisite, Message: "component reached filesystem freeze after the exact native epoch check"}
}

func codexEpochRequest(t *testing.T, f *fx.Fixture, method api.Method, params any) (context.Context, api.Scope) {
	t.Helper()
	scope := f.Human // The retained parent lane, never a forged human proof.
	scope.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: scope.Config, Method: method,
		RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, params)}
	var err error
	scope.Request.RequestSHA256, err = api.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame = &fx.Frame{Raw: fx.JSON(t, scope.Request)}
	ctx, retire := f.State.TrackMutation(context.Background())
	t.Cleanup(retire)
	if _, won, err := f.State.ReserveMutation(ctx, api.RequestReservation{Scope: scope, RawRequest: scope.Frame.Bytes(), Deadline: fx.Expiry()}); err != nil || !won {
		t.Fatal("cannot reserve actual controller request", method, err)
	}
	return ctx, scope
}

func TestCodexStopArchiveEpoch(t *testing.T) {
	for _, mode := range []string{"exited-before-stop", "reclaimed-stop", "observe-owned-end"} {
		t.Run(mode, func(t *testing.T) { codexStopArchiveEpoch(t, mode) })
	}
}

func codexStopArchiveEpoch(t *testing.T, mode string) {
	f := fx.ControlledChild(t)
	f.Process = admin.StopArchiveLaunchHandle(f.Binding)
	f.Opened(t)
	if f.Plan.Runner.Driver != api.DriverCodex {
		t.Fatal("regression requires an actual Codex launch plan")
	}
	measured := f.Observation(t, "exited")
	exit := 1 // Codex has exited before the installed Stop effect observes it.
	measured.Observation.ExitCode = &exit
	if err := f.State.RecordLaunchObservation(context.Background(), f.Reservation.LaunchID, measured); err != nil {
		t.Fatal("cannot retain the independent terminal process observation", err)
	}
	native := &codexEpochNative{observation: measured.Observation}
	clock := &codexEpochClock{}
	f.Deps.Clock = clock
	f.Deps.ArchiveNative = native
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	native.state = f.State
	service, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: &codexEpochIdentity{actor: f.Human.Actor}, Launcher: native, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	before, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil || before.State != "running" {
		t.Fatal("missing original running Codex life", err)
	}
	reasonBytes := []byte("stop the retained Codex process\n")
	reason, err := f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: f.Intent(t, api.InternalObjectRetain),
		Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: "task", Bytes: reasonBytes, SHA256: fx.Digest(reasonBytes), Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Human.Actor, LifeID: before.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	stop := api.StopRequest{Target: f.Reservation.Target, ExpectedGeneration: before.Generation, Reason: reason}
	stopCtx, caller := codexEpochRequest(t, f, "lane.stop", stop)
	operation, err := service.LaneStop(stopCtx, caller, stop)
	if err != nil || operation.Status != "pending" {
		t.Fatal("actual Codex stop did not commit its original intent", err)
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var stopping api.Effect
	for _, effect := range effects {
		if effect.OperationID == operation.ID && effect.Stop != nil {
			stopping = effect
		}
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: stopping.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID,
		Deadline: api.Timestamp(clock.Now().Add(5 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal("cannot claim the actual installed stop effect", err)
	}
	native.probe = admin.NewStopArchiveEpochProbe(f.Reservation)
	expectedStops := 1
	if mode == "reclaimed-stop" {
		native.stopFailure = errors.New("component kill/wait failed after native fence")
		if _, err := servicehost.ReconcileStoppedGate(ctx, native, service, f.Execution, claim); !errors.Is(err, native.stopFailure) {
			t.Fatal("first attempt did not retain its actual incomplete stop", err)
		}
		clock.advance.Store(int64(10 * time.Second))
		first := claim
		f.Execution.Actor = api.Actor{Kind: "service", ID: fx.ID(t)}
		claim, err = f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: stopping.ID, ExpectedGeneration: first.Record.Generation,
			ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
		if err != nil || claim.ClaimID == first.ClaimID {
			t.Fatal("real writer did not reclaim the expired stop under a new claim", err)
		}
		native.stopFailure = nil
		expectedStops = 2
	}
	if mode == "observe-owned-end" {
		if _, err := native.Stop(api.WithEffectLease(ctx, claim), *claim.Record.Effect.Stop, "committed stop intent"); err != nil {
			t.Fatal("native stop did not retain the original writer cause", err)
		}
		checkCtx, caller := codexEpochRequest(t, f, "lane.check", f.Reservation.Target)
		if _, err := service.LaneCheck(checkCtx, caller, f.Reservation.Target); err != nil {
			t.Fatal("concurrent check lost the actual exited gate", err)
		}
		pending, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
		if err != nil || pending.State != "verifying" || pending.CancellationEpoch != before.CancellationEpoch+1 {
			t.Fatal("observe path did not retain its actual stopped end", err)
		}
		expectedStops = 2
	}
	if _, err := servicehost.ReconcileStoppedGate(ctx, native, service, f.Execution, claim); err != nil {
		t.Fatal("installed stop reconciler did not commit its measured end", err)
	}
	effects, err = f.State.PendingEffects(ctx, api.CursorRequest{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var release *api.HelperReleaseRequest
	for _, effect := range effects {
		if effect.HelperRelease != nil && effect.HelperRelease.Observation.Handle == native.observation.Handle {
			release = effect.HelperRelease
		}
	}
	if release == nil {
		t.Fatal("actual stop did not commit its original native release")
	}
	if mode == "observe-owned-end" && release.Cause.CauseOperationID == operation.ID {
		t.Fatal("observe-owned release incorrectly reused the stop operation")
	}
	if err := native.probe.Release(f.Binding, *release); err != nil {
		t.Fatal("native component lost the committed release cause or observation", err)
	}
	ended, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil || ended.State != "verifying" || ended.CancellationEpoch != before.CancellationEpoch+1 {
		t.Fatal("stop did not retain its exact committed cancellation epoch", err)
	}
	mark := api.MarkRequest{Target: f.Reservation.Target, ExpectedGeneration: ended.Generation, State: "abandoned",
		Review: api.ReviewReceipt{Checks: []api.BlobRef{}, RefusalResolution: []api.ID{}}}
	markCtx, caller := codexEpochRequest(t, f, "lane.mark", mark)
	if _, err := service.LaneMark(markCtx, caller, mark); err != nil {
		t.Fatal("actual controller could not abandon the stopped run", err)
	}
	abandoned, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil || abandoned.CancellationEpoch != ended.CancellationEpoch+1 {
		t.Fatal("terminal decision did not advance the writer epoch", err)
	}
	request := api.ArchiveRequest{Target: f.Reservation.Target, ExpectedGeneration: abandoned.Generation}
	archiveCtx, caller := codexEpochRequest(t, f, "lane.archive", request)
	_, err = service.LaneArchive(archiveCtx, caller, request)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || typed.Message != "component reached filesystem freeze after the exact native epoch check" {
		t.Fatalf("Codex stop/archive failed at the writer/native boundary: launch_epoch=%d stop_epoch=%d archive_epoch=%d: %v; handoff=%v", before.CancellationEpoch, ended.CancellationEpoch, abandoned.CancellationEpoch, err, native.freezeError)
	}
	if native.fence == nil || native.fence.Intent != native.intent || native.fence.LaunchEpoch != before.CancellationEpoch ||
		!reflect.DeepEqual(native.fence.End.Observation, native.observation) {
		t.Fatal("archive did not hand over its real committed Codex epoch and end")
	}
	changed := native.intent
	changed.CancellationEpoch++
	if err := native.probe.Check(native.fence, changed); err == nil {
		t.Fatal("native comparison accepted an epoch different from its exact writer handoff")
	}
	if err := native.probe.WithoutNativeStop(native.fence, native.intent); err == nil {
		t.Fatal("archive accepted a writer handoff without the native stop fence")
	}
	if native.fence.Stop == nil || native.fence.Stop.Release.CancellationEpoch != ended.CancellationEpoch {
		t.Fatal("archive lost the actual writer-committed stop epoch")
	}
	if mode == "observe-owned-end" && native.fence.Stop.End.OperationID == native.fence.Stop.Event.OperationID {
		t.Fatal("observe-owned end was not bound independently of the stop operation")
	}
	if native.stops != expectedStops {
		t.Fatal("installed reconciler lost a stop attempt or repeated the original end")
	}
	if mode == "reclaimed-stop" && (len(native.causes) != 2 || native.causes[0].ID == native.causes[1].ID || native.causes[0].Actor == native.causes[1].Actor) {
		t.Fatal("reclaimed stop did not exercise distinct real per-claim causes")
	}
	if first, ok := native.probe.FirstStop(); !ok || !reflect.DeepEqual(first, native.causes[0]) {
		t.Fatal("native fence did not keep the first real writer cause")
	}
	for _, field := range []string{"epoch", "operation", "request", "requester", "turn"} {
		if err := native.probe.MismatchStop(native.fence, native.intent, field); err == nil {
			t.Error("archive accepted a mismatched native stop", field)
		}
	}
	foreign := native.causes[len(native.causes)-1]
	foreign.EffectID = fx.ID(t)
	if err := native.probe.Stop(foreign); err == nil {
		t.Fatal("native fence accepted a different stop identity")
	}
	if err := native.probe.RevokedCheck(native.fence, native.causes[0]); err != nil {
		t.Fatal("credential archive lost the first native stop cause", err)
	}
	foreign = native.causes[0]
	foreign.CauseRequestID = fx.ID(t)
	if err := native.probe.RevokedCheck(native.fence, foreign); err == nil {
		t.Fatal("credential archive accepted a different retained stop")
	}
	for _, field := range []string{"stop-epoch", "stop-operation", "stop-sequence", "missing-stop", "end", "end-operation", "end-request", "end-id", "end-sequence"} {
		changed := *native.fence
		stop := *changed.Stop
		changed.Stop = &stop
		switch field {
		case "stop-epoch":
			changed.Stop.Release.CancellationEpoch++
		case "stop-operation":
			changed.Stop.Release.CauseOperationID = fx.ID(t)
		case "stop-sequence":
			changed.Stop.Event.Seq = changed.Intent.EndSeq
		case "missing-stop":
			changed.Stop = nil
		case "end":
			changed.End.Reason = "exit"
		case "end-operation":
			changed.Stop.End.OperationID = fx.ID(t)
		case "end-request":
			changed.Stop.End.RequestID = fx.ID(t)
		case "end-id":
			changed.Stop.End.ID = fx.ID(t)
		case "end-sequence":
			changed.Stop.End.Seq++
		}
		if err := archivejob.ValidateEpochFence(changed); err == nil {
			t.Error("archive accepted a changed committed stop proof", field)
		}
	}
	verification, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("actual Codex stop/archive journal did not verify", err)
	}
	t.Logf("real SQLite/native epoch boundary: launch=%d stop=%d archive=%d; changed epoch refused", before.CancellationEpoch, ended.CancellationEpoch, abandoned.CancellationEpoch)
}
