//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Native metadata and resource counts are explicit component inputs. The
// reservation, natural end, terminal stop, decision, outbox claim and
// credential fence/completion are the real SQLite writer and reconciler.
type releaseProjectionSource struct {
	store.CredentialProjectionSource
	request api.CredentialProjectionRequest
	owner   api.Actor
	meta    api.CredentialProjectionAuthority
}

func (n *releaseProjectionSource) ResolveCredentialProjection(ctx context.Context, scope api.Scope, request api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	if err := ctx.Err(); err != nil {
		return api.CredentialProjectionAuthority{}, err
	}
	if scope.Actor != n.owner || !reflect.DeepEqual(request, n.request) {
		return api.CredentialProjectionAuthority{}, serviceError(api.CodeForbidden, "component native projection selector changed")
	}
	return n.meta, nil
}

func releaseProjection(t *testing.T, f *fx.Fixture) api.CredentialProjectionRecord {
	t.Helper()
	r := api.CredentialProjectionRequest{Cause: *f.PreparedClaim.Record.Effect.Context, Claim: f.PreparedClaim,
		Handoff: *f.Record.Handoff, Prepared: f.Prepared, Lease: f.Plan.Lease, Home: f.Plan.Data.Home}
	boot := string(fx.ID(t))
	n := &releaseProjectionSource{request: r, owner: f.Execution.Actor, meta: api.CredentialProjectionAuthority{
		Helper:     api.Executable{ID: fx.ID(t), SHA256: fx.Digest([]byte("component-helper")), Version: "component"},
		Broker:     api.Executable{ID: fx.ID(t), SHA256: fx.Digest([]byte("component-broker")), Version: "component"},
		HelperPeer: api.PeerFacts{HostPID: os.Getpid() + 1, ProcessGeneration: boot + ":helper"},
		BrokerPeer: api.PeerFacts{HostUID: uint32(os.Geteuid()) + 3000, HostGID: uint32(os.Getegid()) + 3000, HostPID: os.Getpid(),
			ProcessGeneration: boot + ":broker", ContainmentID: fx.ID(t)},
		ServiceUID: uint32(os.Geteuid()) + 2000, InstallationGeneration: 1, BootID: boot}}
	targets, err := api.CredentialTargets(r, f.Deps.Clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		version := target.Version
		if target.SlotID != "" {
			version = "component-version"
		}
		n.meta.Sources = append(n.meta.Sources, api.CredentialSourceVersion{Key: target.Key, Generation: 1, Version: version})
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.Deps.CredentialProjection = n
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := f.State.ReserveCredentialProjection(context.Background(), f.Execution, r)
	if err != nil {
		t.Fatal("cannot reserve original native projection", err)
	}
	return projection
}

func releaseMutation(t *testing.T, f *fx.Fixture, method api.Method, body any) (context.Context, api.Scope, api.Operation) {
	t.Helper()
	scope := f.Human
	scope.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: method,
		RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, body)}
	var err error
	scope.Request.RequestSHA256, err = api.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame = &fx.Frame{Raw: fx.JSON(t, scope.Request)}
	ctx, retire := f.State.TrackMutation(context.Background())
	t.Cleanup(retire)
	r, won, err := f.State.ReserveMutation(ctx, api.RequestReservation{Scope: scope, RawRequest: scope.Frame.Bytes(), Deadline: fx.Expiry()})
	if err != nil || !won {
		t.Fatal("cannot reserve actual release lifecycle request", err)
	}
	return ctx, scope, r.Operation
}

type credentialReleaseHelper struct {
	*drainHelperFixture
	f          *fx.Fixture
	t          *testing.T
	projection api.CredentialProjectionRecord
	receipt    api.ReleaseReceipt
	completed  bool
}

func (h *credentialReleaseHelper) Release(ctx context.Context, request api.HelperReleaseRequest) (api.ReleaseReceipt, error) {
	claim, ok := api.EffectLeaseFromContext(ctx)
	if !ok || h.ack == nil {
		return api.ReleaseReceipt{}, serviceError(api.CodeForbidden, "component release lost its drained current claim")
	}
	want := *claim.Record.Effect.Context
	want.Actor = api.Actor{Kind: "service", ID: claim.Record.ClaimantID}
	logCauseDifferences := func(label string, got api.InternalIntent) {
		wantFields, gotFields := reflect.ValueOf(want), reflect.ValueOf(got)
		var differences []string
		for i := 0; i < wantFields.NumField(); i++ {
			differences = append(differences, fmt.Sprintf("%s=%t", wantFields.Type().Field(i).Name,
				!reflect.DeepEqual(wantFields.Field(i).Interface(), gotFields.Field(i).Interface())))
		}
		h.t.Logf("credential release %s cause differences: %v", label, differences)
	}
	logCauseDifferences("request", request.Cause)
	for _, field := range []string{"kind", "id", "actor", "target", "operation"} {
		changed := want
		switch field {
		case "kind":
			changed.Kind = api.InternalHelperAbort
		case "id":
			changed.ID = fx.ID(h.t)
		case "actor":
			changed.Actor.ID = fx.ID(h.t)
		case "target":
			changed.Target.Run++
		case "operation":
			changed.CauseOperationID = fx.ID(h.t)
		}
		result, err := h.f.State.FenceCredentialProjection(ctx, h.f.Execution, api.CredentialWithdrawalRequest{
			ProjectionID: h.projection.Authority.ID, ExpectedGeneration: h.projection.Generation, Cause: changed, Reason: "release"})
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || result.Authority.ID != "" {
			return api.ReleaseReceipt{}, serviceError(api.CodeIntegrity, "credential release accepted changed "+field)
		}
	}
	fenced, err := h.f.State.FenceCredentialProjection(ctx, h.f.Execution, api.CredentialWithdrawalRequest{
		ProjectionID: h.projection.Authority.ID, ExpectedGeneration: h.projection.Generation, Cause: request.Cause, Reason: "release"})
	if err != nil {
		return api.ReleaseReceipt{}, err
	}
	h.t.Logf("credential release fence missing: %t", fenced.Fence == nil)
	if fenced.Fence != nil {
		logCauseDifferences("fence", fenced.Fence.Cause)
	}
	if want != request.Cause || fenced.Fence == nil || fenced.Fence.Cause != want {
		return api.ReleaseReceipt{}, serviceError(api.CodeIntegrity, "credential release did not retain its exact current claimant cause")
	}
	zero, executed := uint64(0), true
	r := fenced.Authority.Request
	withdrawal := api.CredentialWithdrawalReceipt{ProjectionID: fenced.Authority.ID, Generation: fenced.Generation + 1,
		Cause: request.Cause, Prepared: r.Prepared, HelperLeaseID: r.Lease.ID, Home: r.Home,
		ObservedAt: request.Observation.ObservedAt, Observation: request.Observation, AgentExecuted: &executed,
		HelperDescriptors: &zero, ProjectedFiles: &zero, EnvironmentBuffers: &zero, OpenGates: &zero, BrokerDescriptors: &zero, RefreshLeases: &zero}
	done, err := h.f.State.CompleteCredentialWithdrawal(ctx, h.f.Execution, withdrawal)
	if err != nil {
		return api.ReleaseReceipt{}, err
	}
	h.completed = done.State == "withdrawn" && done.Withdrawal != nil
	return h.receipt, nil
}

type credentialReleaseArchive struct {
	archivejob.Native
	release func() error
}

func (n *credentialReleaseArchive) FreezeArchive(context.Context, archivejob.Intent, api.Lane) (archivejob.Snapshot, error) {
	if err := n.release(); err != nil {
		return archivejob.Snapshot{}, err
	}
	return archivejob.Snapshot{}, serviceError(api.CodePrerequisite, "component stops after measuring credential release")
}

func TestCredentialReleaseClaimant(t *testing.T) {
	credentialReleaseClaimant(t, false)
}

func TestArchiveFixtureReceiptProgress(t *testing.T) {
	credentialReleaseClaimant(t, true)
}

func credentialReleaseClaimant(t *testing.T, fixtureTree bool) {
	t.Helper()
	f := fx.Ready(t, true)
	var projection api.CredentialProjectionRecord
	f.Child(t, func(f *fx.Fixture) { projection = releaseProjection(t, f) })
	f.Opened(t)
	observed := f.Observation(t, "exited")
	exit := 1
	observed.Observation.ExitCode = &exit
	if err := f.State.RecordLaunchObservation(context.Background(), f.Reservation.LaunchID, observed); err != nil {
		t.Fatal(err)
	}
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: &authFixture{}, Clock: f.Deps.Clock,
		Launcher: &endedRunLauncher{observation: observed.Observation}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, scope, _ := releaseMutation(t, f, "lane.check", f.Reservation.Target)
	if _, err := coordinator.LaneCheck(ctx, scope, f.Reservation.Target); err != nil {
		t.Fatal("actual natural end could not queue its release", err)
	}
	lane, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil || lane.State != "verifying" {
		t.Fatal("natural end lost its verifying life", err)
	}
	stop := api.StopRequest{Target: f.Reservation.Target, ExpectedGeneration: lane.Generation, Reason: lane.Task}
	ctx, scope, _ = releaseMutation(t, f, "lane.stop", stop)
	stopped, err := coordinator.LaneStop(ctx, scope, stop)
	if err != nil || stopped.Stop == nil || stopped.Stop.End.Reason != "exit" || stopped.Stop.End.Observation.ExitCode == nil || *stopped.Stop.End.Observation.ExitCode != exit {
		t.Fatal("actual r18 terminal stop did not retain the ended result", err)
	}
	mark := api.MarkRequest{Target: f.Reservation.Target, ExpectedGeneration: lane.Generation, State: "abandoned",
		Review: api.ReviewReceipt{Checks: []api.BlobRef{}, RefusalResolution: []api.ID{}}}
	ctx, scope, _ = releaseMutation(t, f, "lane.mark", mark)
	if _, err := coordinator.LaneMark(ctx, scope, mark); err != nil {
		t.Fatal("actual ended life could not be abandoned", err)
	}
	lane, err = f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil || len(pending) != 1 || pending[0].HelperRelease == nil {
		t.Fatal("natural end lost its single original release", err)
	}
	effect := pending[0]
	executor := f.Execution
	executor.Actor.ID = fx.ID(t)
	claim, err := f.State.ClaimEffect(ctx, executor, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
		ClaimantID: executor.Actor.ID, Deadline: api.Timestamp(f.Deps.Clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	helper := &credentialReleaseHelper{drainHelperFixture: runDrainHelper(t, f, *effect.HelperRelease), f: f, t: t,
		projection: projection, receipt: runReceipt(t, effect)}
	host := launchServer(t, f)
	host.runtime.Helper = helper
	native := &credentialReleaseArchive{release: func() error {
		outcome, err := host.runEffect(context.Background(), executor, claim)
		if err != nil {
			return err
		}
		if !helper.completed || outcome.Release == nil {
			return serviceError(api.CodeIntegrity, "archive skipped credential withdrawal or native release")
		}
		_, err = f.State.CompleteEffect(context.Background(), executor, outcome)
		return err
	}}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.Deps.ArchiveNative = native
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	host.deps.Store = f.State
	request := api.ArchiveRequest{Target: f.Reservation.Target, ExpectedGeneration: lane.Generation}
	ctx, scope, operation := releaseMutation(t, f, "lane.archive", request)
	_, err = f.State.ReserveArchive(ctx, scope, archivejob.Intent{OperationID: operation.ID, Request: request,
		CancellationEpoch: lane.CancellationEpoch, EndEventID: stopped.Stop.EndEventID, EndSeq: stopped.Stop.EndSequence})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || typed.Message != "component stops after measuring credential release" || !helper.completed {
		t.Fatal("archive HelperRelease did not pass its real credential fence", err)
	}
	retained, err := f.State.Effect(context.Background(), executor, effect.ID)
	if err != nil || retained.Outcome == nil || retained.Outcome.Release == nil || !reflect.DeepEqual(retained.Effect, effect) {
		t.Fatal("release changed its immutable original outbox cause", err)
	}
	if verified, err := f.State.Verify(context.Background(), api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
		t.Fatal("credential release journal did not verify", err)
	}
	f.Lane = lane
	var extra []api.ObjectWrite
	if fixtureTree {
		for i := range 32 {
			data := []byte(fmt.Sprintf("fixture file %d retained bytes\n", i))
			extra = append(extra, api.ObjectWrite{ObjectKey: api.ID(fmt.Sprintf("file-%02d", i)), Class: "artifact", Bytes: data, SHA256: fx.Digest(data)})
		}
	}
	collect := f.CleanupReleased(t, func(ctx context.Context, scope api.Scope, principal api.WorkerPrincipal) (api.WorkerResultReceipt, error) {
		if fixtureTree {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, 600*time.Millisecond)
			defer cancel()
		}
		reads, started := 0, time.Now()
		result, err := dataworker.RunArchive(ctx, dataworker.ArchiveJob{Principal: principal, Scope: scope, Bootstrap: f.State,
			Read: func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
				reads++
				if fixtureTree {
					timer := time.NewTimer(5 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-ctx.Done():
						return api.BlobChunk{}, ctx.Err()
					case <-timer.C:
					}
				}
				return f.State.WorkerObject(ctx, scope, request)
			}, Sink: f.State, Clock: f.Deps.Clock})
		if fixtureTree {
			t.Logf("same-life fixture archive: files=%d remote_reads=%d elapsed_ms=%d receipt=%t err=%v", len(extra)+1, reads, time.Since(started).Milliseconds(), result.Result.ID != "", err)
		}
		return result, err
	}, extra...)
	receipt := collect()
	if !f.Lane.Cleaned || receipt.Workspace.After.WorktreeState != "absent" || len(receipt.Objects) == 0 {
		t.Fatal("same ended life did not complete archive read-back and clean")
	}
	if verified, err := f.State.Verify(context.Background(), api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
		t.Fatal("same-life archive and cleanup journal did not verify", err)
	}
	t.Log("terminal stop and abandonment: actual credential fence, original HelperRelease, archive read-back and same-life clean passed")
}
