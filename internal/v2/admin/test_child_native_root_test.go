//go:build linux && laneboss_root_canary

package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
	peerlinux "laneboss.io/laneboss/internal/v2/peer/linux"
	"laneboss.io/laneboss/internal/v2/service"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/testjob"
)

type nativeTestPort interface {
	nativeReviewPort
	StageChildTest(context.Context, api.Scope, api.TestChildRequest, api.GrantSet, api.ReviewSubject) (testjob.Reservation, error)
}

// This test-only measured executable checks actual file bytes; it is enrolled
// as the native kit's real runtime artifact and never used by production.
func init() {
	if len(os.Args) != 4 || os.Args[1] != "test-child-measure" {
		return
	}
	raw, err := os.ReadFile(os.Args[2])
	if err != nil || string(fx.Digest(raw)) != os.Args[3] {
		os.Exit(41)
	}
	if _, err := os.Stdout.Write(raw); err != nil {
		os.Exit(42)
	}
	os.Exit(0)
}

func TestNativeChildStoreClient(t *testing.T) {
	if _, ok := any(new(store.Service)).(nativeTestPort); !ok {
		t.Fatal("installed writer lacks real native review execution and result producers")
	}
	if os.Args[len(os.Args)-1] != "test-store-client" {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestNativeChildLaunch$", "-test.v")
		command.Env = []string{}
		output, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: TestNativeChildLaunch ")) {
			t.Fatalf("real native review kit failed: %v\n%s", err, output)
		}
		return
	}
	if os.Geteuid() == 0 {
		t.Fatal("native archive store must use its actual unprivileged service UID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	input := os.NewFile(3, "archive-native-metadata")
	defer input.Close()
	var meta archiveNativeMetadata
	if err := json.NewDecoder(input).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if uint32(os.Geteuid()) != meta.Binding.ServiceUID || fx.Digest(meta.RuntimeBytes) != meta.Runtime.SHA256 || int64(len(meta.RuntimeBytes)) != meta.Runtime.Bytes {
		t.Fatal("native store kit changed its installed identity/runtime")
	}
	directory := filepath.Join(meta.Directory, "state")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	deps := store.Dependencies{Config: meta.Binding.Config, Directory: directory, Clock: fx.Clock{}}
	state, err := store.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	f := fx.NewIn(t, state, deps)
	t.Cleanup(func() {
		if err := f.State.Close(); err != nil {
			t.Error(err)
		}
	})
	f.Start.Budget = meta.Budget
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	runtimeIntent := f.Intent(t, api.InternalLaunchPlan)
	if _, err := f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: runtimeIntent, Object: api.ObjectWrite{ObjectKey: meta.Runtime.ID, Class: meta.Runtime.Class, Bytes: meta.RuntimeBytes, SHA256: meta.Runtime.SHA256, Origin: "service", ACL: api.ObjectACL{Config: deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}}); err != nil {
		t.Fatal(err)
	}
	sourced := f.SourceTransaction(t)
	sourced.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Manifest = meta.Runtime
	sourced.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Executable = meta.Executable
	if _, err := f.State.Transact(ctx, sourced); err != nil {
		t.Fatal(err)
	}
	f.Record = sourced.Writes.LaunchPlans[0]
	f.BuildPlanForIdentity(t, true, meta.Parent.UID, meta.Parent.GID)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	for i, stream := range f.Plan.Capture.Streams {
		q := f.AppendRequest(t, nil, true)
		q.StreamID = stream.ID
		q.ExpectedGeneration = api.Generation(i + 1)
		if _, err := f.State.AppendCapture(ctx, f.Worker, q); err != nil {
			t.Fatal(err)
		}
	}
	f.Ended(t)
	ready, ack := os.NewFile(4, "archive-native-ready"), os.NewFile(5, "archive-native-ack")
	defer ready.Close()
	defer ack.Close()
	if err := json.NewEncoder(ready).Encode(f.Lane); err != nil {
		t.Fatal(err)
	}
	var signal [1]byte
	if _, err := io.ReadFull(ack, signal[:]); err != nil || signal[0] != 1 {
		t.Fatal("native archive roots were not enrolled", err)
	}

	helperDeps := admin.Dependencies{Config: deps.Config, Store: f.State, ServiceUID: meta.Binding.ServiceUID, ArtifactSHA256: meta.Binding.ArtifactSHA256, Version: meta.Binding.ServiceVersion, Protocol: api.Protocol, Schema: api.SchemaVersion, RuntimeManifest: meta.Runtime}
	helper, err := admin.New(helperDeps)
	if err != nil {
		t.Fatal(err)
	}
	reviewHelper, ok := any(helper).(nativeReviewHelper)
	if !ok {
		t.Fatal("administrator lacks native review helper producers")
	}
	noReplacement := &reviewNativeNoReplacement{}
	source := any(f.State).(nativeTestPort)
	if err := source.BindReviewRuntime(helper, noReplacement); err != nil {
		t.Fatal(err)
	}
	subject, err := source.ReviewSnapshot(ctx, f.Execution, f.Reservation.Target)
	if err != nil {
		t.Fatal("actual native post-run review freeze failed", err)
	}
	chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: subject.Snapshot.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var tree api.ObjectManifest
	if api.DecodeObject(chunk.Data, &tree) != nil {
		t.Fatal("native TestChild freeze is malformed")
	}
	var content api.BlobRef
	for _, entry := range tree.Entries {
		if entry.Kind == "file" && strings.HasPrefix(entry.Path, "work/") && entry.Content != nil {
			content = *entry.Content
			break
		}
	}
	if content.ID == "" {
		t.Fatal("native TestChild has no actual frozen candidate file")
	}
	original, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: content.ID, Limit: api.MaxChunkBytes})
	if err != nil || fx.Digest(original.Data) != content.SHA256 {
		t.Fatal("native TestChild source changed", err)
	}
	candidate := nativeReviewRetain(t, f, "manifest", fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "candidate.txt", Kind: "file", Mode: 0600, Content: &content}}}))
	grants, err := f.State.Grants(ctx, f.Lane.GrantSetID)
	if err != nil {
		t.Fatal(err)
	}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", Input: candidate, GrantSetID: grants.ID, Budget: meta.Budget, Executable: meta.Executable,
		Argv: []string{"native-test", "test-child-measure", "candidate.txt", string(content.SHA256)}}
	request := api.TestChildRequest{Child: subject.Target, Candidate: candidate, TestPlan: nativeReviewRetain(t, f, "manifest", fx.JSON(t, plan)), Budget: plan.Budget}
	caller := f.LaneScope(t)
	caller.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: "grants.test-child", RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, request)}
	caller.Request.RequestSHA256, err = api.RequestDigest(caller.Request)
	if err != nil {
		t.Fatal(err)
	}
	caller.Frame = &fx.Frame{Raw: fx.JSON(t, caller.Request)}
	owner, retire := f.State.TrackMutation(ctx)
	defer retire()
	pending, won, err := f.State.ReserveMutation(owner, api.RequestReservation{Scope: caller, RawRequest: caller.Frame.Bytes(), Deadline: fx.Expiry()})
	if err != nil || !won {
		t.Fatal("native TestChild dispatcher reservation failed", err)
	}
	staged, err := source.StageChildTest(owner, caller, request, grants, subject)
	if err != nil {
		t.Fatal("native TestChild staging failed", err)
	}
	if _, err := f.State.Transact(owner, api.Transaction{Scope: caller, RawRequest: caller.Frame.Bytes(), Compare: staged.Compare, Writes: api.StateWrites{WorkerLeases: []api.WorkerLease{staged.Job.Lease}},
		Effects: []api.Effect{staged.Effect}, Reply: &api.RPCReply{Result: fx.JSON(t, api.Operation{ID: pending.Operation.ID, Status: "pending"})}}); err != nil {
		t.Fatal("native TestChild admission failed", err)
	}
	job, lease := staged.Job, staged.Job.Lease
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: lease.EffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.BeginReviewAllocation(ctx, f.Execution, claim); err != nil {
		t.Fatal(err)
	}
	allocation, err := reviewHelper.ReviewWorkerLease(ctx, job, claim)
	if err != nil {
		t.Fatal("actual native review allocation failed", err)
	}
	if err := source.RecordReviewAllocation(ctx, f.Execution, claim, allocation); err != nil {
		t.Fatal(err)
	}
	workerID, err := source.ReviewWorkerID(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := meta.Binding
	endpoint.Class, endpoint.Socket, endpoint.LaunchID, endpoint.Target, endpoint.WorkerLeaseID = api.EndpointWorker, "/runtime/laneboss-worker.sock", workerID, &lease.Target, lease.ID
	endpoint.EndpointGeneration = allocation.EndpointGeneration
	handoff, err := source.ReviewHandoff(ctx, f.Execution, claim, allocation, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	peers, err := peerlinux.New(helper)
	if err != nil {
		t.Fatal(err)
	}
	defer peers.Close()
	auth, err := identity.New(identity.Dependencies{Peers: peers, Registry: helper, Store: f.State, Clock: deps.Clock, Workers: helper})
	if err != nil {
		t.Fatal(err)
	}
	authWait, releaseAuth := context.WithCancel(ctx)
	defer releaseAuth()
	probe, err := service.OpenArchiveProbe(ctx, service.Dependencies{Store: f.State, Clock: deps.Clock, Binding: meta.Binding, Authenticator: archiveAuthHold{auth, authWait.Done()}}, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := probe.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := reviewHelper.RegisterReviewWorker(ctx, job, claim, handoff, endpoint); err != nil {
		t.Fatal("actual review sealed registration failed", err)
	}
	prepared, err := reviewHelper.PrepareReviewWorker(ctx, job, claim)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := source.BindReviewWorker(ctx, f.Execution, claim, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(ready).Encode(f.Lane); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ack, signal[:]); err != nil || signal[0] != 1 {
		t.Fatal("native review prepared witness failed", err)
	}
	if err := ready.Close(); err != nil {
		t.Fatal(err)
	}
	var process api.ProcessHandle
	err = helper.WithWorkerLaunch(ctx, prepared, func(held context.Context) error {
		permit, err := auth.BindLaunch(held, binding)
		if err != nil {
			return err
		}
		cause := *claim.Record.Effect.Context
		cause.Kind, cause.Actor = api.InternalHelperOpen, f.Execution.Actor
		process, err = reviewHelper.OpenReviewWorker(held, job, claim, api.HelperOpenRequest{Cause: cause, Prepared: prepared, Permit: permit, OperationID: lease.OperationID, EffectID: lease.EffectID})
		return err
	})
	if err != nil {
		t.Fatal("real identity could not open its original native review verifier", err)
	}
	if err := source.RecordReviewProcess(ctx, f.Execution, claim, process); err != nil {
		t.Fatal(err)
	}
	observed, err := reviewHelper.ObserveReviewWorker(ctx, job, claim)
	if err != nil || observed.State != "running" || observed.Handle != process {
		t.Fatal("real review worker was not observed running", err)
	}
	releaseAuth()
	waitCtx, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		observed, err = reviewHelper.ObserveReviewWorker(waitCtx, job, claim)
		if err != nil {
			t.Fatal(err)
		}
		if observed.State == "exited" {
			break
		}
		if observed.State != "running" {
			t.Fatal("real review native state is unknown")
		}
		select {
		case <-waitCtx.Done():
			t.Fatal("real verifier did not finish")
		case <-ticker.C:
		}
	}
	if observed.Handle != process || observed.ExitCode == nil || *observed.ExitCode != 0 || observed.Signal != nil || observed.Survivors == nil || *observed.Survivors != 0 {
		t.Fatal("real review verifier lacks a measured successful known-zero exit")
	}
	retainedAck, err := source.ReviewAcknowledgement(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal("real verifier did not retain authenticated output", err)
	}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: lease.EffectID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded", Output: &retainedAck.Result, Observation: &observed}); err == nil {
		t.Fatal("native result without retirement prematurely completed")
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	proof, err := reviewHelper.RetireReviewWorker(ctx, job, claim)
	if err != nil {
		t.Fatal("actual review worker retirement failed", err)
	}
	if err := source.RecordReviewRetirement(ctx, f.Execution, claim, proof); err != nil {
		t.Fatal(err)
	}
	if proof.Release == nil {
		t.Fatal("actual verifier retirement lost its terminal wait")
	}
	observed = proof.Release.Quiescence
	if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: lease.EffectID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded", Output: &retainedAck.Result, Observation: &observed}); err != nil {
		t.Fatal(err)
	}
	output, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: retainedAck.Result.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var result testjob.Result
	if api.DecodeObject(output.Data, &result) != nil || result.Check.ExitCode != 0 || result.Check.WorkerLeaseID != lease.ID ||
		result.Check.SnapshotSHA256 != subject.Snapshot.SHA256 || !bytes.Equal(result.Stdout, original.Data) {
		t.Fatal("native TestChild lost actual candidate bytes, command exit or frozen worker identity")
	}
	operation, err := f.State.Operation(ctx, caller, job.Intent.OperationID)
	if err != nil || operation.Status != "succeeded" || operation.Run != lease.Target.Run {
		t.Fatal("native TestChild did not complete its original operation", err)
	}
	verified, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verified.OK {
		t.Fatal("native TestChild broke durable verification", err, verified.Problems)
	}
	t.Logf("native TestChild: stdout_sha256=%s result_sha256=%s exit=%d survivors=%d", fx.Digest(result.Stdout), retainedAck.Result.SHA256, *observed.ExitCode, *observed.Survivors)
}
