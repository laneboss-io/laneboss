//go:build linux && laneboss_root_canary

package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/identity"
	peerlinux "laneboss.io/laneboss/internal/v2/peer/linux"
	"laneboss.io/laneboss/internal/v2/reviewjob"
	"laneboss.io/laneboss/internal/v2/service"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type nativeReviewPort interface {
	reviewjob.Source
	BindReviewRuntime(any, any) error
	ReviewJob(context.Context, api.Scope, api.ID) (archivejob.Job, error)
	ReviewWorkerID(context.Context, api.Scope, api.EffectLease) (api.ID, error)
	ReviewHandoff(context.Context, api.Scope, api.EffectLease, api.HelperLease, api.InstalledBinding) (api.PreparedSpecHandoff, error)
	BindReviewWorker(context.Context, api.Scope, api.EffectLease, api.PreparedLaunch) (api.LaunchBindingRequest, error)
	RecordReviewProcess(context.Context, api.Scope, api.EffectLease, api.ProcessHandle) error
	BeginReviewAllocation(context.Context, api.Scope, api.EffectLease) error
	RecordReviewAllocation(context.Context, api.Scope, api.EffectLease, api.HelperLease) error
	RecordReviewRetirement(context.Context, api.Scope, api.EffectLease, archivejob.Retirement) error
	ReviewAcknowledgement(context.Context, api.Scope, api.EffectLease) (api.WorkerResultReceipt, error)
}

type nativeReviewHelper interface {
	RequiredReviewChecks(context.Context, api.Scope, api.LifeRef) ([]string, error)
	ReviewWorkerLease(context.Context, archivejob.Job, api.EffectLease) (api.HelperLease, error)
	RegisterReviewWorker(context.Context, archivejob.Job, api.EffectLease, api.PreparedSpecHandoff, api.InstalledBinding) (api.PreparedSpecReceipt, error)
	PrepareReviewWorker(context.Context, archivejob.Job, api.EffectLease) (api.PreparedLaunch, error)
	OpenReviewWorker(context.Context, archivejob.Job, api.EffectLease, api.HelperOpenRequest) (api.ProcessHandle, error)
	ObserveReviewWorker(context.Context, archivejob.Job, api.EffectLease) (api.ProcessObservation, error)
	RetireReviewWorker(context.Context, archivejob.Job, api.EffectLease) (archivejob.Retirement, error)
}

type reviewNativeNoReplacement struct{ calls int }

func (n *reviewNativeNoReplacement) ExecuteReviewWorker(ctx context.Context, scope api.Scope, job archivejob.Job) error {
	n.calls++
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("the original verifier has already executed; replacement is forbidden")
}
func nativeReviewStamp() api.Timestamp {
	return api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
}

func nativeReviewRetain(t *testing.T, f *fx.Fixture, class string, raw []byte) api.BlobRef {
	t.Helper()
	cause := f.Intent(t, api.InternalObjectRetain)
	ref, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: class, Bytes: raw, SHA256: fx.Digest(raw), Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, LifeID: f.Lane.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal("component review input retention failed", err)
	}
	return ref
}

func nativeReviewCandidateInput(t *testing.T, f *fx.Fixture, subject api.ReviewSubject) (api.ReviewRequest, api.WorkerLease) {
	t.Helper()
	ctx := context.Background()
	operation := f.Reservation.OperationID
	check := reviewjob.CheckRecord{Schema: "laneboss.check.v2", Name: "unit", Target: subject.Target, EndSeq: subject.EndSeq, SnapshotSHA256: subject.Snapshot.SHA256, ExitCode: 0, WorkerLeaseID: fx.ID(t), OperationID: operation}
	checkRef := nativeReviewRetain(t, f, "check", fx.JSON(t, check))
	input := nativeReviewRetain(t, f, "manifest", fx.JSON(t, subject))
	testLease := api.WorkerLease{ID: check.WorkerLeaseID, Kind: "test", Target: subject.Target, OperationID: operation, EffectID: fx.ID(t), Input: input, RuntimeManifest: f.Record.Handoff.Spec.RuntimeManifest, GrantSetID: f.Lane.GrantSetID, Generation: 1, ExpiresAt: fx.Expiry()}
	cause := f.Intent(t, api.InternalLifecycleEffect)
	cause.EffectID = testLease.EffectID
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", Executable: f.Plan.Runner.Executable, Argv: []string{"component-test"}, Input: input, GrantSetID: testLease.GrantSetID, Budget: f.Plan.Budget}
	effect := api.Effect{ID: testLease.EffectID, OperationID: operation, Context: &cause, Worker: &plan}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{WorkerLeases: []api.WorkerLease{testLease}}, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal("prior test job prerequisite failed", err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	worker := api.LaunchRecord{Kind: "worker", ID: fx.ID(t), Config: f.Deps.Config, Target: subject.Target, RootLifeID: f.Lane.RootLifeID, ParentLifeID: f.Lane.ParentLifeID, StarterChain: append([]api.ID{}, f.Lane.StarterChain...), StarterEventSeq: f.Lane.StarterEventSeq, Actor: api.Actor{Kind: "worker", ID: fx.ID(t)}, HostUID: uint32(os.Geteuid()), UIDLeaseID: fx.ID(t), ContainmentID: fx.ID(t), ProcessGeneration: "component-prior-test:1", GrantSetID: testLease.GrantSetID, GrantsSHA256: f.Plan.Inputs.Grants.SHA256, PolicyGeneration: 1, EndpointGeneration: 1}
	bindCause := f.Intent(t, api.InternalLifecycleEffect)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &bindCause, Events: []api.Event{f.Event(t, "identity.bound", worker)}}); err != nil {
		t.Fatal(err)
	}
	testLease.ConsumedBy = worker.ID
	f.Replace(t, "worker_lease", testLease.ID, testLease.Generation, testLease)
	zero, exit := uint64(0), 0
	observation := api.ProcessObservation{Handle: api.ProcessHandle{ID: worker.ID, Target: subject.Target, ContainmentID: worker.ContainmentID, Generation: worker.ProcessGeneration}, State: "exited", ExitCode: &exit, Survivors: &zero, ObservedAt: nativeReviewStamp(), PromptStatus: "completed"}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: effect.ID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded", Output: &checkRef, Observation: &observation}); err != nil {
		t.Fatal("prior measured test fact prerequisite failed", err)
	}
	base := f.Plan.Inputs.Sources.Project.Object
	diff := reviewjob.Diff{Schema: "laneboss.review-diff.v2", Base: base.SHA256, Current: subject.Snapshot.SHA256, Changes: []reviewjob.Change{}}
	// The fixed verifier recomputes this candidate below. The two tree entries
	// are read from the actual retained manifests, never supplied by a verdict.
	baseChunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: base.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	currentChunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: subject.Snapshot.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var before, after api.ObjectManifest
	if api.DecodeObject(baseChunk.Data, &before) != nil || api.DecodeObject(currentChunk.Data, &after) != nil {
		t.Fatal("candidate manifest prerequisite failed")
	}
	left, right, paths := map[string]api.ObjectEntry{}, map[string]api.ObjectEntry{}, map[string]bool{}
	for _, entry := range before.Entries {
		left[entry.Path] = entry
		paths[entry.Path] = true
	}
	for _, entry := range after.Entries {
		if strings.HasPrefix(entry.Path, "work/") {
			entry.Path = strings.TrimPrefix(entry.Path, "work/")
			right[entry.Path] = entry
			paths[entry.Path] = true
		}
	}
	ordered := []string{}
	for name := range paths {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		a, aok := left[name]
		b, bok := right[name]
		if aok && bok && reflect.DeepEqual(a, b) {
			continue
		}
		change := reviewjob.Change{Path: name}
		if aok {
			change.Before = &a
		}
		if bok {
			change.After = &b
		}
		diff.Changes = append(diff.Changes, change)
	}
	diffRef := nativeReviewRetain(t, f, "diff", fx.JSON(t, diff))
	streams := []api.ReviewStreamFact{}
	for _, stream := range subject.Streams {
		streams = append(streams, api.ReviewStreamFact{BindingID: subject.CaptureBindingID, StreamID: stream.ID, StartOffset: 0, EndOffset: 0, EOF: true, GapIDs: []api.ID{}})
	}
	tools := nativeReviewRetain(t, f, "manifest", fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}))
	inventory := reviewjob.InventoryRecord{Schema: "laneboss.review-inventory.v2", ThroughSeq: subject.InventorySeq, Streams: streams, ToolRecords: tools, ToolCoverage: api.CoveragePartial}
	inventoryRef := nativeReviewRetain(t, f, "manifest", fx.JSON(t, inventory))
	return api.ReviewRequest{Target: subject.Target, Diff: diffRef, Checks: []api.BlobRef{checkRef}, RecordInventory: inventoryRef, RefusalResolution: []api.ID{}}, testLease
}

func TestReviewNativeStoreClient(t *testing.T) {
	if _, ok := any(new(store.Service)).(nativeReviewPort); !ok {
		t.Fatal("installed writer lacks real native review execution and result producers")
	}
	if os.Args[len(os.Args)-1] != "review-store-client" {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestReviewLaunchNative$", "-test.v")
		command.Env = []string{}
		output, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: TestReviewLaunchNative ")) {
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
	source := any(f.State).(nativeReviewPort)
	if err := source.BindReviewRuntime(helper, noReplacement); err != nil {
		t.Fatal(err)
	}
	subject, err := source.ReviewSnapshot(ctx, f.Execution, f.Reservation.Target)
	if err != nil {
		t.Fatal("actual native post-run review freeze failed", err)
	}
	request, _ := nativeReviewCandidateInput(t, f, subject)
	// Only the prior test fact is a declared fixture. The verifier below is a
	// real separate UID/process, fixed CLI entry, sealed input and native wait.
	source = any(f.State).(nativeReviewPort)
	helperDeps.Store = f.State
	helper, err = admin.New(helperDeps)
	if err != nil {
		t.Fatal(err)
	}
	reviewHelper, ok = any(helper).(nativeReviewHelper)
	if !ok {
		t.Fatal("administrator lost its native review helper producers")
	}
	if err := source.BindReviewRuntime(helper, noReplacement); err != nil {
		t.Fatal(err)
	}
	names, err := reviewHelper.RequiredReviewChecks(ctx, f.Execution, f.Reservation.Target)
	if err != nil || !reflect.DeepEqual(names, []string{"unit"}) {
		for i, path := range []string{"/etc/laneboss-v2", "/etc/laneboss-v2/review", filepath.Join("/etc/laneboss-v2/review", meta.Binding.Config+".json")} {
			info, statErr := os.Lstat(path)
			if statErr != nil {
				t.Logf("review policy path stage=%d available=false missing=%t permission=%t", i, os.IsNotExist(statErr), os.IsPermission(statErr))
			} else {
				t.Logf("review policy path stage=%d available=true mode=%s", i, info.Mode())
			}
		}
		t.Fatal("protected requirement producer failed", err)
	}
	caller := f.Human
	caller.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: "lane.review", RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, request)}
	caller.Request.RequestSHA256, err = api.RequestDigest(caller.Request)
	if err != nil {
		t.Fatal(err)
	}
	caller.Frame = &fx.Frame{Raw: fx.JSON(t, caller.Request)}
	owner, retire := f.State.TrackMutation(ctx)
	defer retire()
	pending, won, err := f.State.ReserveMutation(owner, api.RequestReservation{Scope: caller, RawRequest: caller.Frame.Bytes(), Deadline: fx.Expiry()})
	if err != nil || !won {
		t.Fatal("native review original dispatcher reservation failed", err)
	}
	lease, err := source.ReserveReviewWorker(owner, caller, request, subject, names)
	if err != nil {
		t.Fatal(err)
	}
	job, err := source.ReviewJob(ctx, f.Execution, pending.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
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
	output, err := source.AwaitReviewResult(owner, caller, lease)
	if err != nil || output != retainedAck.Result || noReplacement.calls != 0 {
		t.Fatal("native result replay replaced or lost its original worker", err)
	}
	bytes, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: output.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var evidence api.ReviewEvidence
	if api.DecodeObject(bytes.Data, &evidence) != nil || evidence.Coverage != api.CoveragePartial || evidence.VerifierLeaseID != lease.ID {
		t.Fatal("real native verifier output lost its measured identity or partial coverage")
	}
	changed := lease
	changed.Input.SHA256 = fx.Digest([]byte("changed original input"))
	if _, err := source.AwaitReviewResult(owner, caller, changed); err == nil {
		t.Fatal("native result replay accepted changed sealed input")
	}
	if err := api.ValidateReviewAcceptance(caller, api.ReviewReceipt{ID: job.ID, Reviewer: caller.Actor, Diff: request.Diff, Checks: request.Checks, RecordInventory: request.RecordInventory, RefusalResolution: request.RefusalResolution, Coverage: evidence.Coverage, Evidence: &evidence}, subject, names); err == nil {
		t.Fatal("native verifier execution substituted for missing complete tool coverage")
	}
	t.Logf("native review verifier: output_sha256=%s bytes=%d exit=%d survivors=%d; partial coverage refused acceptance", output.SHA256, output.Bytes, *observed.ExitCode, *observed.Survivors)
}
