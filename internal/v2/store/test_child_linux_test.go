//go:build linux

package store_test

import (
	"context"
	"os"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/reviewjob"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/testjob"
)

func (n *reviewNativeInput) TestCheckNames(ctx context.Context, scope api.Scope, target api.LifeRef) ([]string, error) {
	return n.RequiredReviewChecks(ctx, scope, target)
}

type testProducerPort interface {
	reviewProducerPort
	StageChildTest(context.Context, api.Scope, api.TestChildRequest, api.GrantSet, api.ReviewSubject) (testjob.Reservation, error)
	AdmittedChildTest(context.Context, api.Scope, api.Effect) (archivejob.Job, error)
}

// Parent/helper/identity measurements are explicit fixture boundaries. The
// test worker executes the actual candidate and SQLite retains its exact
// result; no prior check or worker-result receipt is injected into the writer.
func TestNativeChildWriter(t *testing.T) {
	ctx := context.Background()
	f := fx.New(t)
	f.Reserve(t)
	executable, err := os.Open("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	bytes, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	tool := api.Executable{ID: fx.ID(t), SHA256: fx.Digest(bytes), Version: "component-shell"}
	toolRef := f.Retain(t, "artifact", bytes, f.Execution.Actor, "")
	runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: tool, Bootstrap: tool,
		Objects: []api.RuntimeObject{{ID: tool.ID, Role: "tool", RootID: "runtime", RelativePath: "tool", Content: toolRef, Mode: 0555}}, Bindings: []api.InstalledBinding{}}
	runtimeRef := f.Retain(t, "manifest", fx.JSON(t, runtime), f.Execution.Actor, "")
	sourced := f.SourceTransaction(t)
	sourced.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Manifest = runtimeRef
	sourced.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Executable = tool
	if _, err := f.State.Transact(ctx, sourced); err != nil {
		t.Fatal(err)
	}
	f.Record = sourced.Writes.LaunchPlans[0]
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	for i, stream := range f.Plan.Capture.Streams {
		q := f.AppendRequest(t, nil, true)
		q.StreamID, q.ExpectedGeneration = stream.ID, api.Generation(i+1)
		if _, err := f.State.AppendCapture(ctx, f.Worker, q); err != nil {
			t.Fatal(err)
		}
	}
	f.Ended(t)
	zeroWriters := uint64(0)
	frozenBytes := []byte(t.Name() + string(fx.ID(t)))
	frozenContent := api.BlobRef{ID: fx.ID(t), Class: "artifact", Bytes: int64(len(frozenBytes)), SHA256: fx.Digest(frozenBytes)}
	frozenRaw := fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "workspace/file.txt", Kind: "file", Mode: 0600, Content: &frozenContent}}})
	frozenRef := api.BlobRef{ID: fx.ID(t), Class: "manifest", Bytes: int64(len(frozenRaw)), SHA256: fx.Digest(frozenRaw)}
	acl := api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, LifeID: f.Lane.LifeID, Audience: "private", Generation: 1}
	native := &reviewNativeInput{checks: []string{"unit"}, snapshot: archivejob.Snapshot{Freeze: archivejob.Freeze{Target: f.Reservation.Target, LaunchID: f.Lane.LaunchID, Snapshot: frozenRef, Writers: &zeroWriters, WritableExports: &zeroWriters, ObservedAt: beginStamp()}, Objects: []api.ObjectWrite{
		{ObjectKey: frozenContent.ID, Class: "artifact", Bytes: frozenBytes, SHA256: frozenContent.SHA256, Origin: "service", ACL: acl}, {ObjectKey: frozenRef.ID, Class: "manifest", Bytes: frozenRaw, SHA256: frozenRef.SHA256, Origin: "service", ACL: acl}}}}
	source := any(f.State).(testProducerPort)
	if err := source.BindReviewRuntime(native, native); err != nil {
		t.Fatal(err)
	}
	subject, err := source.ReviewSnapshot(ctx, f.Execution, f.Reservation.Target)
	if err != nil {
		t.Fatal(err)
	}
	script := reviewRetain(t, f, "artifact", []byte("#!/bin/sh\nset -eu\nread -r value < input.txt\nprintf '%s' \"$value\"\ntest \"$value\" = \"$1\"\n"))
	expected := string(fx.ID(t))
	content := reviewRetain(t, f, "artifact", []byte(expected+"\n"))
	candidate := reviewRetain(t, f, "manifest", fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "task.sh", Kind: "file", Mode: 0700, Content: &script}, {Path: "input.txt", Kind: "file", Mode: 0600, Content: &content}}}))
	grants, err := f.State.Grants(ctx, f.Lane.GrantSetID)
	if err != nil {
		t.Fatal(err)
	}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", Input: candidate, GrantSetID: grants.ID, Budget: f.Plan.Budget, Executable: tool, Argv: []string{"sh", "task.sh", expected}}
	planRef := reviewRetain(t, f, "manifest", fx.JSON(t, plan))
	request := api.TestChildRequest{Child: subject.Target, Candidate: candidate, TestPlan: planRef, Budget: plan.Budget}
	owner, caller, pending := beginOperation(t, f, f.LaneScope(t), "grants.test-child", request)
	staged, err := source.StageChildTest(owner, caller, request, grants, subject)
	if err != nil {
		t.Fatal("native child staging failed", err)
	}
	if _, err := f.State.WorkerLease(ctx, f.Execution, staged.Job.Lease.ID); err == nil {
		t.Fatal("inert TestChild stage published worker authority before atomic admission")
	}
	if _, err := source.AdmittedChildTest(ctx, f.Execution, staged.Effect); err == nil {
		t.Fatal("TestChild recovery accepted an unadmitted staged job")
	}
	// This component retains a lane caller; the grants/service controls
	// separately check hierarchy and the human frame/proof handoff.
	input := api.Transaction{Scope: caller, RawRequest: caller.Frame.Bytes(), Compare: staged.Compare,
		Writes: api.StateWrites{WorkerLeases: []api.WorkerLease{staged.Job.Lease}}, Effects: []api.Effect{staged.Effect}, Reply: &api.RPCReply{Result: fx.JSON(t, api.Operation{ID: pending.Operation.ID, Status: "pending"})}}
	commit, err := f.State.Transact(owner, input)
	if err != nil {
		t.Fatal("TestChild atomic admission failed", err)
	}
	if commit.Operation.ID != pending.Operation.ID || commit.Operation.Status != "pending" || commit.Operation.FirstSeq == 0 {
		t.Fatal("TestChild admission lost its original operation")
	}
	admitted, err := source.AdmittedChildTest(ctx, f.Execution, staged.Effect)
	if err != nil || !reflect.DeepEqual(admitted, staged.Job) {
		t.Fatal("TestChild recovery lost its real committed admission", err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: staged.Effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: staged.Job.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.BeginReviewAllocation(ctx, f.Execution, claim); err != nil {
		t.Fatal(err)
	}
	allocation := api.HelperLease{ID: fx.ID(t), UID: uint32(os.Geteuid()) + 2000, GID: uint32(os.Getegid()) + 2000, ContainmentID: fx.ID(t), EndpointGeneration: 1}
	if err := source.RecordReviewAllocation(ctx, f.Execution, claim, allocation); err != nil {
		t.Fatal(err)
	}
	id, err := source.ReviewWorkerID(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal(err)
	}
	job := staged.Job
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion,
		Config: f.Deps.Config, Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: "/runtime/laneboss-worker.sock",
		ArtifactSHA256: tool.SHA256, ServiceVersion: tool.Version, Backend: "linux-bwrap-landlock", LaunchID: id, Target: &job.Lease.Target, WorkerLeaseID: job.Lease.ID}
	handoff, err := source.ReviewHandoff(ctx, f.Execution, claim, allocation, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	prepared := api.PreparedLaunch{ID: fx.ID(t), GateID: fx.ID(t), SpecSHA256: handoff.SpecSHA256, Target: job.Lease.Target, ContainmentID: allocation.ContainmentID, EndpointGeneration: 1, ProcessGeneration: "component-test:1"}
	binding, err := source.BindReviewWorker(ctx, f.Execution, claim, prepared)
	if err != nil {
		t.Fatal(err)
	}
	process := api.ProcessHandle{ID: id, Target: job.Lease.Target, ContainmentID: allocation.ContainmentID, Generation: prepared.ProcessGeneration}
	if err := source.RecordReviewProcess(ctx, f.Execution, claim, process); err != nil {
		t.Fatal(err)
	}
	facts := api.PeerFacts{HostUID: allocation.UID, HostGID: allocation.GID, HostPID: os.Getpid(), ProcessGeneration: "component-test:connector", ContainmentID: allocation.ContainmentID}
	worker := api.Scope{Config: f.Deps.Config, Actor: binding.Record.Actor, LaunchID: id, EndpointGeneration: 1, PolicyGeneration: 1,
		Connection: &fx.Connection{Identity: fx.ID(t), Endpoint: endpoint, Verified: &fx.Peer{FactsValue: facts}}, Frame: &fx.Frame{Raw: []byte("component native test worker frame")}}
	principal, err := f.State.WorkerBinding(ctx, endpoint, facts)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ack, err := dataworker.RunTest(ctx, dataworker.TestJob{Principal: principal, Scope: worker, Bootstrap: f.State, Clock: f.Deps.Clock, Workspace: root, Directory: directory, Executable: executable,
		Read: func(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
			return f.State.WorkerObject(ctx, worker, q)
		}})
	if err != nil {
		t.Fatal("native test did not submit its actual result", err)
	}
	before, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: job.Lease.Target.LifeID, Run: job.Lease.Target.Run})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range before.Events {
		if event.OperationID == job.Intent.OperationID && (event.Kind == "worker.completed" || event.Kind == "capture.bound") {
			t.Fatal("TestChild published measured completion before native retirement")
		}
	}
	zero, exit := uint64(0), 0
	observation := api.ProcessObservation{Handle: process, State: "exited", ExitCode: &exit, Survivors: &zero, ObservedAt: beginStamp(), PromptStatus: "completed"}
	outcome := api.EffectOutcome{EffectID: job.Lease.EffectID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded", Output: &ack.Result, Observation: &observation}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, outcome); err == nil {
		t.Fatal("TestChild completed without native retirement")
	}
	proof := archivejob.Retirement{JobID: job.ID, OperationID: job.Intent.OperationID, EffectID: job.Lease.EffectID, Target: job.Lease.Target, Allocation: allocation, ObservedAt: observation.ObservedAt,
		Release: &api.ReleaseReceipt{ID: fx.ID(t), LeaseID: allocation.ID, ContainmentID: allocation.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: job.Intent.OperationID, EffectID: job.Lease.EffectID,
			Quiescence: observation, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: observation.ObservedAt}}
	if err := source.RecordReviewRetirement(ctx, f.Execution, claim, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, outcome); err != nil {
		t.Fatal("native test measured completion failed", err)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: job.Lease.Target.LifeID, Run: job.Lease.Target.Run, Since: commit.Operation.FirstSeq - 1})
	if err != nil {
		t.Fatal(err)
	}
	checks, captures, workers, releases := 0, 0, 0, 0
	for _, event := range page.Events {
		if event.OperationID != job.Intent.OperationID {
			continue
		}
		if event.Kind == "worker.completed" {
			workers++
		}
		if event.Kind == "helper.released" {
			releases++
		}
		if event.Kind == "capture.appended" {
			captures++
		}
		if event.Kind == "blob.committed" {
			var ref api.BlobRef
			if api.DecodeObject(event.Payload, &ref) != nil || ref.Class != "check" {
				continue
			}
			chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: ref.ID, Limit: api.MaxChunkBytes})
			if err != nil {
				t.Fatal(err)
			}
			var check reviewjob.CheckRecord
			if api.DecodeObject(chunk.Data, &check) != nil || check.ExitCode != 0 || check.OperationID != job.Intent.OperationID || check.SnapshotSHA256 != subject.Snapshot.SHA256 {
				t.Fatal("TestChild retained another measured check")
			}
			checks++
		}
	}
	if checks != 1 || captures != 1 || workers != 1 || releases != 1 {
		t.Fatal("TestChild omitted its measured check, actual capture, worker or release")
	}
	operation, err := f.State.Operation(ctx, caller, commit.Operation.ID)
	if err != nil || operation.Status != "succeeded" || operation.LifeID != request.Child.LifeID {
		t.Fatal("TestChild operation did not complete its exact child", err)
	}
	verified, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verified.OK {
		t.Fatal("TestChild broke independent durable verification", err, verified.Problems)
	}
	if !reflect.DeepEqual(principal.Lease.Target, request.Child) {
		t.Fatal("TestChild changed its native target")
	}
}
