//go:build linux

package store_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/reviewjob"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Kernel identities, the prior test observation and protected policy are
// declared component inputs. SQLite, immutable objects, the fixed verifier,
// original mutation ownership and all review producer calls are real.
type reviewProducerPort interface {
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
}

type reviewNativeInput struct {
	snapshot            archivejob.Snapshot
	intent              archivejob.Intent
	checks              []string
	freezes, executions int
}

func (n *reviewNativeInput) FreezeReview(ctx context.Context, i archivejob.Intent, l api.Lane) (archivejob.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return archivejob.Snapshot{}, err
	}
	if i.Request.Target != (api.LifeRef{LifeID: l.LifeID, Run: l.Run}) || l.LaunchID != n.snapshot.Freeze.LaunchID || n.intent.OperationID != "" && n.intent != i {
		return archivejob.Snapshot{}, errors.New("native fixture selected another retained run")
	}
	n.intent = i
	n.freezes++
	n.snapshot.Freeze.Target, n.snapshot.Freeze.CancellationEpoch = i.Request.Target, i.CancellationEpoch
	return n.snapshot, nil
}
func (n *reviewNativeInput) CheckReviewFreeze(ctx context.Context, i archivejob.Intent, f archivejob.Freeze) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if i != n.intent || !reflect.DeepEqual(f, n.snapshot.Freeze) {
		return errors.New("native fixture freeze changed")
	}
	return nil
}
func (n *reviewNativeInput) RequiredReviewChecks(ctx context.Context, s api.Scope, target api.LifeRef) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.Actor.Kind != "service" || target != n.snapshot.Freeze.Target {
		return nil, errors.New("protected fixture requirement selector changed")
	}
	return append([]string{}, n.checks...), nil
}
func (n *reviewNativeInput) ExecuteReviewWorker(context.Context, api.Scope, archivejob.Job) error {
	n.executions++
	return errors.New("native process execution is outside this component boundary")
}

func reviewProducerScene(t *testing.T, drained bool) (*fx.Fixture, reviewProducerPort, *reviewNativeInput) {
	t.Helper()
	port, ok := any(new(store.Service)).(reviewProducerPort)
	if !ok {
		t.Fatal("installed writer lacks durable review producers")
	}
	f := fx.ControlledChild(t)
	f.Opened(t)
	if drained {
		for i, stream := range f.Plan.Capture.Streams {
			q := f.AppendRequest(t, nil, true)
			q.StreamID = stream.ID
			q.ExpectedGeneration = api.Generation(i + 1)
			if _, err := f.State.AppendCapture(context.Background(), f.Worker, q); err != nil {
				t.Fatal("primary EOF prerequisite failed", err)
			}
		}
	}
	f.Ended(t)
	zero := uint64(0)
	data := []byte(t.Name() + " current completed content " + string(fx.ID(t)))
	content := api.BlobRef{ID: fx.ID(t), Class: "artifact", Bytes: int64(len(data)), SHA256: fx.Digest(data)}
	raw := fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "workspace/current.txt", Kind: "file", Mode: 0600, Content: &content}}})
	ref := api.BlobRef{ID: fx.ID(t), Class: "manifest", Bytes: int64(len(raw)), SHA256: fx.Digest(raw)}
	acl := api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, LifeID: f.Lane.LifeID, Audience: "private", Generation: 1}
	native := &reviewNativeInput{checks: []string{"unit"}, snapshot: archivejob.Snapshot{Freeze: archivejob.Freeze{Target: f.Reservation.Target, LaunchID: f.Lane.LaunchID, Snapshot: ref, Writers: &zero, WritableExports: &zero, ObservedAt: beginStamp()}, Objects: []api.ObjectWrite{
		{ObjectKey: content.ID, Class: content.Class, Bytes: data, SHA256: content.SHA256, Origin: "service", ACL: acl}, {ObjectKey: ref.ID, Class: ref.Class, Bytes: raw, SHA256: ref.SHA256, Origin: "service", ACL: acl}}}}
	port = any(f.State).(reviewProducerPort)
	if err := port.BindReviewRuntime(native, native); err != nil {
		t.Fatal(err)
	}
	return f, port, native
}

func TestReviewSnapshotDurable(t *testing.T) {
	f, source, native := reviewProducerScene(t, true)
	ctx := context.Background()
	target := f.Reservation.Target
	first, err := source.ReviewSnapshot(ctx, f.Execution, target)
	if err != nil {
		t.Fatal("real writer did not retain its native frozen input", err)
	}
	second, err := source.ReviewSnapshot(ctx, f.Execution, target)
	if err != nil || !reflect.DeepEqual(first, second) || native.freezes != 1 {
		t.Fatal("review snapshot retry replaced its original freeze", err)
	}
	chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: first.Snapshot.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var tree api.ObjectManifest
	if api.DecodeObject(chunk.Data, &tree) != nil || tree.Entries[0].Path != "work/current.txt" || tree.Entries[0].Content.SHA256 != native.snapshot.Objects[0].SHA256 {
		t.Fatal("review substituted launch-time bytes or lost the verifier namespace")
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	source = any(f.State).(reviewProducerPort)
	if err := source.BindReviewRuntime(native, native); err != nil {
		t.Fatal(err)
	}
	third, err := source.ReviewSnapshot(ctx, f.Execution, target)
	if err != nil || !reflect.DeepEqual(first, third) || native.freezes != 1 {
		t.Fatal("review frozen identity did not survive reopening the writer", err)
	}
	native.snapshot.Freeze.LaunchID = fx.ID(t)
	if subject, err := source.ReviewSnapshot(ctx, f.Execution, target); err == nil || subject.Target.LifeID != "" {
		t.Fatal("review returned a subject after its native freeze changed")
	}
}

func TestReviewSnapshotRefusals(t *testing.T) {
	for _, mode := range []string{"capture-eof", "unknown-writers", "live-export", "wrong-launch", "future-freeze", "content-pin"} {
		t.Run(mode, func(t *testing.T) {
			f, source, native := reviewProducerScene(t, mode != "capture-eof")
			switch mode {
			case "unknown-writers":
				native.snapshot.Freeze.Writers = nil
			case "live-export":
				one := uint64(1)
				native.snapshot.Freeze.WritableExports = &one
			case "wrong-launch":
				native.snapshot.Freeze.LaunchID = fx.ID(t)
			case "future-freeze":
				native.snapshot.Freeze.ObservedAt = api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
			case "content-pin":
				native.snapshot.Objects[0].Bytes[0] ^= 1
			}
			actual, err := source.ReviewSnapshot(context.Background(), f.Execution, f.Reservation.Target)
			if err == nil || actual.Target.LifeID != "" {
				t.Fatal("unmeasured or changed review freeze was returned", mode)
			}
		})
	}
}

func reviewRetain(t *testing.T, f *fx.Fixture, class string, raw []byte) api.BlobRef {
	t.Helper()
	cause := f.Intent(t, api.InternalObjectRetain)
	ref, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: cause, Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: class, Bytes: raw, SHA256: fx.Digest(raw), Origin: "service", ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, LifeID: f.Lane.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal("component review input retention failed", err)
	}
	return ref
}

func reviewCandidateInput(t *testing.T, f *fx.Fixture, subject api.ReviewSubject) (api.ReviewRequest, api.WorkerLease) {
	t.Helper()
	ctx := context.Background()
	operation := f.Reservation.OperationID
	check := reviewjob.CheckRecord{Schema: "laneboss.check.v2", Name: "unit", Target: subject.Target, EndSeq: subject.EndSeq, SnapshotSHA256: subject.Snapshot.SHA256, ExitCode: 0, WorkerLeaseID: fx.ID(t), OperationID: operation}
	checkRef := reviewRetain(t, f, "check", fx.JSON(t, check))
	input := reviewRetain(t, f, "manifest", fx.JSON(t, subject))
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
	observation := api.ProcessObservation{Handle: api.ProcessHandle{ID: worker.ID, Target: subject.Target, ContainmentID: worker.ContainmentID, Generation: worker.ProcessGeneration}, State: "exited", ExitCode: &exit, Survivors: &zero, ObservedAt: beginStamp(), PromptStatus: "completed"}
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
	diffRef := reviewRetain(t, f, "diff", fx.JSON(t, diff))
	streams := []api.ReviewStreamFact{}
	for _, stream := range subject.Streams {
		streams = append(streams, api.ReviewStreamFact{BindingID: subject.CaptureBindingID, StreamID: stream.ID, StartOffset: 0, EndOffset: 0, EOF: true, GapIDs: []api.ID{}})
	}
	tools := reviewRetain(t, f, "manifest", fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}))
	inventory := reviewjob.InventoryRecord{Schema: "laneboss.review-inventory.v2", ThroughSeq: subject.InventorySeq, Streams: streams, ToolRecords: tools, ToolCoverage: api.CoveragePartial}
	inventoryRef := reviewRetain(t, f, "manifest", fx.JSON(t, inventory))
	return api.ReviewRequest{Target: subject.Target, Diff: diffRef, Checks: []api.BlobRef{checkRef}, RecordInventory: inventoryRef, RefusalResolution: []api.ID{}}, testLease
}

func TestReviewWorkerRetained(t *testing.T) {
	f, source, native := reviewProducerScene(t, true)
	ctx := context.Background()
	subject, err := source.ReviewSnapshot(ctx, f.Execution, f.Reservation.Target)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := reviewCandidateInput(t, f, subject)
	// Replace reopens the writer for the declared prior-test primitive.
	source = any(f.State).(reviewProducerPort)
	if err := source.BindReviewRuntime(native, native); err != nil {
		t.Fatal(err)
	}
	// A service-origin manifest is still only a candidate. Its complete label
	// cannot substitute for an actual authenticated provider/tool inventory.
	inventoryChunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: request.RecordInventory.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var labelled reviewjob.InventoryRecord
	if api.DecodeObject(inventoryChunk.Data, &labelled) != nil {
		t.Fatal("retained inventory prerequisite failed")
	}
	labelled.ToolCoverage = api.CoverageComplete
	changedRequest := request
	changedRequest.RecordInventory = reviewRetain(t, f, "manifest", fx.JSON(t, labelled))
	labelOwner, labelCaller, _ := beginOperation(t, f, f.Human, "lane.review", changedRequest)
	if invented, err := source.ReserveReviewWorker(labelOwner, labelCaller, changedRequest, subject, []string{"unit"}); err == nil || invented.ID != "" {
		t.Fatal("complete labels substituted for an authenticated tool inventory")
	}
	owner, caller, pending := beginOperation(t, f, f.Human, "lane.review", request)
	lease, err := source.ReserveReviewWorker(owner, caller, request, subject, []string{"unit"})
	if err != nil {
		t.Fatal("real writer did not reserve the exact verifier", err)
	}
	again, err := source.ReserveReviewWorker(owner, caller, request, subject, []string{"unit"})
	if err != nil || again != lease {
		t.Fatal("review retry replaced its original worker", err)
	}
	correlated := caller
	correlated.Request.RequestID = fx.ID(t)
	correlated.Frame = &fx.Frame{Raw: fx.JSON(t, correlated.Request)}
	correlationReplay, err := source.ReserveReviewWorker(owner, correlated, request, subject, []string{"unit"})
	if err != nil || correlationReplay != lease {
		t.Fatal("new response correlation replaced the original review worker", err)
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
	allocation := api.HelperLease{ID: fx.ID(t), UID: uint32(os.Geteuid()) + 2000, GID: uint32(os.Getegid()) + 2000, ContainmentID: fx.ID(t), EndpointGeneration: 1}
	if err := source.RecordReviewAllocation(ctx, f.Execution, claim, allocation); err != nil {
		t.Fatal(err)
	}
	id, err := source.ReviewWorkerID(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: f.Deps.Config, Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: "/runtime/laneboss-worker.sock", ArtifactSHA256: job.Plan.Executable.SHA256, ServiceVersion: job.Plan.Executable.Version, Backend: "linux-bwrap-landlock", LaunchID: id, Target: &lease.Target, WorkerLeaseID: lease.ID}
	handoff, err := source.ReviewHandoff(ctx, f.Execution, claim, allocation, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	prepared := api.PreparedLaunch{ID: fx.ID(t), GateID: fx.ID(t), SpecSHA256: handoff.SpecSHA256, Target: lease.Target, ContainmentID: allocation.ContainmentID, EndpointGeneration: 1, ProcessGeneration: "component-review:1"}
	binding, err := source.BindReviewWorker(ctx, f.Execution, claim, prepared)
	if err != nil {
		t.Fatal(err)
	}
	process := api.ProcessHandle{ID: id, Target: lease.Target, ContainmentID: allocation.ContainmentID, Generation: prepared.ProcessGeneration}
	if err := source.RecordReviewProcess(ctx, f.Execution, claim, process); err != nil {
		t.Fatal(err)
	}
	facts := api.PeerFacts{HostUID: allocation.UID, HostGID: allocation.GID, HostPID: os.Getpid(), ProcessGeneration: "component-review:connector", ContainmentID: allocation.ContainmentID}
	worker := api.Scope{Config: f.Deps.Config, Actor: binding.Record.Actor, LaunchID: id, EndpointGeneration: 1, PolicyGeneration: 1, Connection: &fx.Connection{Identity: fx.ID(t), Endpoint: endpoint, Verified: &fx.Peer{FactsValue: facts}}, Frame: &fx.Frame{Raw: []byte("component review worker frame")}}
	principal, err := f.State.WorkerBinding(ctx, endpoint, facts)
	if err != nil {
		t.Fatal("real writer did not authenticate its export-review principal", err)
	}
	ack, err := dataworker.RunReview(ctx, dataworker.ReviewJob{Principal: principal, Scope: worker, Bootstrap: f.State, Clock: f.Deps.Clock, Read: func(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
		return f.State.WorkerObject(ctx, worker, q)
	}})
	if err != nil {
		t.Fatal("fixed verifier failed on real retained inputs", err)
	}
	zero, exit := uint64(0), 0
	observed := api.ProcessObservation{Handle: process, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "completed", ObservedAt: beginStamp()}
	outcome := api.EffectOutcome{EffectID: lease.EffectID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded", Output: &ack.Result, Observation: &observed}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, outcome); err == nil {
		t.Fatal("result labels completed a verifier without native retirement")
	}
	proof := archivejob.Retirement{JobID: job.ID, OperationID: job.Intent.OperationID, EffectID: lease.EffectID, Target: lease.Target, Allocation: allocation, ObservedAt: observed.ObservedAt,
		Release: &api.ReleaseReceipt{ID: fx.ID(t), LeaseID: allocation.ID, ContainmentID: allocation.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: job.Intent.OperationID, EffectID: lease.EffectID, Quiescence: observed, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: observed.ObservedAt}}
	if err := source.RecordReviewRetirement(ctx, f.Execution, claim, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, outcome); err != nil {
		t.Fatal("retained measured component result did not complete", err)
	}
	ref, err := source.AwaitReviewResult(owner, caller, lease)
	if err != nil || ref != ack.Result || native.executions != 0 {
		t.Fatal("review result replay allocated or waited for another worker", err)
	}
	verified, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verified.OK {
		t.Fatal("review result broke independent durable store verification", err, verified.Problems)
	}
	receipt, err := f.State.LookupReceipt(owner, caller, pending.Key)
	if err != nil || receipt.Reply != nil || receipt.Operation.Status != "pending" {
		t.Fatal("worker completion prematurely completed the public review", err)
	}
	chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: ref.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var evidence api.ReviewEvidence
	if api.DecodeObject(chunk.Data, &evidence) != nil || evidence.Coverage != api.CoveragePartial {
		t.Fatal("partial tool evidence became complete")
	}
	if err := api.ValidateReviewAcceptance(caller, api.ReviewReceipt{ID: job.ID, Reviewer: caller.Actor, Diff: request.Diff, Checks: request.Checks, RecordInventory: request.RecordInventory, RefusalResolution: request.RefusalResolution, Coverage: evidence.Coverage, Evidence: &evidence}, subject, []string{"unit"}); err == nil {
		t.Fatal("partial evidence authorized acceptance")
	}
}
