//go:build linux

package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Native facts are component doubles. Every reservation, source byte, handoff,
// identity, worker acknowledgement and completion below uses the real writer.
type beginNative struct {
	snapshot  archivejob.Snapshot
	intent    archivejob.Intent
	workspace api.CleanupWorkspace
}

func (n *beginNative) FreezeArchive(ctx context.Context, i archivejob.Intent, l api.Lane) (archivejob.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return archivejob.Snapshot{}, err
	}
	if l.LifeID != i.Request.Target.LifeID || l.Run != i.Request.Target.Run || l.LaunchID != n.snapshot.Freeze.LaunchID {
		return archivejob.Snapshot{}, errors.New("native snapshot selected another original launch")
	}
	n.intent = i
	n.snapshot.Freeze.Target = i.Request.Target
	n.snapshot.Freeze.CancellationEpoch = i.CancellationEpoch
	return n.snapshot, nil
}
func (n *beginNative) CheckArchiveFreeze(ctx context.Context, i archivejob.Intent, f archivejob.Freeze) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if i != n.intent || f.Snapshot != n.snapshot.Freeze.Snapshot || f.Target != i.Request.Target {
		return errors.New("native freeze changed")
	}
	return nil
}
func (n *beginNative) ResolveCleanupWorkspace(ctx context.Context, target api.LifeRef, id api.ID) (api.CleanupWorkspace, error) {
	if err := ctx.Err(); err != nil {
		return api.CleanupWorkspace{}, err
	}
	if target != n.workspace.Target || id != n.workspace.ID {
		return api.CleanupWorkspace{}, errors.New("native workspace selector changed")
	}
	return n.workspace, nil
}
func (*beginNative) ReadWorkspaceRemoval(context.Context, api.CleanupJob) (api.WorkspaceRemoval, error) {
	return api.WorkspaceRemoval{}, api.NotImplemented("lb-v2-admin", "removal is outside this first-intent fixture")
}
func (*beginNative) ReadCleanupWorkspace(context.Context, api.CleanupJob) (api.WorkspaceReadback, error) {
	return api.WorkspaceReadback{}, api.NotImplemented("lb-v2-admin", "workspace collection is outside this first-intent fixture")
}
func beginStamp() api.Timestamp { return api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)) }

func beginOperation(t *testing.T, f *fx.Fixture, scope api.Scope, method api.Method, body any) (context.Context, api.Scope, api.MutationReceipt) {
	t.Helper()
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: method, RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, body)}
	var err error
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request = request
	scope.Frame = &fx.Frame{Raw: fx.JSON(t, request)}
	ctx, retire := f.State.TrackMutation(context.Background())
	t.Cleanup(retire)
	receipt, won, err := f.State.ReserveMutation(ctx, api.RequestReservation{Scope: scope, RawRequest: fx.JSON(t, request), Deadline: fx.Expiry()})
	if err != nil || !won {
		t.Fatal("fresh dispatcher reservation failed", err)
	}
	return ctx, scope, receipt
}

func freshBegin(t *testing.T) (*fx.Fixture, api.EffectLease, api.ArchiveReceipt, api.ReleaseReceipt) {
	t.Helper()
	f := fx.ControlledChild(t)
	f.Opened(t)
	f.Ended(t)
	ctx := context.Background()
	target := f.Reservation.Target
	zero, exit := uint64(0), 0
	data := []byte("current component workspace " + string(fx.ID(t)))
	content := api.BlobRef{ID: fx.ID(t), Class: "artifact", SHA256: fx.Digest(data), Bytes: int64(len(data))}
	tree := fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "current.txt", Kind: "file", Mode: 0600, Content: &content}}})
	manifest := api.BlobRef{ID: fx.ID(t), Class: "manifest", SHA256: fx.Digest(tree), Bytes: int64(len(tree))}
	acl := api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, LifeID: target.LifeID, Audience: "owner", Generation: 1}
	native := &beginNative{snapshot: archivejob.Snapshot{Freeze: archivejob.Freeze{Target: target, LaunchID: f.Lane.LaunchID, CancellationEpoch: f.Lane.CancellationEpoch, Snapshot: manifest, Writers: &zero, WritableExports: &zero, ObservedAt: beginStamp()}, Objects: []api.ObjectWrite{{ObjectKey: content.ID, Class: content.Class, Bytes: data, SHA256: content.SHA256, Origin: "service", ACL: acl}, {ObjectKey: manifest.ID, Class: manifest.Class, Bytes: tree, SHA256: manifest.SHA256, Origin: "service", ACL: acl}}}}
	native.workspace = api.CleanupWorkspace{ID: f.Lane.Workspace.ID, RootID: fx.ID(t), RepositoryID: fx.ID(t), Target: target, Generation: 1, RootIdentity: "native-component-root", DirectoryIdentity: "native-component-directory", GitIdentity: "native-component-git", Branch: f.Lane.Workspace.Branch, Head: f.Lane.Workspace.Base}
	f.Deps.ArchiveNative, f.Deps.CleanupNative = native, native
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: target.LifeID, Run: target.Run})
	if err != nil {
		t.Fatal(err)
	}
	var end api.Event
	for _, e := range page.Events {
		if e.Kind == "lane.ended" {
			end = e
		}
	}
	if end.ID == "" {
		t.Fatal("fresh archive has no actual committed end")
	}
	request := api.ArchiveRequest{Target: target, ExpectedGeneration: f.Lane.Generation}
	owner, caller, reserved := beginOperation(t, f, f.Human, "lane.archive", request)
	job, err := f.State.ReserveArchive(owner, caller, archivejob.Intent{Request: request, OperationID: reserved.Operation.ID, CancellationEpoch: f.Lane.CancellationEpoch, EndEventID: end.ID, EndSeq: end.Seq})
	if err != nil {
		t.Fatal("fresh public archive reservation failed", err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: job.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	workerID, err := f.State.ArchiveWorkerID(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal(err)
	}
	allocation := api.HelperLease{ID: fx.ID(t), UID: f.Plan.Lease.UID + 2000, GID: f.Plan.Lease.GID + 2000, ContainmentID: fx.ID(t), EndpointGeneration: 1}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: f.Deps.Config, Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: "/runtime/laneboss-worker.sock", ArtifactSHA256: job.Plan.Executable.SHA256, ServiceVersion: job.Plan.Executable.Version, Backend: "linux-bwrap-landlock", LaunchID: workerID, Target: &target, WorkerLeaseID: job.Lease.ID}
	handoff, err := f.State.ArchiveHandoff(ctx, f.Execution, claim, allocation, endpoint)
	if err != nil {
		t.Fatal("fresh archive handoff failed", err)
	}
	prepared := api.PreparedLaunch{ID: fx.ID(t), GateID: fx.ID(t), SpecSHA256: handoff.SpecSHA256, Target: target, ContainmentID: allocation.ContainmentID, EndpointGeneration: 1, ProcessGeneration: "fresh-boot:worker"}
	binding, err := f.State.BindArchiveWorker(ctx, f.Execution, claim, prepared)
	if err != nil {
		t.Fatal("fresh archive prepared identity failed", err)
	}
	process := api.ProcessHandle{ID: workerID, Target: target, ContainmentID: allocation.ContainmentID, Generation: prepared.ProcessGeneration}
	if err := f.State.RecordArchiveProcess(ctx, f.Execution, claim, process); err != nil {
		t.Fatal(err)
	}
	facts := api.PeerFacts{HostUID: allocation.UID, HostGID: allocation.GID, HostPID: os.Getpid(), ProcessGeneration: "fresh-boot:connector", ContainmentID: allocation.ContainmentID}
	worker := api.Scope{Config: f.Deps.Config, Actor: binding.Record.Actor, LaunchID: workerID, EndpointGeneration: 1, PolicyGeneration: 1, Connection: &fx.Connection{Identity: fx.ID(t), Endpoint: endpoint, Verified: &fx.Peer{FactsValue: facts}}, Frame: &fx.Frame{Raw: []byte("component native archive frame")}}
	principal, err := f.State.WorkerBinding(ctx, endpoint, facts)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := dataworker.RunArchive(ctx, dataworker.ArchiveJob{Principal: principal, Scope: worker, Bootstrap: f.State, Read: func(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
		return f.State.WorkerObject(ctx, worker, q)
	}, Sink: f.State, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal("fresh real archive producer failed", err)
	}
	observation := api.ProcessObservation{Handle: process, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "completed", ObservedAt: beginStamp()}
	if _, err := f.State.CompleteArchive(ctx, f.Execution, claim, observation); err != nil {
		t.Fatal("fresh archive completion failed", err)
	}
	raw, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: ack.Result.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var completion archivejob.Completion
	if err := api.DecodeObject(raw.Data, &completion); err != nil {
		t.Fatal(err)
	}
	// The terminal decision is a fixture prerequisite; the actual store CAS and
	// causal lifecycle event are used, rather than writing a collection intent.
	before := f.Lane.Generation
	f.Lane.Generation++
	f.Lane.State = "merged"
	decision := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalLifecycleEffect, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: f.Human.Actor, CauseOperationID: fx.ID(t), CauseRequestID: fx.ID(t), EffectID: fx.ID(t), Target: target, CancellationEpoch: f.Lane.CancellationEpoch}
	event := f.Event(t, "lane.state", api.StateEvent{From: "verifying", To: "merged", Generation: f.Lane.Generation})
	event.OperationID, event.RequestID = decision.CauseOperationID, decision.CauseRequestID
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &decision, Writes: api.StateWrites{Lanes: []api.Lane{f.Lane}}, Events: []api.Event{event}, Compare: []api.Compare{{Kind: api.CompareLane, ID: target.LifeID, Generation: before}}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: target.LifeID, Epoch: f.Lane.CancellationEpoch}}}}); err != nil {
		t.Fatal("terminal decision prerequisite failed", err)
	}
	releaseCause := decision
	releaseCause.ID, releaseCause.Kind, releaseCause.CauseOperationID, releaseCause.CauseRequestID, releaseCause.EffectID = fx.ID(t), api.InternalHelperRelease, fx.ID(t), fx.ID(t), fx.ID(t)
	released := f.Observation(t, "exited").Observation
	releaseEffect := api.Effect{ID: releaseCause.EffectID, OperationID: releaseCause.CauseOperationID, Context: &releaseCause, HelperRelease: &api.HelperReleaseRequest{Cause: releaseCause, LeaseID: f.Plan.Lease.ID, Observation: released}}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &releaseCause, Effects: []api.Effect{releaseEffect}}); err != nil {
		t.Fatal("actual release outbox prerequisite failed", err)
	}
	releaseClaim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: releaseEffect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	release := api.ReleaseReceipt{ID: fx.ID(t), LeaseID: f.Plan.Lease.ID, ContainmentID: f.Plan.Lease.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: releaseEffect.OperationID, EffectID: releaseEffect.ID, Quiescence: released, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: released.ObservedAt}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: releaseEffect.ID, ClaimID: releaseClaim.ClaimID, ExpectedGeneration: releaseClaim.Record.Generation, Status: "succeeded", Release: &release}); err != nil {
		t.Fatal("measured release prerequisite failed", err)
	}
	clean := api.CleanRequest{Target: target, ExpectedGeneration: f.Lane.Generation, ArchiveReceiptID: completion.Receipt.ID}
	cleanCtx, cleanScope, cleanReceipt := beginOperation(t, f, f.Human, "lane.clean", clean)
	cause := decision
	cause.ID, cause.CauseOperationID, cause.CauseRequestID, cause.EffectID = fx.ID(t), cleanReceipt.Operation.ID, cleanScope.Request.RequestID, fx.ID(t)
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Clean: &clean}
	if _, err := f.State.Transact(cleanCtx, api.Transaction{Scope: cleanScope, Effects: []api.Effect{effect}, Reply: &api.RPCReply{Result: fx.JSON(t, api.Operation{ID: cleanReceipt.Operation.ID, Status: "pending"})}, Compare: []api.Compare{{Kind: api.CompareLane, ID: target.LifeID, Generation: f.Lane.Generation}}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: target.LifeID, Epoch: f.Lane.CancellationEpoch}}}}); err != nil {
		t.Fatal("fresh cleanup outbox prerequisite failed", err)
	}
	cleanClaim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	return f, cleanClaim, completion.Receipt, release
}

func TestBeginCleanupFresh(t *testing.T) {
	f, claim, archive, release := freshBegin(t)
	job, err := f.State.BeginCleanup(context.Background(), f.Execution, claim)
	if err != nil || job.Intent.ID == "" || job.Intent.Archive != archive || job.Intent.Release.ID != release.ID || job.Claim.ClaimID != claim.ClaimID {
		t.Fatal("first BeginCleanup did not join the actual archive and release", err)
	}
	again, err := f.State.BeginCleanup(context.Background(), f.Execution, claim)
	if err != nil || again.Intent.ID != job.Intent.ID {
		t.Fatal("first cleanup intent was not durable on retry", err)
	}
}
func TestBeginCleanupRefusesClaim(t *testing.T) {
	f, claim, _, _ := freshBegin(t)
	claim.ClaimID = fx.ID(t)
	if _, err := f.State.BeginCleanup(context.Background(), f.Execution, claim); err == nil {
		t.Fatal("first BeginCleanup accepted another claim")
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeConflict {
			t.Fatal("fresh cleanup reached an unrelated refusal", err)
		}
	}
}
