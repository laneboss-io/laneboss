//go:build linux

package testfx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/store"
)

// Only native filesystem/kernel observations are doubles. Archive bytes,
// worker acknowledgements, collection and the cleaned bit use the real store.
type cleanNative struct {
	snapshot  archivejob.Snapshot
	intent    archivejob.Intent
	workspace api.CleanupWorkspace
	removal   api.WorkspaceRemoval
	removed   bool
	dirty     bool
	Roots     []string
	Requester api.Actor
	Stages    map[api.ID]string
	Targets   map[api.ID]string
}

func (n *cleanNative) RestoreRoots(ctx context.Context, scope api.Scope) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if scope.Actor != n.Requester {
		return nil, errors.New("restore roots belong to another caller")
	}
	return append([]string{}, n.Roots...), nil
}

func (n *cleanNative) StageRestore(ctx context.Context, scope api.Scope, q api.RestoreRequest, tree api.ObjectManifest, read archivejob.ReadObject, ceiling uint64) (api.ID, api.RestoreReceipt, error) {
	var report api.RestoreReceipt
	roots, err := n.RestoreRoots(ctx, scope)
	if err != nil {
		return "", report, err
	}
	parent, err := archivejob.RestoreDestination(q.Path, roots)
	if err != nil {
		return "", report, err
	}
	_, err = archivejob.EmptyRestoreTarget(parent, filepath.Base(q.Path))
	parent.Close()
	if err != nil {
		return "", report, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(q.Path), "restore-")
	if err != nil {
		return "", report, err
	}
	report.Head, err = archivejob.Restore(ctx, filepath.Join(stage, "result"), tree, read, ceiling, archivejob.RestoreOptions{Roots: []string{stage}, AllowNestedGit: q.AllowNestedGit, Report: &report})
	if err != nil {
		return "", report, errors.Join(err, os.RemoveAll(stage))
	}
	id := api.ID(filepath.Base(stage))
	if n.Stages == nil {
		n.Stages = map[api.ID]string{}
		n.Targets = map[api.ID]string{}
	}
	n.Stages[id], n.Targets[id] = stage, q.Path
	return id, report, nil
}
func (n *cleanNative) PublishRestore(ctx context.Context, scope api.Scope, id api.ID) error {
	if _, err := n.RestoreRoots(ctx, scope); err != nil {
		return err
	}
	stage, ok := n.Stages[id]
	if !ok {
		return errors.New("unknown restore stage")
	}
	if err := os.Rename(filepath.Join(stage, "result"), n.Targets[id]); err != nil {
		return err
	}
	delete(n.Stages, id)
	delete(n.Targets, id)
	return os.RemoveAll(stage)
}
func (n *cleanNative) AbortRestore(ctx context.Context, scope api.Scope, id api.ID) error {
	stage, ok := n.Stages[id]
	if !ok {
		return nil
	}
	delete(n.Stages, id)
	delete(n.Targets, id)
	return os.RemoveAll(stage)
}

func cleanStamp() api.Timestamp {
	return api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
}

func (n *cleanNative) FreezeArchive(ctx context.Context, i archivejob.Intent, lane api.Lane) (archivejob.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return archivejob.Snapshot{}, err
	}
	if lane.LifeID != i.Request.Target.LifeID || lane.Run != i.Request.Target.Run || lane.LaunchID != n.snapshot.Freeze.LaunchID {
		return archivejob.Snapshot{}, errors.New("archive selected another launch")
	}
	n.intent = i
	n.snapshot.Freeze.Target = i.Request.Target
	n.snapshot.Freeze.CancellationEpoch = i.CancellationEpoch
	return n.snapshot, nil
}

func (n *cleanNative) CheckArchiveFreeze(ctx context.Context, i archivejob.Intent, freeze archivejob.Freeze) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if i != n.intent || freeze.Snapshot != n.snapshot.Freeze.Snapshot || freeze.Target != i.Request.Target {
		return errors.New("archive freeze changed")
	}
	return nil
}

func (n *cleanNative) ResolveCleanupWorkspace(ctx context.Context, target api.LifeRef, id api.ID) (api.CleanupWorkspace, error) {
	if err := ctx.Err(); err != nil {
		return api.CleanupWorkspace{}, err
	}
	if target != n.workspace.Target || id != n.workspace.ID {
		return api.CleanupWorkspace{}, errors.New("cleanup workspace changed")
	}
	return n.workspace, nil
}

func (n *cleanNative) ReadWorkspaceRemoval(ctx context.Context, job api.CleanupJob) (api.WorkspaceRemoval, error) {
	if err := ctx.Err(); err != nil {
		return api.WorkspaceRemoval{}, err
	}
	if job.Intent.Workspace != n.workspace || job.Intent.ID != n.removal.IntentID || job.Claim.ClaimID != n.removal.ClaimID {
		return api.WorkspaceRemoval{}, errors.New("cleanup removal changed")
	}
	return n.removal, nil
}

func (n *cleanNative) ReadCleanupWorkspace(ctx context.Context, job api.CleanupJob) (api.WorkspaceReadback, error) {
	if err := ctx.Err(); err != nil {
		return api.WorkspaceReadback{}, err
	}
	if job.Intent.Workspace != n.workspace || api.ValidateCleanupJob(job, time.Now()) != nil {
		return api.WorkspaceReadback{}, errors.New("cleanup selected another job")
	}
	w := n.workspace
	r := api.WorkspaceReadback{WorkspaceID: w.ID, RootIdentity: w.RootIdentity, GitIdentity: w.GitIdentity, ObservedAt: cleanStamp()}
	var err error
	r.ID, err = wire.NewID()
	if err != nil {
		return r, err
	}
	if n.removed {
		r.WorktreeState, r.BranchState = "absent", "absent"
	} else {
		dirty := n.dirty
		r.WorktreeState, r.BranchState, r.DirectoryIdentity, r.Head, r.Dirty = "present", "present", w.DirectoryIdentity, w.Head, &dirty
	}
	return r, nil
}

func (n *cleanNative) InspectCleanupWorkspace(ctx context.Context, job api.CleanupJob) (api.WorkspaceReadback, error) {
	return n.ReadCleanupWorkspace(ctx, job)
}

func (n *cleanNative) RemoveCleanupWorkspace(ctx context.Context, job api.CleanupJob, before api.WorkspaceReadback) (api.WorkspaceRemoval, error) {
	current, err := n.ReadCleanupWorkspace(ctx, job)
	if err != nil {
		return api.WorkspaceRemoval{}, err
	}
	a, b := current, before
	a.ID, b.ID, a.ObservedAt, b.ObservedAt = "", "", "", ""
	if !reflect.DeepEqual(a, b) {
		if current.Dirty != nil && *current.Dirty {
			return api.WorkspaceRemoval{}, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-admin",
				Message: "cleanup retained dirty work (retain_dirty)",
				Instead: "Merge or discard the uncommitted work (unmerged commits on an abandoned branch are retained), then clean the lane again."}
		}
		return api.WorkspaceRemoval{}, errors.New("cleanup workspace changed before native removal")
	}
	if before.Dirty == nil {
		return api.WorkspaceRemoval{}, errors.New("component preserves dirty or unknown work")
	}
	if *before.Dirty {
		after, err := n.ReadCleanupWorkspace(ctx, job)
		if err != nil {
			return api.WorkspaceRemoval{}, err
		}
		n.removal = api.WorkspaceRemoval{IntentID: job.Intent.ID, ClaimID: job.Claim.ClaimID, Action: "retain_dirty", Before: before, After: after, Unforced: true, Synced: true}
		return n.removal, nil
	}
	n.removed = true
	after, err := n.ReadCleanupWorkspace(ctx, job)
	if err != nil {
		return api.WorkspaceRemoval{}, err
	}
	n.removal = api.WorkspaceRemoval{IntentID: job.Intent.ID, ClaimID: job.Claim.ClaimID, Action: "remove_clean", Before: before, After: after, Unforced: true, Synced: true}
	return n.removal, nil
}

func cleanOperation(t testing.TB, f *Fixture, method api.Method, body any) (context.Context, api.Scope, api.MutationReceipt) {
	t.Helper()
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: method, RequestID: ID(t), IdempotencyKey: ID(t), Params: JSON(t, body)}
	var err error
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	scope := f.Human
	scope.Request, scope.Frame = request, &Frame{Raw: JSON(t, request)}
	ctx, retire := f.State.TrackMutation(context.Background())
	t.Cleanup(retire)
	receipt, won, err := f.State.ReserveMutation(ctx, api.RequestReservation{Scope: scope, RawRequest: scope.Frame.Bytes(), Deadline: Expiry()})
	if err != nil || !won {
		t.Fatal("cleanup reservation failed", err)
	}
	return ctx, scope, receipt
}

// Cleanup prepares a real archive and clean effect, then returns the collection
// step so a recovery job can run across the final committed cleanup transition.
func (f *Fixture) Cleanup(t testing.TB, produce func(context.Context, api.Scope, api.WorkerPrincipal) (api.WorkerResultReceipt, error)) func() api.CleanupReceipt {
	t.Helper()
	scene := f.PrepareCleanup(t, produce, nil, false)
	return func() api.CleanupReceipt { return scene.Collect(t) }
}

// CleanupRun leaves the actual Clean effect pending for service reconciler
// tests. Only native filesystem observations are component inputs.
type CleanupRun struct {
	Effect    api.Effect
	Archive   api.ArchiveReceipt
	Workspace api.WorkspaceCollector
	fixture   *Fixture
	native    *cleanNative
}

func (r *CleanupRun) SetDirty(dirty bool) { r.native.dirty = dirty }

func (r *CleanupRun) SetRestoreRoot(root string) { r.native.Roots = []string{root} }

func (f *Fixture) PrepareCleanup(t testing.TB, produce func(context.Context, api.Scope, api.WorkerPrincipal) (api.WorkerResultReceipt, error), stopped func(), dirty bool) *CleanupRun {
	t.Helper()
	f.Opened(t)
	if stopped == nil {
		f.Ended(t)
	} else {
		stopped()
	}
	return f.prepareCleanupEnded(t, produce, dirty, false, nil)
}

// CleanupReleased continues an already ended, decided and released life. Its
// actual release outcome is required by BeginCleanup; none is fabricated here.
func (f *Fixture) CleanupReleased(t testing.TB, produce func(context.Context, api.Scope, api.WorkerPrincipal) (api.WorkerResultReceipt, error), extra ...api.ObjectWrite) func() api.CleanupReceipt {
	t.Helper()
	lane, err := f.State.Lane(context.Background(), f.Execution, f.Reservation.Target)
	if err != nil || lane.State != "abandoned" && lane.State != "merged" || lane.Cleaned {
		t.Fatal("released cleanup requires its real terminal decision", err)
	}
	f.Lane = lane
	scene := f.prepareCleanupEnded(t, produce, false, true, nil, extra...)
	return func() api.CleanupReceipt { return scene.Collect(t) }
}

// ArchiveEnded uses measured filesystem input for archive/restore components.
// The caller must first end/stop the actual life. Native process and withdrawal
// observations remain explicit fixtures; the store and archive worker are real.
func (f *Fixture) ArchiveEnded(t testing.TB, produce func(context.Context, api.Scope, api.WorkerPrincipal) (api.WorkerResultReceipt, error), snapshot archivejob.Snapshot) *CleanupRun {
	t.Helper()
	var err error
	f.Lane, err = f.State.Lane(context.Background(), f.Execution, f.Reservation.Target)
	if err != nil || f.Lane.State != "verifying" {
		t.Fatal("archive fixture requires its committed ended life", err)
	}
	return f.prepareCleanupEnded(t, produce, true, false, &snapshot)
}

func (f *Fixture) prepareCleanupEnded(t testing.TB, produce func(context.Context, api.Scope, api.WorkerPrincipal) (api.WorkerResultReceipt, error), dirty, released bool, measured *archivejob.Snapshot, extra ...api.ObjectWrite) *CleanupRun {
	t.Helper()
	ctx := context.Background()
	target := f.Reservation.Target
	zero, exit := uint64(0), 0
	data := []byte("current workspace " + string(ID(t)))
	content := api.BlobRef{ID: ID(t), Class: "artifact", SHA256: Digest(data), Bytes: int64(len(data))}
	entries := []api.ObjectEntry{{Path: "current.txt", Kind: "file", Mode: 0600, Content: &content}}
	for _, object := range extra {
		ref := api.BlobRef{ID: object.ObjectKey, Class: object.Class, Bytes: int64(len(object.Bytes)), SHA256: object.SHA256}
		entries = append(entries, api.ObjectEntry{Path: "fixture/" + string(object.ObjectKey), Kind: "file", Mode: 0600, Content: &ref})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	tree := JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: entries})
	manifest := api.BlobRef{ID: ID(t), Class: "manifest", SHA256: Digest(tree), Bytes: int64(len(tree))}
	acl := api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, LifeID: target.LifeID, Audience: "owner", Generation: 1}
	native := &cleanNative{dirty: dirty, snapshot: archivejob.Snapshot{Freeze: archivejob.Freeze{Target: target, LaunchID: f.Lane.LaunchID, CancellationEpoch: f.Lane.CancellationEpoch, Snapshot: manifest, Writers: &zero, WritableExports: &zero, ObservedAt: cleanStamp()}, Objects: []api.ObjectWrite{{ObjectKey: content.ID, Class: content.Class, Bytes: data, SHA256: content.SHA256, Origin: "service", ACL: acl}, {ObjectKey: manifest.ID, Class: manifest.Class, Bytes: tree, SHA256: manifest.SHA256, Origin: "service", ACL: acl}}}}
	native.Requester = f.Human.Actor
	if measured != nil {
		freeze := native.snapshot.Freeze
		freeze.Snapshot = measured.Freeze.Snapshot
		native.snapshot = archivejob.Snapshot{Freeze: freeze, Objects: measured.Objects}
	}
	for _, object := range extra {
		object.ACL, object.Origin = acl, "service"
		native.snapshot.Objects = append(native.snapshot.Objects, object)
	}
	native.workspace = api.CleanupWorkspace{ID: f.Lane.Workspace.ID, RootID: ID(t), RepositoryID: ID(t), Target: target, Generation: 1, RootIdentity: "component-root", DirectoryIdentity: "component-directory", GitIdentity: "component-git", Branch: f.Lane.Workspace.Branch, Head: f.Lane.Workspace.Base}
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
	for _, event := range page.Events {
		if event.Kind == "lane.ended" {
			end = event
		}
	}
	if end.ID == "" {
		t.Fatal("archive lost the committed run end")
	}
	request := api.ArchiveRequest{Target: target, ExpectedGeneration: f.Lane.Generation}
	owner, caller, reserved := cleanOperation(t, f, "lane.archive", request)
	job, err := f.State.ReserveArchive(owner, caller, archivejob.Intent{Request: request, OperationID: reserved.Operation.ID, CancellationEpoch: f.Lane.CancellationEpoch, EndEventID: end.ID, EndSeq: end.Seq})
	if err != nil {
		t.Fatal("archive reservation failed", err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: job.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	workerID, err := f.State.ArchiveWorkerID(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal(err)
	}
	allocation := api.HelperLease{ID: ID(t), UID: f.Plan.Lease.UID + 2000, GID: f.Plan.Lease.GID + 2000, ContainmentID: ID(t), EndpointGeneration: 1}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: f.Deps.Config, Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: "/runtime/laneboss-worker.sock", ArtifactSHA256: job.Plan.Executable.SHA256, ServiceVersion: job.Plan.Executable.Version, Backend: "linux-bwrap-landlock", LaunchID: workerID, Target: &target, WorkerLeaseID: job.Lease.ID}
	handoff, err := f.State.ArchiveHandoff(ctx, f.Execution, claim, allocation, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	prepared := api.PreparedLaunch{ID: ID(t), GateID: ID(t), SpecSHA256: handoff.SpecSHA256, Target: target, ContainmentID: allocation.ContainmentID, EndpointGeneration: 1, ProcessGeneration: "component-boot:worker"}
	binding, err := f.State.BindArchiveWorker(ctx, f.Execution, claim, prepared)
	if err != nil {
		t.Fatal(err)
	}
	process := api.ProcessHandle{ID: workerID, Target: target, ContainmentID: allocation.ContainmentID, Generation: prepared.ProcessGeneration}
	if err := f.State.RecordArchiveProcess(ctx, f.Execution, claim, process); err != nil {
		t.Fatal(err)
	}
	facts := api.PeerFacts{HostUID: allocation.UID, HostGID: allocation.GID, HostPID: os.Getpid(), ProcessGeneration: "component-boot:connector", ContainmentID: allocation.ContainmentID}
	worker := api.Scope{Config: f.Deps.Config, Actor: binding.Record.Actor, LaunchID: workerID, EndpointGeneration: 1, PolicyGeneration: 1, Connection: &Connection{Identity: ID(t), Endpoint: endpoint, Verified: &Peer{FactsValue: facts}}, Frame: &Frame{Raw: []byte("component archive frame")}}
	principal, err := f.State.WorkerBinding(ctx, endpoint, facts)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := produce(ctx, worker, principal)
	if err != nil {
		t.Fatal("real archive producer failed", err)
	}
	observation := api.ProcessObservation{Handle: process, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "completed", ObservedAt: cleanStamp()}
	if _, err := f.State.CompleteArchive(ctx, f.Execution, claim, observation); err != nil {
		t.Fatal("archive completion failed", err)
	}
	raw, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: ack.Result.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var completion archivejob.Completion
	if err := api.DecodeObject(raw.Data, &completion); err != nil {
		t.Fatal(err)
	}
	decision := f.Intent(t, api.InternalLifecycleEffect)
	decision.CancellationEpoch = f.Lane.CancellationEpoch
	if !released {
		before := f.Lane.Generation
		f.Lane.Generation++
		f.Lane.State = "merged"
		decision.ID, decision.CauseOperationID, decision.CauseRequestID, decision.EffectID = ID(t), ID(t), ID(t), ID(t)
		event := f.Event(t, "lane.state", api.StateEvent{From: "verifying", To: "merged", Generation: f.Lane.Generation})
		event.OperationID, event.RequestID = decision.CauseOperationID, decision.CauseRequestID
		if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &decision, Writes: api.StateWrites{Lanes: []api.Lane{f.Lane}}, Events: []api.Event{event}, Compare: []api.Compare{{Kind: api.CompareLane, ID: target.LifeID, Generation: before}}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: target.LifeID, Epoch: f.Lane.CancellationEpoch}}}}); err != nil {
			t.Fatal("terminal decision failed", err)
		}
		releaseCause := decision
		releaseCause.ID, releaseCause.Kind, releaseCause.CauseOperationID, releaseCause.CauseRequestID, releaseCause.EffectID = ID(t), api.InternalHelperRelease, ID(t), ID(t), ID(t)
		released := f.Observation(t, "exited").Observation
		releaseEffect := api.Effect{ID: releaseCause.EffectID, OperationID: releaseCause.CauseOperationID, Context: &releaseCause, HelperRelease: &api.HelperReleaseRequest{Cause: releaseCause, LeaseID: f.Plan.Lease.ID, Observation: released}}
		if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &releaseCause, Effects: []api.Effect{releaseEffect}}); err != nil {
			t.Fatal(err)
		}
		releaseClaim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: releaseEffect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: Expiry()})
		if err != nil {
			t.Fatal(err)
		}
		release := api.ReleaseReceipt{ID: ID(t), LeaseID: f.Plan.Lease.ID, ContainmentID: f.Plan.Lease.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: releaseEffect.OperationID, EffectID: releaseEffect.ID, Quiescence: released, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: released.ObservedAt}
		if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: releaseEffect.ID, ClaimID: releaseClaim.ClaimID, ExpectedGeneration: releaseClaim.Record.Generation, Status: "succeeded", Release: &release}); err != nil {
			t.Fatal(err)
		}
	}
	scene := &CleanupRun{Archive: completion.Receipt, Workspace: native, fixture: f, native: native}
	scene.Effect = scene.Request(t)
	return scene
}

// Request reserves a fresh original operation after an explicit native repair.
// It does not reclaim or rewrite a previously refused effect.
func (r *CleanupRun) Request(t testing.TB) api.Effect {
	t.Helper()
	f, ctx := r.fixture, context.Background()
	target := f.Reservation.Target
	var err error
	f.Lane, err = f.State.Lane(ctx, f.Execution, target)
	if err != nil {
		t.Fatal(err)
	}
	clean := api.CleanRequest{Target: target, ExpectedGeneration: f.Lane.Generation, ArchiveReceiptID: r.Archive.ID}
	cleanCtx, cleanScope, cleanReceipt := cleanOperation(t, f, "lane.clean", clean)
	cause := f.Intent(t, api.InternalLifecycleEffect)
	cause.ID, cause.CauseOperationID, cause.CauseRequestID, cause.EffectID = ID(t), cleanReceipt.Operation.ID, cleanScope.Request.RequestID, ID(t)
	// This is a new cleanup operation after any terminal stop, rather than
	// a replay of the original launch reservation's cancellation epoch.
	cause.CancellationEpoch = f.Lane.CancellationEpoch
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Clean: &clean}
	if _, err := f.State.Transact(cleanCtx, api.Transaction{Scope: cleanScope, Effects: []api.Effect{effect}, Reply: &api.RPCReply{Result: JSON(t, api.Operation{ID: cleanReceipt.Operation.ID, Status: "pending"})}, Compare: []api.Compare{{Kind: api.CompareLane, ID: target.LifeID, Generation: f.Lane.Generation}}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: target.LifeID, Epoch: f.Lane.CancellationEpoch}}}}); err != nil {
		t.Fatal(err)
	}
	return effect
}

func (r *CleanupRun) Collect(t testing.TB) api.CleanupReceipt {
	t.Helper()
	f, native, ctx := r.fixture, r.native, context.Background()
	cleanClaim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: r.Effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	collect := func() api.CleanupReceipt {
		job, err := f.State.BeginCleanup(ctx, f.Execution, cleanClaim)
		if err != nil {
			t.Fatal(err)
		}
		inventory, err := f.State.CleanupInventory(ctx, f.Execution, job)
		if err != nil {
			t.Fatal(err)
		}
		objects, err := f.State.CollectCleanupObjects(ctx, f.Execution, job, inventory)
		if err != nil {
			t.Fatal(err)
		}
		before, err := native.ReadCleanupWorkspace(ctx, job)
		if err != nil {
			t.Fatal(err)
		}
		native.removed = true
		after, err := native.ReadCleanupWorkspace(ctx, job)
		if err != nil {
			t.Fatal(err)
		}
		native.removal = api.WorkspaceRemoval{IntentID: job.Intent.ID, ClaimID: job.Claim.ClaimID, Action: "remove_clean", Before: before, After: after, Unforced: true, Synced: true}
		receipt, err := f.State.RetainCleanupReceipt(ctx, f.Execution, job, api.CleanupReceipt{ID: ID(t), IntentID: job.Intent.ID, ClaimID: job.Claim.ClaimID, InventoryID: inventory.ID, Objects: objects, Workspace: native.removal})
		if err != nil {
			t.Fatal(err)
		}
		verified, err := api.VerifyCleanup(ctx, f.State.CleanupReadbacks(f.Execution), job, inventory, receipt, f.Deps.Clock)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.State.CompleteCleanup(ctx, f.Execution, job, verified); err != nil {
			t.Fatal(err)
		}
		f.Lane, err = f.State.Lane(ctx, f.Execution, r.Effect.Context.Target)
		if err != nil || !f.Lane.Cleaned {
			t.Fatal("collection did not commit cleaned lane", err)
		}
		return receipt
	}
	return collect()
}
