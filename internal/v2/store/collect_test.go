//go:build linux

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type collectNative struct {
	workspace api.CleanupWorkspace
	journal   api.WorkspaceRemoval
	dirty     bool
	unknown   bool
	removed   bool
	reads     int
	corrupt   bool
}

func (n *collectNative) ResolveCleanupWorkspace(ctx context.Context, target api.LifeRef, id api.ID) (api.CleanupWorkspace, error) {
	if err := ctx.Err(); err != nil {
		return api.CleanupWorkspace{}, err
	}
	if target != n.workspace.Target || id != n.workspace.ID {
		return api.CleanupWorkspace{}, errors.New("fixture workspace selector changed")
	}
	return n.workspace, nil
}
func (n *collectNative) ReadWorkspaceRemoval(ctx context.Context, job api.CleanupJob) (api.WorkspaceRemoval, error) {
	if err := ctx.Err(); err != nil {
		return api.WorkspaceRemoval{}, err
	}
	if job.Intent.Workspace != n.workspace || job.Intent.ID != n.journal.IntentID || job.Claim.ClaimID != n.journal.ClaimID {
		return api.WorkspaceRemoval{}, errors.New("fixture removal journal selected another job or claim")
	}
	return n.journal, nil
}
func (n *collectNative) ReadCleanupWorkspace(ctx context.Context, job api.CleanupJob) (api.WorkspaceReadback, error) {
	if err := ctx.Err(); err != nil {
		return api.WorkspaceReadback{}, err
	}
	if job.Intent.Workspace != n.workspace || api.ValidateCleanupJob(job, time.Now()) != nil {
		return api.WorkspaceReadback{}, errors.New("fixture workspace read selected another job")
	}
	n.reads++
	id, err := wire.NewID()
	if err != nil {
		return api.WorkspaceReadback{}, err
	}
	w := n.workspace
	r := api.WorkspaceReadback{ID: id, WorkspaceID: w.ID, RootIdentity: w.RootIdentity, GitIdentity: w.GitIdentity, ObservedAt: archStamp()}
	if n.removed {
		r.WorktreeState, r.BranchState = "absent", "absent"
	} else {
		d := n.dirty
		r.WorktreeState, r.BranchState, r.DirectoryIdentity, r.Head, r.Dirty = "present", "present", w.DirectoryIdentity, w.Head, &d
		if n.unknown {
			r.Dirty = nil
		}
	}
	if n.corrupt {
		r.WorktreeState = "unknown"
	}
	return r, nil
}
func (n *collectNative) remove(t *testing.T, job api.CleanupJob) {
	t.Helper()
	before, err := n.ReadCleanupWorkspace(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	n.removed = true
	after, err := n.ReadCleanupWorkspace(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	n.journal = api.WorkspaceRemoval{IntentID: job.Intent.ID, ClaimID: job.Claim.ClaimID, Action: "remove_clean", Before: before, After: after, Unforced: true, Synced: true}
}

type collectFixture struct {
	arch      *archFixture
	job       api.CleanupJob
	inventory api.CleanupInventory
	native    *collectNative
	scratch   api.BlobRef
}

func newCollect(t *testing.T) *collectFixture {
	t.Helper()
	return buildCollect(t, 0)
}

func buildCollect(t *testing.T, extra int) *collectFixture {
	t.Helper()
	f := newArch(t)
	ref := f.append(t, f.tar)
	f.result(t, ref, f.tar)
	zero, exit := uint64(0), 0
	observation := api.ProcessObservation{Handle: f.record.Process, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "completed", ObservedAt: archStamp()}
	if _, err := f.s.CompleteArchive(context.Background(), f.executor, f.record.Claim, observation); err != nil {
		t.Fatal(err)
	}
	var archived archiveRecord
	if err := storedProjection(context.Background(), f.s.db, "archive_job", f.record.Job.Intent.OperationID, &archived); err != nil {
		t.Fatal(err)
	}
	var completed archivejob.Completion
	if err := api.DecodeObject(archived.Ack.Submission.Result, &completed); err != nil {
		t.Fatal(err)
	}
	lane := f.record.Lane
	lane.State = "merged"
	lane.Generation++
	fixtureProjection(t, f.s, "lane", lane.LifeID, lane.Generation, lane)
	request := testRequest(t, "lane.clean", api.CleanRequest{Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, ExpectedGeneration: lane.Generation, ArchiveReceiptID: completed.Receipt.ID})
	scope := api.Scope{Config: f.deps.Config, Actor: f.record.Scope.Actor, Request: request, PolicyGeneration: 1, EndpointGeneration: 1, Connection: &scopeConnection{id: testID(t), binding: api.InstalledBinding{Config: f.deps.Config, Class: api.EndpointHuman, EndpointGeneration: 1}, peer: &scopePeer{}}, Frame: &archFrame{raw: archJSON(t, request)}}
	receipt, _, err := f.s.ReserveMutation(context.Background(), api.RequestReservation{Scope: scope, RawRequest: archJSON(t, request), Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(timeFormat))})
	if err != nil {
		t.Fatal(err)
	}
	cause := api.InternalIntent{ID: testID(t), Kind: api.InternalLifecycleEffect, Config: f.deps.Config, Actor: f.executor.Actor, RequestedBy: scope.Actor, CauseOperationID: receipt.Operation.ID, CauseRequestID: request.RequestID, EffectID: testID(t), Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, CancellationEpoch: lane.CancellationEpoch}
	var clean api.CleanRequest
	if err := api.DecodeObject(request.Params, &clean); err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertLaunchEffect(context.Background(), tx, api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Clean: &clean}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	// Set up the already delivered pending Operation reply. Authorization and
	// lifecycle preflight are outside this SQLite collector component fixture.
	op := receipt.Operation
	op.LifeID, op.Run = lane.LifeID, lane.Run
	body := archJSON(t, op)
	receipt.Operation, receipt.Reply = op, &api.RPCReply{Result: body}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"UPDATE operations SET data=? WHERE id=?", []any{body, string(op.ID)}},
		{"INSERT INTO receipts VALUES(?,?,?,?,?,?)", []any{principal(scope), string(request.Method), string(request.IdempotencyKey), string(request.RequestSHA256), archJSON(t, request), body}},
		{"INSERT INTO replies VALUES(?,?,?,?)", []any{principal(scope), string(request.Method), string(request.IdempotencyKey), archJSON(t, storedReceipt{Config: f.deps.Config, Receipt: receipt})}},
		{"DELETE FROM reservations WHERE operation_id=?", []any{string(op.ID)}},
	} {
		if _, err := tx.ExecContext(context.Background(), q.sql, q.args...); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	cleanDeadline := f.record.Grants.ExpiresAt
	if extra > 0 {
		// This scale fixture measures byte/count bounds, with an explicit finite
		// authority window for its SQL readbacks rather than the tiny base job.
		var source api.GrantSet
		if err := storedProjection(context.Background(), f.s.db, "grants", lane.GrantSetID, &source); err != nil {
			t.Fatal(err)
		}
		source.ExpiresAt = api.Timestamp(time.Now().Add(10 * time.Minute).UTC().Format(timeFormat))
		fixtureProjection(t, f.s, "grants", source.ID, source.Generation, source)
		cleanDeadline = source.ExpiresAt
	}
	claim, err := f.s.ClaimEffect(context.Background(), f.executor, api.EffectClaimRequest{EffectID: cause.EffectID, ExpectedGeneration: 1, ClaimantID: f.executor.Actor.ID, Deadline: cleanDeadline})
	if err != nil {
		t.Fatal(err)
	}
	w := api.CleanupWorkspace{ID: lane.Workspace.ID, RootID: testID(t), RepositoryID: testID(t), Target: cause.Target, Generation: 1, RootIdentity: "component-root", DirectoryIdentity: "component-directory", GitIdentity: "component-git", Branch: "lane/" + string(lane.LifeID), Head: strings.Repeat("a", 40)}
	release := api.ReleaseReceipt{ID: testID(t), LeaseID: testID(t), ContainmentID: observation.Handle.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: testID(t), EffectID: testID(t), Quiescence: observation, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: archStamp()}
	job := api.CleanupJob{Intent: api.CleanupIntent{ID: testID(t), Cause: cause, ExpectedGeneration: lane.Generation, Decision: lane.State, Archive: completed.Receipt, ArchiveRequest: archived.Job.Intent.Request, Release: release, Workspace: w}, Claim: claim}
	if err := api.ValidateCleanupJob(job, time.Now()); err != nil {
		t.Fatal("collector component job", err)
	}
	fixtureProjection(t, f.s, "collection", cause.EffectID, 1, collectionRecord{Intent: job.Intent})
	native := &collectNative{workspace: w}
	f.s.deps.CleanupNative = native
	f.deps.CleanupNative = native
	tx, err = f.s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	scratch, err := f.s.archiveBytes(context.Background(), tx, f.record, "artifact", []byte("unreferenced transient component bytes"))
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	for n := 0; n < extra; n++ {
		if _, err := f.s.archiveBytes(context.Background(), tx, f.record, "artifact", []byte("large owned transient "+string(testID(t)))); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	inventory, err := f.s.CleanupInventory(context.Background(), f.executor, job)
	if err != nil {
		t.Fatal("real store owned inventory", err)
	}
	return &collectFixture{arch: f, job: job, inventory: inventory, native: native, scratch: scratch}
}

func (f *collectFixture) collect(t *testing.T) api.CleanupReceipt {
	t.Helper()
	s := f.arch.s
	objects, err := s.CollectCleanupObjects(context.Background(), f.arch.executor, f.job, f.inventory)
	if err != nil {
		t.Fatal("real object collection", err)
	}
	f.native.remove(t, f.job)
	receipt := api.CleanupReceipt{ID: testID(t), IntentID: f.job.Intent.ID, ClaimID: f.job.Claim.ClaimID, InventoryID: f.inventory.ID, Objects: objects, Workspace: f.native.journal}
	retained, err := s.RetainCleanupReceipt(context.Background(), f.arch.executor, f.job, receipt)
	if err != nil {
		t.Fatal("real retained cleanup receipt", err)
	}
	return retained
}

func TestCollectSQLReadback(t *testing.T) {
	f := newCollect(t)
	receipt := f.collect(t)
	removed := false
	for _, result := range receipt.Objects {
		if result.ObjectID == f.scratch.ID {
			removed = result.Action == "remove" && result.Before.State == "present" && result.After.State == "absent"
		}
	}
	if !removed {
		t.Fatal("owned unreferenced SQL bytes were not removed and read back")
	}
	if _, _, err := objectRow(context.Background(), f.arch.s.db, f.scratch.ID); !absent(err) {
		t.Fatal("collected object remains in the SQL namespace", err)
	}
	meta, raw, err := objectRow(context.Background(), f.arch.s.db, receipt.Manifest.ID)
	body, _, be := api.CleanupReceiptBytes(receipt)
	if err != nil || be != nil || meta.Ref != receipt.Manifest || string(raw) != string(body) {
		t.Fatal("cleanup receipt lacks actual retained bytes", err, be)
	}
	reads := map[api.ID]int{}
	ctx := context.WithValue(context.Background(), objectVerificationKey{}, func(id api.ID, _ int64) { reads[id]++ })
	if _, err := api.VerifyCleanup(ctx, f.arch.s.CleanupReadbacks(f.arch.executor), f.job, f.inventory, receipt, f.arch.s.deps.Clock); err != nil {
		t.Fatal("independent cleanup readbacks failed", err)
	}
	if reads[receipt.Manifest.ID] == 0 || reads[f.inventory.Manifest.ID] == 0 {
		t.Fatal("cleanup verification did not reopen its retained manifests")
	}
}

func TestCollectDirtyGate(t *testing.T) {
	f := newCollect(t)
	f.native.unknown = true
	results, err := f.arch.s.CollectCleanupObjects(context.Background(), f.arch.executor, f.job, f.inventory)
	if err == nil {
		t.Fatal("unknown workspace state crossed the collection gate")
	}
	expectCode(t, err, api.CodeConflict)
	if len(results) != 0 || f.native.removed {
		t.Fatal("unknown workspace state reached the removal boundary")
	}
	if _, _, err := objectRow(context.Background(), f.arch.s.db, f.scratch.ID); err != nil {
		t.Fatal("unknown workspace state changed the owned object namespace", err)
	}
}

func TestCollectDirtyReachesObjectJournal(t *testing.T) {
	f := newCollect(t)
	f.native.dirty = true
	results, err := f.arch.s.CollectCleanupObjects(context.Background(), f.arch.executor, f.job, f.inventory)
	if err != nil {
		t.Fatal("dirty workspace was refused before its native retention decision", err)
	}
	if len(results) != len(f.inventory.Objects) || f.native.removed {
		t.Fatal("dirty collection crossed the workspace removal boundary")
	}
	if _, _, err := objectRow(context.Background(), f.arch.s.db, f.scratch.ID); err == nil {
		t.Fatal("eligible object journal was not collected before native retention")
	}
}

func TestCollectGraphGate(t *testing.T) {
	f := newCollect(t)
	fixtureProjection(t, f.arch.s, "new-reference", testID(t), 1, f.scratch)
	if _, err := f.arch.s.CollectCleanupObjects(context.Background(), f.arch.executor, f.job, f.inventory); err == nil {
		t.Fatal("changed reference graph allowed collection")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
}

func TestCollectFreshGate(t *testing.T) {
	f := newCollect(t)
	receipt := f.collect(t)
	f.native.corrupt = true
	if _, err := api.VerifyCleanup(context.Background(), f.arch.s.CleanupReadbacks(f.arch.executor), f.job, f.inventory, receipt, f.arch.s.deps.Clock); err == nil {
		t.Fatal("changed workspace namespace passed independent cleanup readback")
	}
}

func TestCollectAtomicGate(t *testing.T) {
	f := newCollect(t)
	receipt := f.collect(t)
	s := f.arch.s
	if _, err := s.CompleteCleanup(context.Background(), f.arch.executor, f.job, api.VerifiedCleanup{}); err == nil {
		t.Fatal("zero cleanup verification marked the lane cleaned")
	}
	verified, err := api.VerifyCleanup(context.Background(), s.CleanupReadbacks(f.arch.executor), f.job, f.inventory, receipt, s.deps.Clock)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := s.CompleteCleanup(context.Background(), f.arch.executor, f.job, verified)
	if err != nil || commit.Operation.Status != "succeeded" {
		t.Fatal("verified cleanup atomic completion", err)
	}
	var lane api.Lane
	if err := storedProjection(context.Background(), s.db, "lane", f.job.Intent.Cause.Target.LifeID, &lane); err != nil || !lane.Cleaned || lane.Generation != f.job.Intent.ExpectedGeneration+1 {
		t.Fatal("cleanup did not atomically publish its fenced lane state", err)
	}
	again, err := s.CompleteCleanup(context.Background(), f.arch.executor, f.job, verified)
	if err != nil || !again.Replayed {
		t.Fatal("cleanup lost-reply retry repeated its work", err)
	}
}

func TestCollectUnowned(t *testing.T) {
	f := newCollect(t)
	s, ctx := f.arch.s, context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	unowned := f.arch.record
	unowned.Lane.LifeID = ""
	refs := []api.BlobRef{}
	for _, raw := range [][]byte{[]byte("abc"), {}} {
		ref, err := s.archiveBytes(ctx, tx, unowned, "artifact", raw)
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
	}
	if _, err := s.archiveBytes(ctx, tx, f.arch.record, "report", archJSON(t, refs)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	f.inventory, err = s.CleanupInventory(ctx, f.arch.executor, f.job)
	if err != nil {
		t.Fatal(err)
	}
	receipt := f.collect(t)
	var want api.UnownedRetained
	found := map[api.ID]bool{}
	for _, result := range receipt.Objects {
		if result.Reason == "unowned" {
			want.Objects++
			want.Bytes += result.Before.Bytes
			found[result.ObjectID] = true
		}
	}
	for _, ref := range refs {
		meta, raw, err := objectRow(ctx, s.db, ref.ID)
		if err != nil || !found[ref.ID] || meta.Ref != ref || int64(len(raw)) != ref.Bytes {
			t.Fatal("unowned object was omitted or lost its retained bytes", err)
		}
	}
	verified, err := api.VerifyCleanup(ctx, s.CleanupReadbacks(f.arch.executor), f.job, f.inventory, receipt, s.deps.Clock)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := os.CreateTemp(t.TempDir(), "journal")
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = journal
	defer func() {
		os.Stderr = stderr
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := s.CompleteCleanup(ctx, f.arch.executor, f.job, api.VerifiedCleanup{}); err == nil {
		t.Fatal("unverified cleanup completed")
	}
	if _, err := s.CompleteCleanup(ctx, f.arch.executor, f.job, verified); err != nil {
		t.Fatal(err)
	}
	again, err := s.CompleteCleanup(ctx, f.arch.executor, f.job, verified)
	if err != nil || !again.Replayed {
		t.Fatal("cleanup replay repeated completion", err)
	}
	os.Stderr = stderr
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.life_id')=? AND json_extract(data,'$.kind')='lane.cleaned' ORDER BY seq DESC LIMIT 1", string(f.job.Intent.Cause.Target.LifeID)).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var event api.Event
	var body api.CleanEvent
	if err := api.DecodeObject(raw, &event); err != nil {
		t.Fatal(err)
	}
	if err := api.DecodeObject(event.Payload, &body); err != nil {
		t.Fatal(err)
	}
	if body.UnownedRetained != want {
		t.Errorf("cleaned event lost measured unowned totals: got %+v, want %+v", body.UnownedRetained, want)
	}
	if _, err := journal.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(journal)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var line struct {
		Event   string `json:"event"`
		Life    api.ID `json:"life"`
		Objects int    `json:"objects"`
		Bytes   int64  `json:"bytes"`
	}
	if len(lines) != 1 || json.Unmarshal(lines[0], &line) != nil || line.Event != "cleanup_unowned_retained" ||
		line.Life != event.LifeID || line.Objects != want.Objects || line.Bytes != want.Bytes {
		t.Errorf("completed clean must journal its measured totals once: %q", data)
	}
}

func TestCollectTombstone(t *testing.T) {
	f := newCollect(t)
	f.collect(t)
	tx, err := f.arch.s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := put(context.Background(), tx, "late-reference", testID(t), 1, f.scratch); err == nil {
		t.Fatal("collected object acquired a new retained reference")
	}
	if err := rejectCollectedKey(context.Background(), tx, f.scratch.ID); err == nil {
		t.Fatal("collected object ID was reusable")
	}
}

func TestCollectTriggerClosed(t *testing.T) {
	f := newCollect(t)
	if _, err := f.arch.s.db.Exec("DELETE FROM objects WHERE id=?", string(f.scratch.ID)); err == nil {
		t.Fatal("SQL removal bypassed the protected deletion journal")
	}
	var count int
	if err := f.arch.s.db.QueryRow("SELECT count(*) FROM objects WHERE id=?", string(f.scratch.ID)).Scan(&count); err != nil || count != 1 {
		t.Fatal("refused SQL deletion changed owned bytes", err)
	}
}

func TestCollectDelete(t *testing.T) {
	f := newCollect(t)
	results, err := f.arch.s.CollectCleanupObjects(context.Background(), f.arch.executor, f.job, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	removed := false
	for _, r := range results {
		if r.ObjectID == f.scratch.ID {
			removed = r.Action == "remove" && r.After.State == "absent"
		}
	}
	if !removed {
		t.Fatal("owned transient object deletion was omitted")
	}
}

func TestCollectLegacyTrigger(t *testing.T) {
	s, deps := testStore(t)
	// Reproduce the exact previous schema in this disposable component store.
	if _, err := s.db.Exec("DROP TRIGGER objects_no_delete; CREATE TRIGGER objects_no_delete BEFORE DELETE ON objects\n BEGIN SELECT RAISE(ABORT, 'immutable objects'); END;"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(deps)
	if err != nil {
		t.Fatal("known legacy object trigger was not upgraded", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := reopened.verifySchema(context.Background()); err != nil {
		t.Fatal("upgraded object trigger lost the exact protected schema", err)
	}
}

func TestCollectLegacyRefs(t *testing.T) {
	f := newArch(t)
	raw := []byte("legacy bytes " + string(testID(t)))
	ref := api.BlobRef{ID: testID(t), Class: "artifact", SHA256: testDigest(raw), Bytes: int64(len(raw))}
	meta := api.ObjectMetadata{Ref: ref, ACL: f.s.archiveACL(f.record), Origin: "service", SourceOperationID: f.record.Job.Intent.OperationID, CommittedAt: archStamp()}
	// Old schema bytes have no retained InputRefs observation. Do not silently
	// backfill a zero-reference claim while reading that historic namespace.
	if _, err := f.s.db.Exec("INSERT INTO objects VALUES(?,?,?)", string(ref.ID), archJSON(t, meta), raw); err != nil {
		t.Fatal(err)
	}
	job := api.CleanupJob{Intent: api.CleanupIntent{Cause: api.InternalIntent{CauseOperationID: testID(t), Target: f.record.Job.Intent.Request.Target}, Archive: api.ArchiveReceipt{ID: f.record.Input.ReceiptID}}}
	objects, _, _, err := f.s.collectionGraph(context.Background(), job, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, object := range objects {
		if object.Ref.ID == ref.ID {
			found = true
			if object.Role != "unknown" {
				t.Fatal("legacy reference uncertainty was relabeled transient")
			}
		}
	}
	if !found {
		t.Fatal("legacy owned bytes disappeared from the complete inventory")
	}
}

func TestBlobEdgesStable(t *testing.T) {
	left := api.BlobRef{ID: testID(t), Class: "artifact", SHA256: testDigest([]byte("left")), Bytes: 4}
	right := api.BlobRef{ID: testID(t), Class: "artifact", SHA256: testDigest([]byte("right")), Bytes: 5}
	a := archJSON(t, map[string]any{"z": left, "a": right})
	b := archJSON(t, map[string]any{"first": right, "second": left})
	if !sameValue(blobEdges(a), blobEdges(b)) || len(blobEdges(a)) != 2 {
		t.Fatal("reference graph depends on JSON key traversal order")
	}
	if len(blobEdges(json.RawMessage(`{"id":"a-label"}`))) != 0 {
		t.Fatal("an object label manufactured a BlobRef edge")
	}
}

// Box 102-103: the helper's data-roots evidence is referenced from the materialize input and launch spec
// but kept by the helper, so it is no store object; any other absent reference still refuses the graph.
func TestCollectHelperRootsEvidence(t *testing.T) {
	for _, mode := range []string{"materialize", "launch", "report", "lane_report", "lane_input", "lane_spec", "prefix", "class", "stored"} {
		t.Run(mode, func(t *testing.T) {
			f := newArch(t)
			evidence := []byte("helper roots evidence")
			missing := api.BlobRef{ID: api.ID("roots-" + string(testID(t))), Class: "manifest", SHA256: testDigest(evidence), Bytes: int64(len(evidence))}
			class, origin := "materialize_input", "service"
			switch mode {
			case "launch", "lane_spec":
				class = "launch_spec"
			case "report", "lane_report":
				class = "report"
			case "prefix":
				missing.ID = testID(t)
			case "class":
				missing.Class = "artifact"
			}
			if strings.HasPrefix(mode, "lane_") {
				origin = "lane"
			}
			raw := archJSON(t, map[string]any{"storage": map[string]any{"Evidence": missing}})
			ref := api.BlobRef{ID: testID(t), Class: class, SHA256: testDigest(raw), Bytes: int64(len(raw))}
			meta := api.ObjectMetadata{Ref: ref, ACL: f.s.archiveACL(f.record), Origin: origin, SourceOperationID: f.record.Job.Intent.OperationID, CommittedAt: archStamp()}
			if origin == "lane" {
				meta.ACL.Owner = api.Actor{Kind: "lane", ID: testID(t), LifeID: f.record.Lane.LifeID}
			}
			if _, err := f.s.db.Exec("INSERT INTO objects VALUES(?,?,?)", string(ref.ID), archJSON(t, meta), raw); err != nil {
				t.Fatal(err)
			}
			if mode == "stored" {
				meta.Ref = missing
				// Reach this foreign object only through the outbound edge;
				// target ownership must not mask a wrongly skipped stored ref.
				meta.ACL.LifeID = testID(t)
				if _, err := f.s.db.Exec("INSERT INTO objects VALUES(?,?,?)", string(missing.ID), archJSON(t, meta), evidence); err != nil {
					t.Fatal(err)
				}
			}
			job := api.CleanupJob{Intent: api.CleanupIntent{Cause: api.InternalIntent{CauseOperationID: testID(t), Target: f.record.Job.Intent.Request.Target}, Archive: api.ArchiveReceipt{ID: f.record.Input.ReceiptID}}}
			objects, _, _, err := f.s.collectionGraph(context.Background(), job, nil)
			if mode == "materialize" || mode == "launch" || mode == "stored" {
				if err != nil {
					t.Fatal("helper roots control failed", err)
				}
				found := false
				for _, object := range objects {
					found = found || object.Ref == missing
				}
				if found != (mode == "stored") {
					t.Fatal("stored roots reference was not followed exactly")
				}
				return
			}
			expectCode(t, err, api.CodeIntegrity)
			if !strings.Contains(err.Error(), "missing referenced object") {
				t.Fatal("foreign helper edge missed the graph refusal", err)
			}
		})
	}
}

func TestCollectRootsJournal(t *testing.T) {
	f := newArch(t)
	evidence := []byte("shared helper evidence")
	missing := api.BlobRef{ID: api.ID("roots-" + string(testID(t))), Class: "manifest", SHA256: testDigest(evidence), Bytes: int64(len(evidence))}
	from := map[api.ID]bool{}
	for _, class := range []string{"materialize_input", "launch_spec"} {
		raw := archJSON(t, map[string]any{"storage": map[string]any{"Evidence": missing}})
		ref := api.BlobRef{ID: testID(t), Class: class, SHA256: testDigest(raw), Bytes: int64(len(raw))}
		meta := api.ObjectMetadata{Ref: ref, ACL: f.s.archiveACL(f.record), Origin: "service", SourceOperationID: f.record.Job.Intent.OperationID, CommittedAt: archStamp()}
		if _, err := f.s.db.Exec("INSERT INTO objects VALUES(?,?,?)", string(ref.ID), archJSON(t, meta), raw); err != nil {
			t.Fatal(err)
		}
		from[ref.ID] = true
	}
	job := api.CleanupJob{Intent: api.CleanupIntent{Cause: api.InternalIntent{CauseOperationID: testID(t), Target: f.record.Job.Intent.Request.Target}, Archive: api.ArchiveReceipt{ID: f.record.Input.ReceiptID}}}
	journal, err := os.CreateTemp(t.TempDir(), "roots-journal")
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = journal
	defer func() {
		os.Stderr = stderr
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, _, _, err := f.s.collectionGraph(context.Background(), job, nil); err != nil {
		t.Fatal(err)
	}
	os.Stderr = stderr
	if _, err := journal.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(journal)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	if len(lines) != len(from) {
		t.Fatal("shared helper ref lost an embedding edge")
	}
	for _, line := range lines {
		var event struct {
			Event string `json:"event"`
			Life  api.ID `json:"life"`
			From  api.ID `json:"from"`
			Ref   api.ID `json:"ref"`
		}
		if err := json.Unmarshal(line, &event); err != nil || event.Event != "cleanup_graph_skipped_helper_ref" || event.Life != job.Intent.Cause.Target.LifeID || event.Ref != missing.ID || !from[event.From] {
			t.Fatal("helper journal changed or repeated an edge", err)
		}
		delete(from, event.From)
	}
}
