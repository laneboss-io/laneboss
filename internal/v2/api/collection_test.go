package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Component data and journals only; never an installed collector or native proof.
type collectionClock struct{ at time.Time }

func (c *collectionClock) Now() time.Time { return c.at }

func collectionBlob(id ID, class string, data []byte) BlobRef {
	sum := sha256.Sum256(data)
	return BlobRef{ID: id, Class: class, Bytes: int64(len(data)), SHA256: Digest(hex.EncodeToString(sum[:]))}
}
func collectionInventory(t *testing.T, i *CleanupInventory) []byte {
	t.Helper()
	body, digest, err := CleanupInventoryBytes(*i)
	if err != nil {
		t.Fatal(err)
	}
	i.Manifest = BlobRef{ID: "inventory-blob", Class: "manifest", Bytes: int64(len(body)), SHA256: digest}
	return body
}
func collectionReceipt(t *testing.T, r *CleanupReceipt) []byte {
	t.Helper()
	body, digest, err := CleanupReceiptBytes(*r)
	if err != nil {
		t.Fatal(err)
	}
	r.Manifest = BlobRef{ID: "receipt-blob", Class: "manifest", Bytes: int64(len(body)), SHA256: digest}
	return body
}

type collectionModel struct {
	job                               CleanupJob
	inventory                         CleanupInventory
	receipt                           CleanupReceipt
	blobs                             map[ID][]byte
	objects                           map[ID][]byte
	identities                        map[ID]string
	journals                          map[ID]ObjectDisposition
	workspaceJournal                  WorkspaceRemoval
	workspace                         WorkspaceReadback
	clock                             *collectionClock
	checks, reads, revokeAt, expireAt int
	rewindAt                          int
	objectReadIDs                     map[ID]ID
	err                               error
}

func (m *collectionModel) CheckCleanup(ctx context.Context, j CleanupJob, i CleanupInventory) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.checks++
	if !reflect.DeepEqual(j, m.job) || i.GraphGeneration != m.inventory.GraphGeneration || m.checks == m.revokeAt {
		return &Error{Code: CodeConflict, Owner: "lb-v2-service", Message: "cleanup authority changed"}
	}
	if m.checks == m.expireAt {
		m.clock.at = m.clock.at.Add(2 * time.Minute)
	}
	if m.checks == m.rewindAt {
		m.clock.at = m.clock.at.Add(-time.Second)
	}
	return nil
}
func (m *collectionModel) read(ref BlobRef, into any) error {
	if m.err != nil {
		return m.err
	}
	data, ok := m.blobs[ref.ID]
	if !ok || collectionBlob(ref.ID, ref.Class, data) != ref {
		return cleanupIntegrity("lb-v2-service", "fixture manifest readback differs")
	}
	return json.Unmarshal(data, into)
}
func (m *collectionModel) ReadCleanupInventory(_ context.Context, _ CleanupJob, id ID) (CleanupInventory, error) {
	var r CleanupInventory
	if id != m.inventory.ID {
		return r, cleanupIntegrity("lb-v2-service", "foreign inventory")
	}
	if err := m.read(m.inventory.Manifest, &r); err != nil {
		return r, err
	}
	r.Manifest = m.inventory.Manifest
	return r, nil
}
func (m *collectionModel) ReadCleanupReceipt(_ context.Context, _ CleanupJob, id ID) (CleanupReceipt, error) {
	var r CleanupReceipt
	if id != m.receipt.ID {
		return r, cleanupIntegrity("lb-v2-service", "foreign receipt")
	}
	if err := m.read(m.receipt.Manifest, &r); err != nil {
		return r, err
	}
	r.Manifest = m.receipt.Manifest
	return r, nil
}
func (m *collectionModel) ReadCleanupObjectResult(_ context.Context, _ CleanupJob, id ID) (ObjectDisposition, error) {
	r, ok := m.journals[id]
	if !ok {
		return r, cleanupIntegrity("lb-v2-service", "missing object journal")
	}
	return r, nil
}
func (m *collectionModel) ReadCleanupObject(_ context.Context, _ CleanupJob, o CleanupObject) (ObjectReadback, error) {
	m.reads++
	r := ObjectReadback{ID: ID("fresh-" + string(o.Ref.ID)), ObjectID: o.Ref.ID, RootID: o.RootID, RootIdentity: o.RootIdentity, State: "absent", ObservedAt: contractStamp(m.clock.Now())}
	if data, ok := m.objects[o.Ref.ID]; ok {
		ref := collectionBlob(o.Ref.ID, o.Ref.Class, data)
		r.State, r.Identity, r.SHA256, r.Bytes = "present", m.identities[o.Ref.ID], ref.SHA256, ref.Bytes
	}
	if id, ok := m.objectReadIDs[o.Ref.ID]; ok {
		r.ID = id
	}
	return r, nil
}
func (m *collectionModel) ReadWorkspaceRemoval(context.Context, CleanupJob) (WorkspaceRemoval, error) {
	return m.workspaceJournal, nil
}
func (m *collectionModel) ReadCleanupWorkspace(context.Context, CleanupJob) (WorkspaceReadback, error) {
	return m.workspace, nil
}

func collectionFixture(t *testing.T) (CleanupJob, CleanupInventory, CleanupReceipt, *collectionModel) {
	t.Helper()
	now := contractNow()
	zero := uint64(0)
	clean := false
	target := LifeRef{LifeID: "collected-life", Run: 2}
	cause := InternalIntent{ID: "clean-cause", Kind: InternalLifecycleEffect, Config: "demo", Actor: Actor{Kind: "service", ID: "collector"}, RequestedBy: Actor{Kind: "human", ID: "owner"}, CauseOperationID: "clean-operation", CauseRequestID: "clean-request", EffectID: "clean-effect", Target: target, CancellationEpoch: 3}
	archiveBytes := []byte("retained archive manifest bytes")
	archive := ArchiveReceipt{ID: "archive-receipt", LifeID: target.LifeID, Manifest: collectionBlob("archive-manifest", "manifest", archiveBytes), ArchiveSHA256: launchFixtureBlob("archive-bytes", "archive").SHA256, VerifiedAt: contractStamp(now.Add(-2 * time.Second)), StoreID: "archive-store"}
	archive.ReadBackSHA256 = archive.ArchiveSHA256
	release := ReleaseReceipt{ID: "release-receipt", LeaseID: "released-lease", ContainmentID: "containment", Backend: "linux-bwrap-landlock", OperationID: "release-operation", EffectID: "release-effect", LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: contractStamp(now.Add(-3 * time.Second)),
		Quiescence: ProcessObservation{Handle: ProcessHandle{ID: "old-process", Target: target, ContainmentID: "containment", Generation: "process-generation"}, State: "exited", Survivors: &zero, PromptStatus: "completed", ObservedAt: contractStamp(now.Add(-3 * time.Second))}}
	w := CleanupWorkspace{ID: "owned-workspace", RootID: "workspace-parent", RepositoryID: "owned-repository", Target: target, Generation: 4, RootIdentity: "parent-inode", DirectoryIdentity: "workspace-inode", GitIdentity: "git-admin-inode", Branch: "lane/collected-life", Head: strings.Repeat("a", 40)}
	intent := CleanupIntent{ID: "cleanup-intent", Cause: cause, ExpectedGeneration: 7, Decision: "abandoned", Archive: archive, ArchiveRequest: ArchiveRequest{Target: target, ExpectedGeneration: 7}, Release: release, Workspace: w}
	expiry := contractStamp(now.Add(time.Minute))
	effect := Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Clean: &CleanRequest{Target: target, ExpectedGeneration: 7, ArchiveReceiptID: archive.ID}}
	job := CleanupJob{Intent: intent, Claim: EffectLease{ClaimID: "cleanup-claim", ExpiresAt: expiry, Record: EffectRecord{Effect: effect, Generation: 2, State: EffectClaimed, ClaimID: "cleanup-claim", ClaimExpiresAt: expiry}}}
	i := CleanupInventory{ID: "owned-inventory", IntentID: intent.ID, Config: cause.Config, Target: target, ExpectedGeneration: 7, CancellationEpoch: 3, GraphGeneration: 5, Objects: []CleanupObject{}}
	r := CleanupReceipt{ID: "collection-receipt", IntentID: intent.ID, ClaimID: job.Claim.ClaimID, InventoryID: i.ID, Objects: []ObjectDisposition{}}
	m := &collectionModel{job: job, blobs: map[ID][]byte{}, objects: map[ID][]byte{}, identities: map[ID]string{}, journals: map[ID]ObjectDisposition{}, clock: &collectionClock{at: now}}
	rows := []struct {
		id, role, class, action, reason string
		foreign                         bool
		refs                            uint64
	}{
		{"scratch", "transient", "artifact", "remove", "unreferenced", false, 0},
		{"archive-manifest", "archive", "manifest", "retain", "archive", false, 0},
		{"capture", "capture", "capture", "retain", "capture", false, 0},
		{"input", "input", "task", "retain", "input", false, 0},
		{"report", "report", "report", "retain", "report", false, 0},
		{"event-payload", "event", "record", "retain", "event", false, 0},
		{"shared", "transient", "artifact", "retain", "referenced", false, 1},
		{"foreign", "transient", "artifact", "retain", "unowned", true, 0},
		{"history", "transient", "prompt", "retain", "history", false, 0},
	}
	for _, row := range rows {
		id := ID(row.id)
		data := []byte("actual component bytes for " + row.id)
		if id == archive.Manifest.ID {
			data = archiveBytes
		}
		o := CleanupObject{Ref: collectionBlob(id, row.class, data), RootID: "object-root", RootIdentity: "store-parent", Identity: "object-" + row.id, OwnerLifeID: target.LifeID, OwnershipGeneration: 1, Role: row.role, References: row.refs}
		if row.foreign {
			o.OwnerLifeID = "other-life"
		}
		i.Objects = append(i.Objects, o)
		m.identities[id] = o.Identity
		before := ObjectReadback{ID: ID("before-" + row.id), ObjectID: id, RootID: o.RootID, RootIdentity: o.RootIdentity, Identity: o.Identity, State: "present", SHA256: o.Ref.SHA256, Bytes: o.Ref.Bytes, ObservedAt: contractStamp(now.Add(-time.Second))}
		after := before
		after.ID = ID("after-" + row.id)
		after.ObservedAt = contractStamp(now)
		if row.action == "remove" {
			after.State, after.Identity, after.SHA256, after.Bytes = "absent", "", "", 0
		} else {
			m.objects[id] = data
		}
		result := ObjectDisposition{ObjectID: id, Action: row.action, Reason: row.reason, Before: before, After: after}
		r.Objects = append(r.Objects, result)
		m.journals[id] = result
	}
	before := WorkspaceReadback{ID: "workspace-before", WorkspaceID: w.ID, RootIdentity: w.RootIdentity, DirectoryIdentity: w.DirectoryIdentity, GitIdentity: w.GitIdentity, WorktreeState: "present", BranchState: "present", Head: w.Head, Dirty: &clean, ObservedAt: contractStamp(now.Add(-time.Second))}
	after := WorkspaceReadback{ID: "workspace-after", WorkspaceID: w.ID, RootIdentity: w.RootIdentity, GitIdentity: w.GitIdentity, WorktreeState: "absent", BranchState: "absent", ObservedAt: contractStamp(now)}
	r.Workspace = WorkspaceRemoval{IntentID: intent.ID, ClaimID: job.Claim.ClaimID, Action: "remove_clean", Before: before, After: after, Unforced: true, Synced: true}
	m.blobs["inventory-blob"] = collectionInventory(t, &i)
	m.blobs["receipt-blob"] = collectionReceipt(t, &r)
	m.inventory, m.receipt, m.workspaceJournal, m.workspace = i, cloneCleanupReceipt(r), r.Workspace, after
	m.workspace.ID = "workspace-fresh"
	return job, i, r, m
}

func TestCollectJob(t *testing.T) {
	for _, fault := range []string{"claim", "expiry", "state", "target", "generation", "epoch", "archive", "archive_run", "survivors", "workspace", "branch", "requester"} {
		t.Run(fault, func(t *testing.T) {
			j, _, _, _ := collectionFixture(t)
			if err := ValidateCleanupJob(j, contractNow()); err != nil {
				t.Fatal("valid cleanup job refused", err)
			}
			switch fault {
			case "claim":
				j.Claim.ClaimID = "foreign-claim"
			case "expiry":
				j.Claim.ExpiresAt = contractStamp(contractNow())
				j.Claim.Record.ClaimExpiresAt = j.Claim.ExpiresAt
			case "state":
				j.Intent.Decision = "accepted"
			case "target":
				j.Claim.Record.Effect.Clean.Target.Run++
			case "generation":
				j.Intent.ExpectedGeneration++
			case "epoch":
				j.Intent.Cause.CancellationEpoch++
			case "archive":
				j.Intent.Archive.ReadBackSHA256 = launchFixtureBlob("wrong-archive", "manifest").SHA256
			case "archive_run":
				j.Intent.ArchiveRequest.Target.Run++
			case "survivors":
				one := uint64(1)
				j.Intent.Release.Quiescence.Survivors = &one
			case "workspace":
				j.Intent.Workspace.RootIdentity = ""
			case "branch":
				j.Intent.Workspace.Branch = "foreign-branch"
			case "requester":
				j.Intent.Cause.RequestedBy.Kind = "worker"
				j.Claim.Record.Effect.Context.RequestedBy = j.Intent.Cause.RequestedBy
			}
			contractCode(t, ValidateCleanupJob(j, contractNow()), CodeInvalid, "cleanup job authority fence was bypassed")
		})
	}
}

func TestCollectInventory(t *testing.T) {
	for _, fault := range []string{"empty", "duplicate", "epoch", "graph", "archive", "role", "digest", "owner_generation"} {
		t.Run(fault, func(t *testing.T) {
			j, i, _, _ := collectionFixture(t)
			if err := ValidateCleanupInventory(j, i, contractNow()); err != nil {
				t.Fatal("valid owned inventory refused", err)
			}
			switch fault {
			case "empty":
				i.Objects = nil
			case "duplicate":
				i.Objects = append(i.Objects, i.Objects[0])
			case "epoch":
				i.CancellationEpoch++
			case "owner_generation":
				i.Objects[0].OwnershipGeneration = 0
			case "graph":
				i.GraphGeneration = 0
			case "archive":
				i.Objects[1].Role = "history"
			case "role":
				i.Objects[0].Role = "caller-owned"
			case "digest":
				i.Manifest.SHA256 = launchFixtureBlob("changed-inventory", "manifest").SHA256
			}
			if fault != "digest" {
				collectionInventory(t, &i)
			}
			contractCode(t, ValidateCleanupInventory(j, i, contractNow()), CodeInvalid, "owned inventory boundary was bypassed")
		})
	}
}

// Box 104: an archived lane's empty output parts are zero-byte store objects, so the inventory carries them.
func TestCollectInventoryEmptyObject(t *testing.T) {
	j, i, _, _ := collectionFixture(t)
	i.Objects[0].Ref.Bytes, i.Objects[0].Ref.SHA256 = 0, collectionBlob("empty", "output", nil).SHA256
	collectionInventory(t, &i)
	if err := ValidateCleanupInventory(j, i, contractNow()); err != nil {
		t.Fatal("empty owned object refused from the inventory", err)
	}
	i.Objects[0].Ref.Bytes = -1
	collectionInventory(t, &i)
	contractCode(t, ValidateCleanupInventory(j, i, contractNow()), CodeInvalid, "negative object size passed the inventory")
}

func TestCollectReceipt(t *testing.T) {
	for _, fault := range []string{"missing", "action", "reason", "root", "identity", "hash", "absent", "journal_id", "claim", "digest", "manifest_id"} {
		t.Run(fault, func(t *testing.T) {
			j, i, r, _ := collectionFixture(t)
			if err := ValidateCleanupReceipt(j, i, r, contractNow()); err != nil {
				t.Fatal("valid cleanup receipt refused", err)
			}
			switch fault {
			case "missing":
				r.Objects = r.Objects[:1]
			case "action":
				r.Objects[0].Action = "retain"
			case "reason":
				r.Objects[0].Reason = "gone"
			case "root":
				r.Objects[0].After.RootIdentity = "foreign-root"
			case "identity":
				r.Objects[1].After.Identity = "foreign-inode"
			case "hash":
				r.Objects[1].After.SHA256 = launchFixtureBlob("wrong-retained", "manifest").SHA256
			case "absent":
				r.Objects[0].After.State = "unknown"
			case "journal_id":
				r.Objects[0].After.ID = r.Objects[0].Before.ID
			case "claim":
				r.ClaimID = "other-claim"
			case "digest":
				r.Manifest.Bytes++
			}
			if fault != "digest" {
				collectionReceipt(t, &r)
			}
			if fault == "manifest_id" {
				r.Manifest.ID = i.Manifest.ID
			}
			contractCode(t, ValidateCleanupReceipt(j, i, r, contractNow()), CodeInvalid, "cleanup receipt readback boundary was bypassed")
		})
	}
}

func TestCollectWorkspace(t *testing.T) {
	for _, fault := range []string{"forced", "sync", "branch", "worktree", "dirty_unknown", "dirty_remove", "git", "head"} {
		t.Run(fault, func(t *testing.T) {
			j, _, r, _ := collectionFixture(t)
			w := r.Workspace
			if err := ValidateWorkspaceRemoval(j, w, contractNow()); err != nil {
				t.Fatal("valid workspace receipt refused", err)
			}
			switch fault {
			case "forced":
				w.Unforced = false
			case "sync":
				w.Synced = false
			case "branch":
				w.After.BranchState = "present"
			case "worktree":
				w.After.WorktreeState = "present"
			case "dirty_unknown":
				w.Before.Dirty = nil
			case "dirty_remove":
				dirty := true
				w.Before.Dirty = &dirty
			case "git":
				w.After.GitIdentity = "foreign-git"
			case "head":
				w.Before.Head = strings.Repeat("b", 40)
			}
			contractCode(t, ValidateWorkspaceRemoval(j, w, contractNow()), CodeInvalid, "workspace collection boundary was bypassed")
		})
	}
}

func TestCollectVerify(t *testing.T) {
	for _, fault := range []string{"object", "retained", "object_journal", "workspace", "workspace_journal", "inventory", "receipt", "revoke", "expiry", "unavailable", "receipt_record", "object_id", "object_dup", "workspace_id", "clock"} {
		t.Run(fault, func(t *testing.T) {
			j, i, r, m := collectionFixture(t)
			if _, err := VerifyCleanup(context.Background(), m, j, i, r, m.clock); err != nil || m.reads != len(i.Objects) || m.checks != 2 {
				t.Fatal("cleanup did not perform every installed readback", err)
			}
			m.reads, m.checks = 0, 0
			code := CodeIntegrity
			owner := "lb-v2-service"
			switch fault {
			case "object":
				m.objects[i.Objects[0].Ref.ID] = []byte("object still present")
			case "retained":
				m.objects[i.Objects[1].Ref.ID] = []byte("retained bytes changed")
			case "object_journal":
				x := m.journals[i.Objects[0].Ref.ID]
				x.Before.ID = "invented-observation"
				m.journals[x.ObjectID] = x
			case "workspace":
				owner = "lb-v2-admin"
				m.workspace.BranchState = "present"
			case "workspace_journal":
				owner = "lb-v2-admin"
				m.workspaceJournal.Unforced = false
			case "inventory":
				i.Objects = i.Objects[1:]
				r.Objects = r.Objects[1:]
				collectionInventory(t, &i)
				collectionReceipt(t, &r)
				m.receipt = cloneCleanupReceipt(r)
				m.blobs[r.Manifest.ID] = collectionReceipt(t, &r)
			case "receipt":
				m.blobs[r.Manifest.ID] = []byte("not the retained receipt")
			case "receipt_record":
				stored := cloneCleanupReceipt(r)
				stored.InventoryID = "changed-inventory"
				m.blobs[r.Manifest.ID] = collectionReceipt(t, &stored)
				m.receipt = stored
			case "object_id":
				m.objectReadIDs = map[ID]ID{i.Objects[0].Ref.ID: r.Objects[0].After.ID}
			case "object_dup":
				m.objectReadIDs = map[ID]ID{i.Objects[1].Ref.ID: ID("fresh-" + string(i.Objects[0].Ref.ID))}
			case "workspace_id":
				owner = "lb-v2-admin"
				m.workspace.ID = r.Workspace.After.ID
			case "clock":
				m.rewindAt = 2
			case "revoke":
				m.revokeAt = 2
				code = CodeConflict
			case "expiry":
				m.expireAt = 2
				code = CodeInvalid
			case "unavailable":
				sentinel := &Error{Code: CodeUnavailable, Owner: "lb-v2-service", Message: "readback unavailable"}
				m.err = sentinel
				code = CodeUnavailable
			}
			_, err := VerifyCleanup(context.Background(), m, j, i, r, m.clock)
			contractCode(t, err, code, "cleanup accepted an unmeasured removal or retention")
			if code == CodeIntegrity {
				var actual *Error
				if !errors.As(err, &actual) || actual.Owner != owner {
					t.Fatal("cleanup failure reached wrong owner", err)
				}
			}
		})
	}
}

func collectionCompletion(t *testing.T, j CleanupJob, r CleanupReceipt) (Lane, Event, EffectOutcome) {
	t.Helper()
	removed, retained := []ID{}, []ID{}
	var unowned UnownedRetained
	for _, o := range r.Objects {
		if o.Action == "remove" {
			removed = append(removed, o.ObjectID)
		} else {
			retained = append(retained, o.ObjectID)
		}
		if o.Reason == "unowned" {
			unowned.Objects++
			unowned.Bytes += o.Before.Bytes
		}
	}
	body, err := json.Marshal(CleanEvent{ArchiveReceipt: j.Intent.Archive, RemovedObjectIDs: removed, RetainedObjectIDs: retained, UnownedRetained: unowned, Quiescence: j.Intent.Release.Quiescence})
	if err != nil {
		t.Fatal(err)
	}
	c := j.Intent.Cause
	lane := Lane{LifeID: c.Target.LifeID, Run: c.Target.Run, Generation: j.Intent.ExpectedGeneration + 1, CancellationEpoch: c.CancellationEpoch, State: j.Intent.Decision, Cleaned: true, Workspace: Workspace{ID: j.Intent.Workspace.ID}}
	event := Event{Schema: SchemaVersion, ID: "clean-event", Kind: "lane.cleaned", Config: c.Config, Actor: c.Actor, RequestedBy: c.RequestedBy, OperationID: c.CauseOperationID, RequestID: c.CauseRequestID, LifeID: c.Target.LifeID, Run: c.Target.Run, Origin: "service", Payload: body}
	out := EffectOutcome{EffectID: c.EffectID, ClaimID: j.Claim.ClaimID, ExpectedGeneration: j.Claim.Record.Generation, Status: "succeeded", Output: &r.Manifest}
	return lane, event, out
}

func TestCollectUnowned(t *testing.T) {
	j, i, r, m := collectionFixture(t)
	for n, data := range map[int][]byte{7: []byte("abc"), 2: {}} {
		o, result := &i.Objects[n], &r.Objects[n]
		o.OwnerLifeID, o.OwnershipGeneration = "", 0
		o.Ref = collectionBlob(o.Ref.ID, o.Ref.Class, data)
		result.Reason = "unowned"
		result.Before.Bytes, result.Before.SHA256 = o.Ref.Bytes, o.Ref.SHA256
		result.After.Bytes, result.After.SHA256 = o.Ref.Bytes, o.Ref.SHA256
		m.objects[o.Ref.ID] = data
		m.journals[o.Ref.ID] = *result
	}
	m.blobs[i.Manifest.ID] = collectionInventory(t, &i)
	m.blobs[r.Manifest.ID] = collectionReceipt(t, &r)
	m.inventory, m.receipt = i, cloneCleanupReceipt(r)
	v, err := VerifyCleanup(context.Background(), m, j, i, r, m.clock)
	if err != nil {
		t.Fatal("unowned receipt failed independent verification", err)
	}
	lane, event, out := collectionCompletion(t, j, r)
	var body CleanEvent
	if err := json.Unmarshal(event.Payload, &body); err != nil {
		t.Fatal(err)
	}
	if body.UnownedRetained != (UnownedRetained{Objects: 2, Bytes: 3}) {
		t.Fatal("unowned totals omitted empty objects or counted other retention", body.UnownedRetained)
	}
	if err := ValidateCleanupCompletion(j, i, v, lane, event, out, contractNow()); err != nil {
		t.Fatal("measured unowned totals refused", err)
	}
	for _, fault := range []string{"objects", "bytes", "missing"} {
		t.Run(fault, func(t *testing.T) {
			changed := body
			switch fault {
			case "objects":
				changed.UnownedRetained.Objects--
			case "bytes":
				changed.UnownedRetained.Bytes++
			case "missing":
				changed.UnownedRetained = UnownedRetained{}
			}
			event.Payload, err = json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			contractCode(t, ValidateCleanupCompletion(j, i, v, lane, event, out, contractNow()), CodeInvalid, "unowned totals bypassed the measured receipt")
		})
	}
}

func TestCollectComplete(t *testing.T) {
	for _, fault := range []string{"seal", "generation", "epoch", "flag", "event", "claim", "output", "competing", "payload", "proof_time"} {
		t.Run(fault, func(t *testing.T) {
			j, i, r, m := collectionFixture(t)
			v, err := VerifyCleanup(context.Background(), m, j, i, r, m.clock)
			if err != nil {
				t.Fatal(err)
			}
			lane, event, out := collectionCompletion(t, j, r)
			if err := ValidateCleanupCompletion(j, i, v, lane, event, out, contractNow()); err != nil {
				t.Fatal("valid cleanup completion refused", err)
			}
			switch fault {
			case "proof_time":
				v.verification.CheckedAt = contractStamp(contractNow().Add(-time.Second))
				_, digest, err := launchCanonical(v.verification)
				if err != nil {
					t.Fatal(err)
				}
				v.proofDigest = digest
			case "seal":
				v.jobDigest = ""
			case "generation":
				lane.Generation++
			case "epoch":
				lane.CancellationEpoch++
			case "flag":
				lane.Cleaned = false
			case "event":
				event.RequestedBy.ID = "foreign-requester"
			case "claim":
				out.ClaimID = "other-claim"
			case "output":
				changed := *out.Output
				changed.ID = "unretained-receipt"
				out.Output = &changed
			case "competing":
				out.Process = &ProcessHandle{ID: "unrelated-process"}
			case "payload":
				var body CleanEvent
				if err := json.Unmarshal(event.Payload, &body); err != nil {
					t.Fatal(err)
				}
				body.RemovedObjectIDs = []ID{}
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				event.Payload = raw
			}
			contractCode(t, ValidateCleanupCompletion(j, i, v, lane, event, out, contractNow()), CodeInvalid, "cleanup completion bypassed its measured receipt")
		})
	}
}

func TestCollectDirty(t *testing.T) {
	j, i, r, m := collectionFixture(t)
	if err := ValidateCleanupReceipt(j, i, r, contractNow()); err != nil {
		t.Fatal(err)
	}
	dirty := true
	r.Workspace.Before.Dirty = &dirty
	r.Workspace.Action = "retain_dirty"
	r.Workspace.After = r.Workspace.Before
	r.Workspace.After.ID = "dirty-after"
	r.Workspace.After.ObservedAt = contractStamp(contractNow())
	m.workspaceJournal = r.Workspace
	m.workspace = r.Workspace.After
	m.workspace.ID = "dirty-fresh"
	m.blobs[r.Manifest.ID] = collectionReceipt(t, &r)
	m.receipt = cloneCleanupReceipt(r)
	v, err := VerifyCleanup(context.Background(), m, j, i, r, m.clock)
	if err != nil {
		t.Fatal("dirty retention receipt was refused", err)
	}
	lane, event, out := collectionCompletion(t, j, r)
	contractCode(t, ValidateCleanupCompletion(j, i, v, lane, event, out, contractNow()), CodeInvalid, "dirty retention was credited as collection")
	copy := v.Receipt()
	*copy.Workspace.Before.Dirty = false
	copy.Objects[0].Reason = "changed"
	if !*v.Receipt().Workspace.Before.Dirty || v.Receipt().Objects[0].Reason == "changed" {
		t.Fatal("cleanup verification exposed mutable receipt data")
	}
}

func TestCollectUnavailable(t *testing.T) {
	j, i, r, m := collectionFixture(t)
	if _, err := VerifyCleanup(context.Background(), m, j, i, r, m.clock); err != nil {
		t.Fatal(err)
	}
	var missing *collectionModel
	_, err := VerifyCleanup(context.Background(), missing, j, i, r, m.clock)
	contractCode(t, err, CodeNotImplemented, "missing cleanup readback source became success")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = VerifyCleanup(ctx, m, j, i, r, m.clock)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cleanup swallowed context cancellation", err)
	}
}

func TestCollectPolicy(t *testing.T) {
	j, i, _, _ := collectionFixture(t)
	if err := ValidateCleanupInventory(j, i, contractNow()); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		index        int
		reason       string
		unknownOwner bool
	}{{1, "archive", false}, {2, "capture", false}, {3, "input", false}, {4, "report", false}, {5, "event", false}, {6, "referenced", false}, {7, "unowned", false}, {8, "history", false}, {2, "unowned", true}} {
		t.Run(row.reason, func(t *testing.T) {
			object := i.Objects[row.index]
			if row.unknownOwner {
				object.OwnerLifeID = ""
			}
			action, reason := cleanupDisposition(object, j.Intent.Cause.Target)
			if action != "retain" || reason != row.reason {
				t.Fatal("protected cleanup object became removable", action, reason)
			}
		})
	}
}

func TestCollectUnknown(t *testing.T) {
	for _, field := range []string{"role", "owner"} {
		t.Run(field, func(t *testing.T) {
			j, i, r, m := collectionFixture(t)
			if err := ValidateCleanupReceipt(j, i, r, contractNow()); err != nil {
				t.Fatal(err)
			}
			if field == "owner" {
				// No owning lane is preserved as unowned and does not block completion (box 108, item 36).
				i.Objects[2].OwnerLifeID = ""
				i.Objects[2].OwnershipGeneration = 0
				r.Objects[2].Reason = "unowned"
			} else {
				i.Objects[2].Role = "unknown"
				r.Objects[2].Reason = "unknown"
			}
			m.blobs[i.Manifest.ID] = collectionInventory(t, &i)
			m.inventory = i
			m.blobs[r.Manifest.ID] = collectionReceipt(t, &r)
			m.receipt = cloneCleanupReceipt(r)
			m.journals[r.Objects[2].ObjectID] = r.Objects[2]
			v, err := VerifyCleanup(context.Background(), m, j, i, r, m.clock)
			if err != nil {
				t.Fatal("unknown object was not retained", err)
			}
			lane, event, out := collectionCompletion(t, j, r)
			if field == "owner" {
				if err := ValidateCleanupCompletion(j, i, v, lane, event, out, contractNow()); err != nil {
					t.Fatal("an object with no owning lane blocked completion", err)
				}
				return
			}
			contractCode(t, ValidateCleanupCompletion(j, i, v, lane, event, out, contractNow()), CodeInvalid, "unknown ownership was credited as collection")
		})
	}
}

func TestCollectTime(t *testing.T) {
	for _, owner := range []string{"lb-v2-service", "lb-v2-admin"} {
		t.Run(owner, func(t *testing.T) {
			stamp := contractStamp(contractNow())
			proof := CleanupVerification{Objects: []ObjectReadback{{ObservedAt: stamp}}, Workspace: WorkspaceReadback{ObservedAt: stamp}, CheckedAt: stamp}
			if got := cleanupProofTimeOwner(proof); got != "" {
				t.Fatal("ordered cleanup proof refused", got)
			}
			future := contractStamp(contractNow().Add(time.Second))
			if owner == "lb-v2-service" {
				proof.Objects[0].ObservedAt = future
			} else {
				proof.Workspace.ObservedAt = future
			}
			if got := cleanupProofTimeOwner(proof); got != owner {
				t.Fatal("cleanup proof accepted a future readback", got)
			}
		})
	}
}
