package dataworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Byte-backed writer/journal and administrator protocol fixtures. These mutate
// actual fixture namespaces and reopen retained bytes, but are not native Git,
// SQLite durability, authenticated service or installed deletion acceptance.
type cleanupPorts struct {
	api.StateStore
	t                                                         *testing.T
	job                                                       api.CleanupJob
	inventory                                                 api.CleanupInventory
	clock                                                     workerClock
	mode                                                      string
	valid, removed                                            bool
	objects, blobs                                            map[api.ID][]byte
	results                                                   []api.ObjectDisposition
	removal                                                   api.WorkspaceRemoval
	receipt                                                   api.CleanupReceipt
	removingClaim, removalJournal                             api.BlobRef
	sequence, inventories, collections, removals, objectReads int
	retentions, receiptReads, inventoryReads, inspections     int
	claimReads                                                int
	probe                                                     error
}

func cleanupCopy[T any](t *testing.T, value T) T {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var copy T
	if err := json.Unmarshal(raw, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func (p *cleanupPorts) id() api.ID {
	p.sequence++
	return api.ID(fmt.Sprintf("observation-%d", p.sequence))
}

func (p *cleanupPorts) auth(ctx context.Context, scope api.Scope, job api.CleanupJob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !p.valid || scope.Config != p.job.Intent.Cause.Config || scope.Actor != (api.Actor{Kind: "service", ID: p.job.Claim.Record.ClaimantID}) || scope.Connection != nil || scope.Frame != nil || !reflect.DeepEqual(job, p.job) {
		return cleanupError(api.CodeConflict, "lb-v2-service", "fixture cleanup claim changed")
	}
	return nil
}

func (p *cleanupPorts) BeginCleanup(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.CleanupJob, error) {
	if !reflect.DeepEqual(lease, p.job.Claim) {
		return api.CleanupJob{}, cleanupError(api.CodeConflict, "lb-v2-service", "fixture lease is not the current claim")
	}
	if err := p.auth(ctx, scope, p.job); err != nil {
		return api.CleanupJob{}, err
	}
	job := cleanupCopy(p.t, p.job)
	if p.mode == "intent" {
		job.Intent.ID = "another-intent"
	}
	return job, nil
}

func (p *cleanupPorts) CleanupInventory(ctx context.Context, scope api.Scope, job api.CleanupJob) (api.CleanupInventory, error) {
	p.inventories++
	if err := p.auth(ctx, scope, job); err != nil {
		return api.CleanupInventory{}, err
	}
	return cleanupCopy(p.t, p.inventory), nil
}

func (p *cleanupPorts) CleanupReadbacks(api.Scope) api.CleanupReadbacks {
	if p.mode == "no-reads" {
		return nil
	}
	if p.mode == "no-removal-reads" {
		return cleanupBasicReads{CleanupReadbacks: p}
	}
	return p
}

func (p *cleanupPorts) CheckCleanup(ctx context.Context, job api.CleanupJob, inventory api.CleanupInventory) error {
	if err := p.auth(ctx, api.Scope{Config: p.job.Intent.Cause.Config, Actor: api.Actor{Kind: "service", ID: p.job.Claim.Record.ClaimantID}}, job); err != nil {
		return err
	}
	if !reflect.DeepEqual(inventory, p.inventory) {
		return p.probe
	}
	return nil
}

func (p *cleanupPorts) object(object api.CleanupObject) api.ObjectReadback {
	r := api.ObjectReadback{ID: p.id(), ObjectID: object.Ref.ID, RootID: object.RootID, RootIdentity: object.RootIdentity, State: "absent", ObservedAt: api.Timestamp(p.clock.Now().Format(time.RFC3339Nano))}
	if data, ok := p.objects[object.Ref.ID]; ok {
		r.State, r.Identity, r.SHA256, r.Bytes = "present", object.Identity, manifest.Hash(data), int64(len(data))
	}
	return r
}

func (p *cleanupPorts) CollectCleanupObjects(ctx context.Context, scope api.Scope, job api.CleanupJob, inventory api.CleanupInventory) ([]api.ObjectDisposition, error) {
	p.collections++
	if err := p.auth(ctx, scope, job); err != nil {
		return nil, err
	}
	if p.mode == "collect-error" {
		return nil, p.probe
	}
	if !reflect.DeepEqual(inventory, p.inventory) {
		return nil, p.probe
	}
	if p.results != nil {
		if p.removed {
			p.removalJournal = p.seal("removal-journal", p.removal)
		}
		return cleanupCopy(p.t, p.results), nil
	}
	for _, object := range inventory.Objects {
		before := p.object(object)
		if before.State != "present" || before.SHA256 != object.Ref.SHA256 || before.Bytes != object.Ref.Bytes {
			return nil, p.probe
		}
		action, reason := "retain", object.Role
		switch {
		case object.Role == "unknown":
			reason = "unknown"
		case object.OwnerLifeID != job.Intent.Cause.Target.LifeID:
			reason = "unowned"
		case object.References != 0:
			reason = "referenced"
		case object.Role == "transient" && object.Ref.Class == "artifact":
			action, reason = "remove", "unreferenced"
		case object.Role == "transient":
			reason = "history"
		}
		if action == "remove" {
			delete(p.objects, object.Ref.ID)
		}
		result := api.ObjectDisposition{ObjectID: object.Ref.ID, Action: action, Reason: reason, Before: before, After: p.object(object)}
		if (p.mode == "referenced" && object.References != 0) || (p.mode == "unowned" && object.OwnerLifeID != job.Intent.Cause.Target.LifeID) {
			result.Action, result.Reason = "remove", "unreferenced" // Corrupt response, no deletion.
		}
		p.results = append(p.results, result)
	}
	p.removingClaim = p.seal("removal-authority", job.Claim)
	if p.mode == "post-objects" {
		p.valid = false
	}
	switch p.mode {
	case "before-absent":
		p.results[0].Before.State = "absent"
	case "after-present":
		p.results[0].After.State = "present"
	case "eligible-retained":
		p.results[0].Action, p.results[0].Reason = "retain", "transient"
	case "retained-absent":
		p.results[1].After.State = "absent"
	case "omit-object":
		p.results = p.results[:len(p.results)-1]
	case "reorder-object":
		p.results[0], p.results[1] = p.results[1], p.results[0]
	}
	return cleanupCopy(p.t, p.results), nil
}

func (p *cleanupPorts) InspectCleanupWorkspace(ctx context.Context, job api.CleanupJob) (api.WorkspaceReadback, error) {
	p.inspections++
	if err := p.auth(ctx, api.Scope{Config: p.job.Intent.Cause.Config, Actor: api.Actor{Kind: "service", ID: p.job.Claim.Record.ClaimantID}}, job); err != nil {
		return api.WorkspaceReadback{}, err
	}
	w := job.Intent.Workspace
	r := api.WorkspaceReadback{ID: p.id(), WorkspaceID: w.ID, RootIdentity: w.RootIdentity, GitIdentity: w.GitIdentity, WorktreeState: "absent", BranchState: "absent", ObservedAt: api.Timestamp(p.clock.Now().Format(time.RFC3339Nano))}
	if !p.removed {
		dirty := p.mode == "dirty-retain" || p.mode == "retain-dirty" && p.removals != 0
		r.DirectoryIdentity, r.Head, r.Dirty, r.WorktreeState, r.BranchState = w.DirectoryIdentity, w.Head, &dirty, "present", "present"
		if p.mode == "unknown" {
			r.Dirty = nil
		}
		if p.mode == "workspace" {
			r.RootIdentity = "foreign-root"
		}
	}
	if p.mode == "fence" {
		p.valid = false
	}
	if p.removed && p.mode == "echo-replay" {
		r = cleanupCopy(p.t, p.removal.After)
	}
	if p.removed && p.mode == "unordered-replay" {
		r.ObservedAt = p.removal.Before.ObservedAt
	}
	return r, nil
}

func (p *cleanupPorts) RemoveCleanupWorkspace(ctx context.Context, job api.CleanupJob, before api.WorkspaceReadback) (api.WorkspaceRemoval, error) {
	p.removals++
	if err := p.auth(ctx, api.Scope{Config: p.job.Intent.Cause.Config, Actor: api.Actor{Kind: "service", ID: p.job.Claim.Record.ClaimantID}}, job); err != nil {
		return api.WorkspaceRemoval{}, err
	}
	if p.mode == "dirty-retain" {
		current, err := p.InspectCleanupWorkspace(ctx, job)
		if err != nil {
			return api.WorkspaceRemoval{}, err
		}
		after := cleanupCopy(p.t, current)
		after.ID = p.id()
		p.removal = api.WorkspaceRemoval{IntentID: job.Intent.ID, ClaimID: job.Claim.ClaimID,
			Action: "retain_dirty", Before: current, After: after, Unforced: true, Synced: true}
		return cleanupCopy(p.t, p.removal), nil
	}
	if before.Dirty == nil || *before.Dirty || p.results == nil {
		return api.WorkspaceRemoval{}, p.probe
	}
	if p.mode == "retain-dirty" {
		// The administrator observes newly dirty work after the clean preflight.
		current, err := p.InspectCleanupWorkspace(ctx, job)
		if err != nil {
			return api.WorkspaceRemoval{}, err
		}
		after := cleanupCopy(p.t, current)
		after.ID = p.id()
		p.removal = api.WorkspaceRemoval{IntentID: job.Intent.ID, ClaimID: job.Claim.ClaimID, Action: "retain_dirty", Before: current, After: after, Unforced: true, Synced: true}
		return cleanupCopy(p.t, p.removal), nil
	}
	if p.mode == "replay-seed" {
		p.clock.now = p.clock.now.Add(time.Millisecond)
	}
	p.removed = true
	after, err := p.InspectCleanupWorkspace(ctx, job)
	if err != nil {
		return api.WorkspaceRemoval{}, err
	}
	p.removal = api.WorkspaceRemoval{IntentID: job.Intent.ID, ClaimID: job.Claim.ClaimID, Action: "remove_clean", Before: before, After: after, Unforced: true, Synced: true}
	if p.mode == "crash-after-remove" {
		return api.WorkspaceRemoval{}, p.probe
	}
	if p.mode == "forced" {
		p.removal.Unforced = false
	}
	if p.mode == "branch" {
		p.removal.After.BranchState = "present"
	}
	return cleanupCopy(p.t, p.removal), nil
}

func (p *cleanupPorts) RetainCleanupReceipt(ctx context.Context, scope api.Scope, job api.CleanupJob, receipt api.CleanupReceipt) (api.CleanupReceipt, error) {
	p.retentions++
	if err := p.auth(ctx, scope, job); err != nil {
		return api.CleanupReceipt{}, err
	}
	if p.mode == "retain-swap" {
		receipt.ID = "substituted-receipt"
	}
	body, digest, err := api.CleanupReceiptBytes(receipt)
	if err != nil {
		return api.CleanupReceipt{}, err
	}
	receipt.Manifest = api.BlobRef{ID: api.ID("receipt-bytes-" + string(receipt.ClaimID)), Class: "manifest", Bytes: int64(len(body)), SHA256: digest}
	p.removalJournal = p.seal("removal-journal", p.removal)
	var validation error
	if receipt.Workspace.ClaimID == job.Claim.ClaimID {
		validation = api.ValidateCleanupReceipt(job, p.inventory, receipt, p.clock.Now())
	} else {
		var claim api.EffectLease
		if err := p.decode(p.removingClaim, &claim); err != nil {
			return api.CleanupReceipt{}, err
		}
		validation = api.ValidateCleanupReceiptWithRemoval(job, p.inventory, receipt, claim, p.clock.Now())
	}
	if validation != nil {
		return api.CleanupReceipt{}, validation
	}
	if p.receipt.ID != "" && p.receipt.ClaimID == receipt.ClaimID && !reflect.DeepEqual(p.receipt, receipt) {
		return api.CleanupReceipt{}, p.probe
	}
	if p.receipt.ID == receipt.ID && p.receipt.ClaimID != receipt.ClaimID {
		return api.CleanupReceipt{}, p.probe
	}
	p.blobs[receipt.Manifest.ID] = append([]byte(nil), body...)
	p.receipt = cleanupCopy(p.t, receipt)
	return cleanupCopy(p.t, receipt), nil
}

func (p *cleanupPorts) decode(ref api.BlobRef, result any) error {
	data, ok := p.blobs[ref.ID]
	if !ok || manifest.Hash(data) != ref.SHA256 || int64(len(data)) != ref.Bytes {
		return p.probe
	}
	return json.Unmarshal(data, result)
}

func (p *cleanupPorts) CleanupReceipt(ctx context.Context, scope api.Scope, id api.ID) (api.CleanupReceipt, error) {
	p.receiptReads++
	if err := p.auth(ctx, scope, p.job); err != nil {
		return api.CleanupReceipt{}, err
	}
	if p.mode == "receipt-read" {
		return api.CleanupReceipt{}, p.probe
	}
	if p.mode == "namespace" {
		p.objects["scratch"] = []byte("restored scratch bytes")
	}
	receipt, err := p.ReadCleanupReceipt(ctx, p.job, id)
	if err != nil {
		return api.CleanupReceipt{}, err
	}
	if p.mode == "read-swap" {
		receipt.ID = "substituted-readback"
		body, digest, err := api.CleanupReceiptBytes(receipt)
		if err != nil {
			return api.CleanupReceipt{}, err
		}
		receipt.Manifest.Bytes, receipt.Manifest.SHA256 = int64(len(body)), digest
	}
	return receipt, nil
}

func (p *cleanupPorts) ReadCleanupInventory(_ context.Context, _ api.CleanupJob, id api.ID) (api.CleanupInventory, error) {
	p.inventoryReads++
	var inventory api.CleanupInventory
	if id != p.inventory.ID {
		return inventory, p.probe
	}
	if err := p.decode(p.inventory.Manifest, &inventory); err != nil {
		return inventory, err
	}
	inventory.Manifest = p.inventory.Manifest
	return inventory, nil
}

func (p *cleanupPorts) ReadCleanupReceipt(_ context.Context, _ api.CleanupJob, id api.ID) (api.CleanupReceipt, error) {
	var receipt api.CleanupReceipt
	if id != p.receipt.ID {
		return receipt, p.probe
	}
	if err := p.decode(p.receipt.Manifest, &receipt); err != nil {
		return receipt, err
	}
	receipt.Manifest = p.receipt.Manifest
	return receipt, nil
}

func (p *cleanupPorts) ReadCleanupObjectResult(_ context.Context, _ api.CleanupJob, id api.ID) (api.ObjectDisposition, error) {
	for _, result := range p.results {
		if result.ObjectID == id {
			return cleanupCopy(p.t, result), nil
		}
	}
	return api.ObjectDisposition{}, p.probe
}
func (p *cleanupPorts) ReadCleanupObject(_ context.Context, _ api.CleanupJob, object api.CleanupObject) (api.ObjectReadback, error) {
	p.objectReads++
	if p.mode == "read-error" {
		return api.ObjectReadback{}, p.probe
	}
	return p.object(object), nil
}
func (p *cleanupPorts) ReadWorkspaceRemoval(_ context.Context, job api.CleanupJob) (api.WorkspaceRemoval, error) {
	if p.removal.IntentID != job.Intent.ID || !reflect.DeepEqual(job, p.job) {
		return api.WorkspaceRemoval{}, p.probe
	}
	journal := cleanupCopy(p.t, p.removal)
	if p.mode == "unknown-remover" {
		journal.ClaimID = "unretained-remover"
	}
	if p.mode == "foreign-intent" {
		journal.IntentID = "unretained-intent"
	}
	return journal, nil
}
func (p *cleanupPorts) ReadCleanupWorkspace(ctx context.Context, job api.CleanupJob) (api.WorkspaceReadback, error) {
	return p.InspectCleanupWorkspace(ctx, job)
}
func (p *cleanupPorts) CompleteCleanup(context.Context, api.Scope, api.CleanupJob, api.VerifiedCleanup) (api.Commit, error) {
	p.t.Fatal("collector attempted the writer's cleanup completion")
	return api.Commit{}, p.probe
}

func cleanupFixture(t *testing.T, mode string) (*Service, *cleanupPorts) {
	t.Helper()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	stamp := func(at time.Time) api.Timestamp { return api.Timestamp(at.Format(time.RFC3339Nano)) }
	zero := uint64(0)
	target := api.LifeRef{LifeID: "cleanup-life", Run: 2}
	cause := api.InternalIntent{ID: "clean-cause", Kind: api.InternalLifecycleEffect, Config: "demo", Actor: api.Actor{Kind: "service", ID: "lifecycle"}, RequestedBy: api.Actor{Kind: "human", ID: "owner"}, CauseOperationID: "clean-operation", CauseRequestID: "clean-request", EffectID: "clean-effect", Target: target, CancellationEpoch: 3}
	archive := api.ArchiveReceipt{ID: "archive-receipt", LifeID: target.LifeID, Manifest: api.BlobRef{ID: "archive", Class: "manifest", Bytes: 7, SHA256: manifest.Hash([]byte("archive"))}, ArchiveSHA256: manifest.Hash([]byte("tar bytes")), VerifiedAt: stamp(now.Add(-time.Second)), StoreID: "archive-store"}
	archive.ReadBackSHA256 = archive.ArchiveSHA256
	release := api.ReleaseReceipt{ID: "release", LeaseID: "released-lease", ContainmentID: "containment", Backend: "linux-bwrap-landlock", OperationID: "release-operation", EffectID: "release-effect", LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: stamp(now.Add(-2 * time.Second)), Quiescence: api.ProcessObservation{Handle: api.ProcessHandle{ID: "process", Target: target, ContainmentID: "containment", Generation: "process-generation"}, State: "exited", Survivors: &zero, PromptStatus: "completed", ObservedAt: stamp(now.Add(-2 * time.Second))}}
	intent := api.CleanupIntent{ID: "cleanup-intent", Cause: cause, ExpectedGeneration: 7, Decision: "abandoned", Archive: archive, ArchiveRequest: api.ArchiveRequest{Target: target, ExpectedGeneration: 7}, Release: release, Workspace: api.CleanupWorkspace{ID: "workspace", RootID: "parent", RepositoryID: "repository", Target: target, Generation: 1, RootIdentity: "root-inode", DirectoryIdentity: "directory-inode", GitIdentity: "git-inode", Branch: "lane/cleanup-life", Head: strings.Repeat("a", 40)}}
	expiry := stamp(now.Add(time.Minute))
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Clean: &api.CleanRequest{Target: target, ExpectedGeneration: 7, ArchiveReceiptID: archive.ID}}
	job := api.CleanupJob{Intent: intent, Claim: api.EffectLease{ClaimID: "claim", ExpiresAt: expiry, Record: api.EffectRecord{Effect: effect, State: api.EffectClaimed, Generation: 2, ClaimID: "claim", ClaimantID: "collector", ClaimExpiresAt: expiry}}}
	p := &cleanupPorts{t: t, job: job, clock: workerClock{now}, mode: mode, valid: true, objects: map[api.ID][]byte{}, blobs: map[api.ID][]byte{}, probe: cleanupError(api.CodeUnavailable, "lb-v2-service", "injected cleanup owner error")}
	p.inventory = api.CleanupInventory{ID: "inventory", IntentID: intent.ID, Config: cause.Config, Target: target, ExpectedGeneration: 7, CancellationEpoch: 3, GraphGeneration: 1, Objects: []api.CleanupObject{}}
	for _, row := range []struct {
		id, role, class string
		refs            uint64
		foreign         bool
	}{{"scratch", "transient", "artifact", 0, false}, {"archive", "archive", "manifest", 0, false}, {"shared", "transient", "artifact", 1, false}, {"foreign", "transient", "artifact", 0, true}, {"audit", "report", "report", 0, false}} {
		data := []byte(row.id)
		p.objects[api.ID(row.id)] = data
		object := api.CleanupObject{Ref: api.BlobRef{ID: api.ID(row.id), Class: row.class, Bytes: int64(len(data)), SHA256: manifest.Hash(data)}, RootID: "object-root", RootIdentity: "store-parent", Identity: "object-" + row.id, OwnerLifeID: target.LifeID, OwnershipGeneration: 1, Role: row.role, References: row.refs}
		if row.foreign {
			object.OwnerLifeID = "other-life"
		}
		p.inventory.Objects = append(p.inventory.Objects, object)
	}
	body, digest, err := api.CleanupInventoryBytes(p.inventory)
	if err != nil {
		t.Fatal(err)
	}
	p.inventory.Manifest = api.BlobRef{ID: "inventory-bytes", Class: "manifest", Bytes: int64(len(body)), SHA256: digest}
	p.blobs[p.inventory.Manifest.ID] = body
	if err := api.ValidateCleanupInventory(job, p.inventory, now); err != nil {
		t.Fatal("invalid cleanup protocol fixture", err)
	}
	s, err := New(Dependencies{Config: cause.Config, Store: p, Helper: &unopenedHelper{}, Workspace: p, Launcher: &probeLauncher{}, Clock: p.clock})
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestCleanupCollector(t *testing.T) {
	s, p := cleanupFixture(t, "valid")
	receipt, err := s.CollectCleanup(context.Background(), p.job)
	if err != nil || receipt.ID == "" || !reflect.DeepEqual(receipt, p.receipt) || p.objectReads != len(p.inventory.Objects) || p.removals != 1 {
		t.Fatal("collector did not return independently verified retained receipt", err)
	}
	if _, present := p.objects["scratch"]; present {
		t.Fatal("collector reported an uncollected transient object")
	}
	for _, id := range []api.ID{"archive", "shared", "foreign", "audit"} {
		if string(p.objects[id]) != string(id) {
			t.Fatal("collector deleted retained or referenced bytes", id)
		}
	}
	again, err := s.CollectCleanup(context.Background(), p.job)
	if err != nil || !reflect.DeepEqual(again, receipt) || p.removals != 1 || p.objectReads != 2*len(p.inventory.Objects) {
		t.Fatal("cleanup replay changed receipt or skipped fresh reads", err)
	}
}

func TestCleanupRefusals(t *testing.T) {
	for _, mode := range []string{"foreign", "executor", "claim", "intent", "unknown", "workspace", "fence", "post-objects", "referenced", "unowned", "forced", "branch", "namespace", "receipt-read", "read-error", "collect-error"} {
		t.Run(mode, func(t *testing.T) {
			s, p := cleanupFixture(t, mode)
			job := cleanupCopy(t, p.job)
			code := api.CodeIntegrity
			switch mode {
			case "foreign":
				s.deps.Config = "foreign-config"
				code = api.CodeForbidden
			case "executor":
				job.Claim.Record.ClaimantID = ""
				code = api.CodeForbidden
			case "claim":
				job.Claim.Record.ClaimantID = "forged-executor"
				code = api.CodeConflict
			case "intent", "fence", "post-objects":
				code = api.CodeConflict
			case "unknown":
				code = api.CodeContainmentUnknown
			case "referenced", "unowned":
				code = api.CodeForbidden
			case "forced", "branch":
				code = api.CodeInvalid
			case "receipt-read", "read-error", "collect-error":
				code = api.CodeUnavailable
			}
			receipt, err := s.CollectCleanup(context.Background(), job)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != code || receipt.ID != "" {
				t.Fatal("cleanup collector escaped its measured refusal", mode, err)
			}
			if (mode == "receipt-read" || mode == "read-error" || mode == "collect-error") && !errors.Is(err, p.probe) {
				t.Fatal("cleanup owner error was replaced", mode, err)
			}
			if (mode == "fence" || mode == "unknown" || mode == "workspace") && (p.collections != 0 || p.removals != 0) {
				t.Fatal("unsafe cleanup reached an object or workspace operation", mode)
			}
			if (mode == "referenced" || mode == "unowned" || mode == "post-objects") && p.removals != 0 {
				t.Fatal("invalid object result reached workspace removal", mode)
			}
			if mode == "intent" && p.inventories != 0 {
				t.Fatal("foreign cleanup intent reached inventory")
			}
			for _, id := range []api.ID{"archive", "shared", "foreign", "audit"} {
				if string(p.objects[id]) != string(id) {
					t.Fatal("refused cleanup deleted retained bytes", id)
				}
			}
		})
	}
}

func TestCleanupDirtyReachesNativeRetention(t *testing.T) {
	s, p := cleanupFixture(t, "dirty-retain")
	receipt, err := s.CollectCleanup(context.Background(), p.job)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite ||
		typed.Message != "cleanup retained dirty work (retain_dirty)" ||
		typed.Instead != "Merge or discard the uncommitted work (unmerged commits on an abandoned branch are retained), then clean the lane again." || receipt.ID != "" {
		t.Fatal("dirty cleanup did not return the native retention refusal", err)
	}
	if p.collections != 1 || p.removals != 1 || p.retentions != 0 || p.removal.Action != "retain_dirty" {
		t.Fatal("dirty cleanup did not reach the native retention journal", p.collections, p.removals, p.retentions, p.removal.Action)
	}
}

type cleanupHelper struct {
	api.HelperControl
	api.WorkspaceCollector
}

func TestCleanupHelperPort(t *testing.T) {
	s, p := cleanupFixture(t, "valid")
	s.deps.Workspace = nil
	s.deps.Helper = &cleanupHelper{HelperControl: &unopenedHelper{}, WorkspaceCollector: p}
	receipt, err := s.CollectCleanup(context.Background(), p.job)
	if err != nil || receipt.ID == "" || p.objectReads != len(p.inventory.Objects) {
		t.Fatal("installed helper collection port was not used", err)
	}
}

func TestCleanupUnavailable(t *testing.T) {
	for _, mode := range []string{"config", "store", "workspace", "no-reads", "cancelled", "lost-journal"} {
		t.Run(mode, func(t *testing.T) {
			s, p := cleanupFixture(t, mode)
			ctx := context.Background()
			code := api.CodeNotImplemented
			switch mode {
			case "config":
				s.deps.Config = ""
				code = api.CodePrerequisite
			case "store":
				s.deps.Store = &unopenedStore{}
			case "workspace":
				s.deps.Workspace = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				code = api.CodeCancelled
			case "lost-journal":
				p.removed = true
				code = api.CodeUnavailable
			}
			receipt, err := s.CollectCleanup(ctx, p.job)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != code || receipt.ID != "" || p.collections != 0 || p.removals != 0 {
				t.Fatal("unavailable cleanup produced work or a receipt", mode, err)
			}
		})
	}
}
