package dataworker

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type cleanupStore interface {
	api.CleanupObjectStore
	CleanupReadbacks(api.Scope) api.CleanupReadbacks
}

var _ api.CleanupDataWorker = (*Service)(nil)

func cleanupError(code api.ErrorCode, owner, message string) error {
	return &api.Error{Code: code, Owner: owner, Message: message,
		Instead: "Retain the original cleanup intent and reconcile through the owning service or administrator."}
}

func dirtyCleanupError() error {
	return &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-admin",
		Message: "cleanup retained dirty work (retain_dirty)",
		Instead: "Merge or discard the uncommitted work (unmerged commits on an abandoned branch are retained), then clean the lane again."}
}

// CollectCleanup orchestrates installed writer/admin capabilities. The writer
// authenticates the original claim before any namespace operation; a job's
// labels or a worker UID never provide a second deletion route.
func (s *Service) CollectCleanup(ctx context.Context, job api.CleanupJob) (api.CleanupReceipt, error) {
	var zero api.CleanupReceipt
	if err := checkContext(ctx); err != nil {
		return zero, err
	}
	if !manifest.Config(s.deps.Config) {
		return zero, cleanupError(api.CodePrerequisite, "lb-v2-grants", "cleanup requires its installed configuration")
	}
	if err := api.ValidateCleanupJob(job, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	if job.Intent.Cause.Config != s.deps.Config || !manifest.ValidID(job.Claim.Record.ClaimantID) {
		return zero, cleanupError(api.CodeForbidden, "lb-v2-grants", "cleanup cannot borrow another configuration or executor")
	}
	store, ok := s.deps.Store.(cleanupStore)
	if !ok || missing(store) {
		return zero, api.NotImplemented("lb-v2-service", "protected cleanup writer and independent readbacks")
	}
	workspace := s.deps.Workspace
	if missing(workspace) {
		workspace, _ = s.deps.Helper.(api.WorkspaceCollector)
	}
	if missing(workspace) {
		return zero, api.NotImplemented("lb-v2-admin", "installed unforced workspace and branch collector")
	}
	// The outbox gives every claim attempt a new executor. Preserve the cause's
	// original Actor, but use this claim's actual claimant for writer calls.
	// BeginCleanup authenticates the complete lease, not this label alone.
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: job.Claim.Record.ClaimantID}}
	current, err := store.BeginCleanup(ctx, scope, job.Claim)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(current, job) {
		return zero, cleanupError(api.CodeConflict, "lb-v2-grants", "cleanup job differs from its protected original intent")
	}
	inventory, err := store.CleanupInventory(ctx, scope, job)
	if err != nil {
		return zero, err
	}
	if err := api.ValidateCleanupInventory(job, inventory, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	// Each independent read sequence takes its own pass (box 106): a pass refuses once the collection record moves,
	// and this worker itself moves it by collecting objects and retaining the receipt between its reads.
	if missing(store.CleanupReadbacks(scope)) {
		return zero, api.NotImplemented("lb-v2-service", "installed cleanup readback source")
	}
	check := func() error {
		if err := checkContext(ctx); err != nil {
			return err
		}
		if err := api.ValidateCleanupJob(job, s.deps.Clock.Now()); err != nil {
			return err
		}
		actual, err := store.BeginCleanup(ctx, scope, job.Claim)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(actual, job) {
			return cleanupError(api.CodeConflict, "lb-v2-grants", "cleanup authority changed before collection")
		}
		return store.CleanupReadbacks(scope).CheckCleanup(ctx, job, inventory)
	}
	if err := check(); err != nil {
		return zero, err
	}
	before, err := workspace.InspectCleanupWorkspace(ctx, job)
	if err != nil {
		return zero, err
	}
	removed := before.WorktreeState == "absent" && before.BranchState == "absent"
	var removal api.WorkspaceRemoval
	removalClaim := job.Claim
	if removed {
		// Absence is replayable only beside the original protected journal.
		removal, err = store.CleanupReadbacks(scope).ReadWorkspaceRemoval(ctx, job)
		if err != nil {
			return zero, err
		}
		fresh := removal
		fresh.After = before
		if removal.ClaimID == job.Claim.ClaimID {
			if err := api.ValidateWorkspaceRemoval(job, fresh, s.deps.Clock.Now()); err != nil {
				return zero, err
			}
		}
		if before.ID == removal.After.ID || !cleanupOrdered(removal.After.ObservedAt, before.ObservedAt) {
			return zero, cleanupError(api.CodeIntegrity, "lb-v2-admin", "cleanup workspace replay echoed its removal observation")
		}
	} else if err := inspectCleanup(job, before, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	if err := check(); err != nil {
		return zero, err
	}
	objects, err := store.CollectCleanupObjects(ctx, scope, job, inventory)
	if err != nil {
		return zero, err
	}
	if err := cleanupObjects(job, inventory, objects); err != nil {
		return zero, err
	}
	if err := api.ValidateCleanupObjectResults(job, inventory, objects, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	if removed {
		// The writer authenticates/replays its object journals and retains the
		// actual native journal before exposing the historical removing claim.
		removalClaim, err = cleanupRemovalClaim(ctx, store.CleanupReadbacks(scope), job, removal)
		if err != nil {
			return zero, err
		}
		if removal.ClaimID != job.Claim.ClaimID {
			fresh := removal
			fresh.After = before
			if err := api.ValidateWorkspaceRemovalReplay(job, fresh, removalClaim, removal.After.ObservedAt, s.deps.Clock.Now()); err != nil {
				return zero, err
			}
		}
	}
	if err := check(); err != nil {
		return zero, err
	}
	if !removed {
		removal, err = workspace.RemoveCleanupWorkspace(ctx, job, before)
		if err != nil {
			return zero, err
		}
		removalClaim, err = cleanupRemovalClaim(ctx, store.CleanupReadbacks(scope), job, removal)
		if err != nil {
			return zero, err
		}
	}
	if removal.ClaimID == job.Claim.ClaimID {
		if err := api.ValidateWorkspaceRemoval(job, removal, s.deps.Clock.Now()); err != nil {
			return zero, err
		}
	} else if err := api.ValidateWorkspaceRemovalReplay(job, removal, removalClaim, removal.After.ObservedAt, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	if removal.Action == "retain_dirty" {
		return zero, dirtyCleanupError()
	}
	if removal.Action != "remove_clean" {
		return zero, cleanupError(api.CodePrerequisite, "lb-v2-admin", "workspace removal has an unknown disposition")
	}
	digest, err := manifest.HashValue(struct {
		Intent, Claim api.ID
		Generation    api.Generation
	}{job.Intent.ID, job.Claim.ClaimID, job.Claim.Record.Generation})
	if err != nil {
		return zero, err
	}
	proposed := api.CleanupReceipt{ID: api.ID("cleanup_" + string(digest[:32])), IntentID: job.Intent.ID,
		ClaimID: job.Claim.ClaimID, InventoryID: inventory.ID, Objects: objects, Workspace: removal}
	retained, err := store.RetainCleanupReceipt(ctx, scope, job, proposed)
	if err != nil {
		return zero, err
	}
	bare := retained
	bare.Manifest = api.BlobRef{}
	if !reflect.DeepEqual(bare, proposed) {
		return zero, cleanupError(api.CodeIntegrity, "lb-v2-service", "retained cleanup receipt substituted the measured operations")
	}
	if removal.ClaimID == job.Claim.ClaimID {
		if err := api.ValidateCleanupReceipt(job, inventory, retained, s.deps.Clock.Now()); err != nil {
			return zero, err
		}
	} else if err := api.ValidateCleanupReceiptWithRemoval(job, inventory, retained, removalClaim, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	actual, err := store.CleanupReceipt(ctx, scope, retained.ID)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(actual, retained) {
		return zero, cleanupError(api.CodeIntegrity, "lb-v2-service", "cleanup receipt failed exact retained readback")
	}
	verified, err := api.VerifyCleanup(ctx, store.CleanupReadbacks(scope), job, inventory, actual, s.deps.Clock)
	if err != nil {
		return zero, err
	}
	return verified.Receipt(), nil // Completion and lane.cleaned belong to the writer.
}

func cleanupRemovalClaim(ctx context.Context, reads api.CleanupReadbacks, job api.CleanupJob, journal api.WorkspaceRemoval) (api.EffectLease, error) {
	if journal.ClaimID == job.Claim.ClaimID {
		return job.Claim, nil
	}
	claims, ok := reads.(api.CleanupRemovalReadbacks)
	if !ok || missing(claims) {
		return api.EffectLease{}, cleanupError(api.CodeIntegrity, "lb-v2-service", "historical removal lacks its installed retained claim source")
	}
	removalClaim, err := claims.ReadCleanupRemovalClaim(ctx, job, journal)
	return removalClaim, err
}

func cleanupOrdered(first, last api.Timestamp) bool {
	a, ae := time.Parse(time.RFC3339Nano, string(first))
	b, be := time.Parse(time.RFC3339Nano, string(last))
	return ae == nil && be == nil && !b.Before(a)
}

func inspectCleanup(job api.CleanupJob, read api.WorkspaceReadback, now time.Time) error {
	w := job.Intent.Workspace
	observed, err := time.Parse(time.RFC3339Nano, string(read.ObservedAt))
	if !manifest.ValidID(read.ID) || read.WorkspaceID != w.ID || read.RootIdentity != w.RootIdentity ||
		read.DirectoryIdentity != w.DirectoryIdentity || read.GitIdentity != w.GitIdentity || read.Head != w.Head ||
		err != nil || observed.IsZero() || observed.After(now) || !cleanupOrdered(job.Intent.Archive.VerifiedAt, read.ObservedAt) {
		return cleanupError(api.CodeIntegrity, "lb-v2-admin", "cleanup workspace differs from its protected identity or archive")
	}
	if read.WorktreeState != "present" || read.BranchState != "present" || read.Dirty == nil {
		return cleanupError(api.CodeContainmentUnknown, "lb-v2-admin", "cleanup workspace or branch state is unknown")
	}
	return nil
}

func cleanupObjects(job api.CleanupJob, inventory api.CleanupInventory, objects []api.ObjectDisposition) error {
	if len(objects) != len(inventory.Objects) {
		return cleanupError(api.CodeIntegrity, "lb-v2-service", "cleanup omitted an object disposition")
	}
	for i, object := range inventory.Objects {
		result := objects[i]
		eligible := object.OwnerLifeID == job.Intent.Cause.Target.LifeID && object.Role == "transient" &&
			object.Ref.Class == "artifact" && object.References == 0
		if result.ObjectID != object.Ref.ID {
			return cleanupError(api.CodeIntegrity, "lb-v2-service", "cleanup substituted an inventory object")
		}
		if result.Action == "remove" && !eligible {
			return cleanupError(api.CodeForbidden, "lb-v2-grants", "cleanup cannot delete unowned referenced or retained objects")
		}
	}
	return nil
}
