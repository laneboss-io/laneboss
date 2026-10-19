package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"
)

// These are private G11 records, not new public request fields. PlanCleanup
// remains the separate failed-launch allocation cleanup contract.
type CleanupWorkspace struct {
	ID, RootID, RepositoryID                     ID
	Target                                       LifeRef
	Generation                                   Generation
	RootIdentity, DirectoryIdentity, GitIdentity string
	Branch, Head                                 string
}

type CleanupIntent struct {
	ID                 ID
	Cause              InternalIntent
	ExpectedGeneration Generation
	Decision           string
	Archive            ArchiveReceipt
	ArchiveRequest     ArchiveRequest
	Release            ReleaseReceipt
	Workspace          CleanupWorkspace
}

// The intent is stable; a retry/reclaim must resolve its current original effect
// claim again. A claim label supplied by a client is never this capability.
type CleanupJob struct {
	Intent CleanupIntent
	Claim  EffectLease
}

type CleanupObject struct {
	Ref                    BlobRef
	RootID                 ID
	RootIdentity, Identity string
	OwnerLifeID            ID
	OwnershipGeneration    Generation
	Role                   string
	References             uint64
}

type CleanupInventory struct {
	ID, IntentID                                           ID
	Config                                                 string
	Target                                                 LifeRef
	ExpectedGeneration, CancellationEpoch, GraphGeneration Generation
	Objects                                                []CleanupObject
	Manifest                                               BlobRef
}

type ObjectReadback struct {
	ID, ObjectID, RootID          ID
	RootIdentity, Identity, State string
	SHA256                        Digest
	Bytes                         int64
	ObservedAt                    Timestamp
}

type ObjectDisposition struct {
	ObjectID       ID
	Action, Reason string
	Before, After  ObjectReadback
}

type WorkspaceReadback struct {
	ID, WorkspaceID                              ID
	RootIdentity, DirectoryIdentity, GitIdentity string
	WorktreeState, BranchState, Head             string
	Dirty                                        *bool `json:",omitempty"`
	ObservedAt                                   Timestamp
}

type WorkspaceRemoval struct {
	IntentID, ClaimID ID
	Action            string
	Before, After     WorkspaceReadback
	Unforced, Synced  bool
}

type CleanupReceipt struct {
	ID, IntentID, ClaimID, InventoryID ID
	Objects                            []ObjectDisposition
	Workspace                          WorkspaceRemoval
	Manifest                           BlobRef
}

// Optional private ObjectStore extension: the single service writer owns
// reachability and deletion. Do not embed it into StateStore until that owner
// implements it. A data worker cannot acquire blob deletion by its worker label.
type CleanupObjectStore interface {
	ObjectStore
	BeginCleanup(context.Context, Scope, EffectLease) (CleanupJob, error)
	CleanupInventory(context.Context, Scope, CleanupJob) (CleanupInventory, error)
	CollectCleanupObjects(context.Context, Scope, CleanupJob, CleanupInventory) ([]ObjectDisposition, error)
	RetainCleanupReceipt(context.Context, Scope, CleanupJob, CleanupReceipt) (CleanupReceipt, error)
	CleanupReceipt(context.Context, Scope, ID) (CleanupReceipt, error)
	CompleteCleanup(context.Context, Scope, CleanupJob, VerifiedCleanup) (Commit, error)
}

// Administrator resolves these opaque handles in its protected storage/Git
// registry. No logical Workspace string is a host path or deletion permission.
type WorkspaceCollector interface {
	InspectCleanupWorkspace(context.Context, CleanupJob) (WorkspaceReadback, error)
	RemoveCleanupWorkspace(context.Context, CleanupJob, WorkspaceReadback) (WorkspaceRemoval, error)
}

type CleanupDataWorker interface {
	DataWorker
	CollectCleanup(context.Context, CleanupJob) (CleanupReceipt, error)
}

func cleanupActor(a Actor) bool {
	return launchID(a.ID) && (a.Kind == "human" && a.LifeID == "" && a.Level == 0 && a.Role == "" ||
		a.Kind == "lane" && launchID(a.LifeID) && a.Level >= 3 && a.Level <= 6 && launchID(ID(a.Role)))
}

func cleanupTime(t Timestamp, now time.Time) bool {
	v, err := time.Parse(time.RFC3339Nano, string(t))
	return err == nil && !v.IsZero() && !v.After(now)
}

func cleanupOrder(first, last Timestamp) bool {
	a, ae := time.Parse(time.RFC3339Nano, string(first))
	b, be := time.Parse(time.RFC3339Nano, string(last))
	return ae == nil && be == nil && !b.Before(a)
}

func ValidateCleanupJob(job CleanupJob, now time.Time) error {
	i, claim := job.Intent, job.Claim
	c, effect := i.Cause, claim.Record.Effect
	expires, err := time.Parse(time.RFC3339Nano, string(claim.ExpiresAt))
	if !launchID(i.ID) || !bindingConfigName.MatchString(c.Config) || c.Kind != InternalLifecycleEffect ||
		!launchID(c.ID) || c.ID == i.ID || c.Actor.Kind != "service" || !launchID(c.Actor.ID) || c.Actor.LifeID != "" || c.Actor.Level != 0 || c.Actor.Role != "" ||
		!cleanupActor(c.RequestedBy) || !launchID(c.CauseOperationID) || !launchID(c.CauseRequestID) || !launchID(c.EffectID) ||
		!launchID(c.Target.LifeID) || c.Target.Run == 0 || c.Target.Run > launchMaxInteger || c.CancellationEpoch > launchMaxInteger ||
		!launchGeneration(i.ExpectedGeneration) || i.ExpectedGeneration >= launchMaxInteger || i.Decision != "merged" && i.Decision != "abandoned" ||
		!launchID(claim.ClaimID) || claim.ClaimID != claim.Record.ClaimID || claim.ExpiresAt != claim.Record.ClaimExpiresAt ||
		!launchGeneration(claim.Record.Generation) || !EffectLeaseClaimed(claim) || claim.Record.Outcome != nil || err != nil || !now.Before(expires) ||
		effect.ID != c.EffectID || effect.OperationID != c.CauseOperationID || effect.Context == nil || !reflect.DeepEqual(*effect.Context, c) ||
		effect.Clean == nil || *effect.Clean != (CleanRequest{Target: c.Target, ExpectedGeneration: i.ExpectedGeneration, ArchiveReceiptID: i.Archive.ID}) {
		return launchInvalid("cleanup intent differs from its original live clean claim")
	}
	// Reuse the closed effect union rather than smuggling cleanup through Worker.
	if ValidateTransactionShape(Transaction{Scope: Scope{Config: c.Config}, Internal: &c, Effects: []Effect{effect}}) != nil {
		return launchInvalid("cleanup claim carries a competing effect payload")
	}
	a, release, w := i.Archive, i.Release, i.Workspace
	if !launchID(a.ID) || a.LifeID != c.Target.LifeID || !launchBlob(a.Manifest, "manifest") || !bindingDigest.MatchString(string(a.ArchiveSHA256)) ||
		a.ArchiveSHA256 != a.ReadBackSHA256 || !cleanupTime(a.VerifiedAt, now) || !launchID(a.StoreID) ||
		i.ArchiveRequest.Target != c.Target || !launchGeneration(i.ArchiveRequest.ExpectedGeneration) || i.ArchiveRequest.ExpectedGeneration > i.ExpectedGeneration ||
		ValidateReleaseReceipt(release) != nil || !launchID(release.ID) || release.Quiescence.Handle.Target != c.Target ||
		!launchID(release.LeaseID) || !launchID(release.ContainmentID) || !launchID(release.OperationID) || !launchID(release.EffectID) ||
		!launchID(release.Quiescence.Handle.ID) || release.Quiescence.Handle.Generation == "" ||
		!cleanupTime(release.ObservedAt, now) || !cleanupTime(release.Quiescence.ObservedAt, now) ||
		!launchID(w.ID) || !launchID(w.RootID) || !launchID(w.RepositoryID) || w.ID == w.RootID || w.RootID == w.RepositoryID || w.ID == w.RepositoryID ||
		w.Target != c.Target || !launchGeneration(w.Generation) || w.RootIdentity == "" || w.DirectoryIdentity == "" || w.GitIdentity == "" ||
		w.Branch != "lane/"+string(c.Target.LifeID) || !launchGitBase.MatchString(w.Head) {
		return launchInvalid("cleanup lacks its verified archive, quiescence or protected workspace")
	}
	return nil
}

// Manifest is zeroed when encoding its own canonical body. The store retains
// those exact bytes, then records their real BlobRef; this function does no I/O.
func CleanupInventoryBytes(inventory CleanupInventory) ([]byte, Digest, error) {
	inventory.Manifest = BlobRef{}
	return cleanupCanonical(inventory)
}

func CleanupReceiptBytes(receipt CleanupReceipt) ([]byte, Digest, error) {
	receipt.Manifest = BlobRef{}
	return cleanupCanonical(receipt)
}

func cleanupCanonical(value any) ([]byte, Digest, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	body, err := CanonicalObjectJSON(raw)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	return body, Digest(hex.EncodeToString(sum[:])), nil
}

func ValidateCleanupInventory(job CleanupJob, inventory CleanupInventory, now time.Time) error {
	if err := ValidateCleanupJob(job, now); err != nil {
		return err
	}
	i, c := job.Intent, job.Intent.Cause
	if !launchID(inventory.ID) || inventory.IntentID != i.ID || inventory.Config != c.Config || inventory.Target != c.Target ||
		inventory.ExpectedGeneration != i.ExpectedGeneration || inventory.CancellationEpoch != c.CancellationEpoch ||
		!launchGeneration(inventory.GraphGeneration) || len(inventory.Objects) == 0 {
		return launchInvalid("cleanup inventory lost its complete bounded ownership fence")
	}
	seen, archive := map[ID]bool{}, false
	for _, object := range inventory.Objects {
		validBlob := inventoryBlob(object.Ref)
		if object.Role == "runtime" {
			// File-backed vendor nodes keep their installation ceiling. This
			// grants no larger SQL blob, wire frame, lane ownership or removal.
			validBlob = launchID(object.Ref.ID) && bindingDigest.MatchString(string(object.Ref.SHA256)) && object.Ref.Class == "artifact" &&
				object.Ref.Bytes > 0 && object.Ref.Bytes <= MaxVendorBytes && object.OwnerLifeID == "" && object.OwnershipGeneration == 0
		}
		if !validBlob || !launchID(ID(object.Ref.Class)) || !launchID(object.RootID) || object.RootIdentity == "" || object.Identity == "" || seen[object.Ref.ID] ||
			object.OwnerLifeID != "" && !launchID(object.OwnerLifeID) ||
			!launchGeneration(object.OwnershipGeneration) && (object.OwnerLifeID != "" || object.OwnershipGeneration != 0) || object.References > launchMaxInteger {
			return launchInvalid("cleanup inventory repeats or loses an owned object identity")
		}
		switch object.Role {
		case "transient", "event", "input", "capture", "report", "archive", "history", "unknown", "runtime":
		default:
			return launchInvalid("cleanup object role is outside its retention catalog")
		}
		seen[object.Ref.ID] = true
		archive = archive || object.Ref == i.Archive.Manifest && object.Role == "archive"
	}
	body, digest, err := CleanupInventoryBytes(inventory)
	if err != nil {
		return err
	}
	if len(body) > MaxObjectBytes {
		return &Error{Code: CodeBudget, Owner: "lb-v2-service", Message: "cleanup inventory exceeds its bounded immutable object budget", Instead: "Increase the approved installation/storage budget without truncating inventory."}
	}
	if !archive || !launchBlob(inventory.Manifest, "manifest") || inventory.Manifest.SHA256 != digest || inventory.Manifest.Bytes != int64(len(body)) || seen[inventory.Manifest.ID] {
		return launchInvalid("cleanup inventory omitted the retained archive or its exact manifest")
	}
	return nil
}

// An object with no owning lane (installed runtime, client and task objects every launch references, box 108)
// has a known service owner: it is preserved as unowned instead of blocking every lane's clean (item 36).
func cleanupDisposition(object CleanupObject, target LifeRef) (string, string) {
	if object.Role == "unknown" {
		return "retain", "unknown"
	}
	if object.OwnerLifeID != target.LifeID {
		return "retain", "unowned"
	}
	if object.References != 0 {
		return "retain", "referenced"
	}
	if object.Role != "transient" {
		return "retain", object.Role
	}
	if object.Ref.Class != "artifact" {
		return "retain", "history"
	}
	return "remove", "unreferenced"
}

func cleanupObjectReadback(o CleanupObject, read ObjectReadback, state string, now time.Time) bool {
	if !launchID(read.ID) || read.ObjectID != o.Ref.ID || read.RootID != o.RootID || read.RootIdentity != o.RootIdentity ||
		read.State != state || !cleanupTime(read.ObservedAt, now) {
		return false
	}
	if state == "absent" {
		return read.Identity == "" && read.SHA256 == "" && read.Bytes == 0
	}
	return state == "present" && read.Identity == o.Identity && read.SHA256 == o.Ref.SHA256 && read.Bytes == o.Ref.Bytes
}

func ValidateWorkspaceRemoval(job CleanupJob, receipt WorkspaceRemoval, now time.Time) error {
	if err := ValidateCleanupJob(job, now); err != nil {
		return err
	}
	return validateWorkspaceRemovalBody(job, receipt, job.Claim.ClaimID, now)
}

func validateWorkspaceRemovalBody(job CleanupJob, receipt WorkspaceRemoval, claimID ID, now time.Time) error {
	w, before, after := job.Intent.Workspace, receipt.Before, receipt.After
	for _, read := range []WorkspaceReadback{before, after} {
		if !launchID(read.ID) || read.WorkspaceID != w.ID || read.RootIdentity != w.RootIdentity || read.GitIdentity != w.GitIdentity || !cleanupTime(read.ObservedAt, now) {
			return launchInvalid("workspace removal changed its protected parent or Git identity")
		}
	}
	if receipt.IntentID != job.Intent.ID || receipt.ClaimID != claimID || !receipt.Unforced || !receipt.Synced || before.ID == after.ID ||
		!cleanupOrder(before.ObservedAt, after.ObservedAt) || !cleanupOrder(job.Intent.Archive.VerifiedAt, before.ObservedAt) ||
		before.WorktreeState != "present" || before.BranchState != "present" || before.DirectoryIdentity != w.DirectoryIdentity || before.Head != w.Head || before.Dirty == nil {
		return launchInvalid("workspace removal lacks its original dirty-work decision and unforced journal")
	}
	if *before.Dirty {
		if receipt.Action != "retain_dirty" || after.WorktreeState != "present" || after.BranchState != "present" ||
			after.DirectoryIdentity != w.DirectoryIdentity || after.Head != w.Head || after.Dirty == nil || !*after.Dirty {
			return launchInvalid("dirty workspace or branch was removed or relabeled clean")
		}
	} else if receipt.Action != "remove_clean" || after.WorktreeState != "absent" || after.BranchState != "absent" || after.DirectoryIdentity != "" || after.Head != "" || after.Dirty != nil {
		return launchInvalid("workspace or branch absence was not read back")
	}
	return nil
}

func ValidateCleanupReceipt(job CleanupJob, inventory CleanupInventory, receipt CleanupReceipt, now time.Time) error {
	return validateCleanupReceiptClaim(job, inventory, receipt, job.Claim, now)
}

// Shape check only: the installed store must authenticate removalClaim from its
// retained pre-removal record. A caller's historical claim label is no authority.
func ValidateCleanupReceiptWithRemoval(job CleanupJob, inventory CleanupInventory, receipt CleanupReceipt, removalClaim EffectLease, now time.Time) error {
	return validateCleanupReceiptClaim(job, inventory, receipt, removalClaim, now)
}

func validateCleanupReceiptClaim(job CleanupJob, inventory CleanupInventory, receipt CleanupReceipt, removalClaim EffectLease, now time.Time) error {
	if err := ValidateCleanupInventory(job, inventory, now); err != nil {
		return err
	}
	if !launchID(receipt.ID) || receipt.IntentID != job.Intent.ID || receipt.ClaimID != job.Claim.ClaimID || receipt.InventoryID != inventory.ID || len(receipt.Objects) != len(inventory.Objects) || receipt.Manifest.ID == inventory.Manifest.ID {
		return launchInvalid("cleanup receipt omitted or substituted an inventory member")
	}
	seen := map[ID]bool{}
	for n, object := range inventory.Objects {
		result := receipt.Objects[n]
		action, reason := cleanupDisposition(object, job.Intent.Cause.Target)
		state := "present"
		beforeState := "present"
		if action == "remove" {
			state = "absent"
		}
		if object.Role == "runtime" {
			// Provenance keeps old pins after an upgrade. The installed reader
			// proves current presence/absence; neither state grants removal.
			beforeState, state = result.Before.State, result.After.State
		}
		if result.ObjectID != object.Ref.ID || result.Action != action || result.Reason != reason ||
			!cleanupOrder(result.Before.ObservedAt, result.After.ObservedAt) || !cleanupOrder(job.Intent.Archive.VerifiedAt, result.Before.ObservedAt) ||
			receipt.Manifest.ID == object.Ref.ID ||
			!cleanupObjectReadback(object, result.Before, beforeState, now) || !cleanupObjectReadback(object, result.After, state, now) ||
			seen[result.Before.ID] || seen[result.After.ID] || result.Before.ID == result.After.ID {
			return launchInvalid("cleanup object disposition lacks its exact removal or retention readback")
		}
		seen[result.Before.ID], seen[result.After.ID] = true, true
	}
	if err := ValidateWorkspaceRemovalReplay(job, receipt.Workspace, removalClaim, receipt.Workspace.After.ObservedAt, now); err != nil {
		return err
	}
	body, digest, err := CleanupReceiptBytes(receipt)
	if err != nil {
		return err
	}
	if !launchBlob(receipt.Manifest, "manifest") || receipt.Manifest.SHA256 != digest || receipt.Manifest.Bytes != int64(len(body)) {
		return launchInvalid("cleanup receipt does not name its exact retained bytes")
	}
	return nil
}

// A replay keeps the journal's actual removing claim while the current job
// retains its live claim. Validate that old claim at the measured removal time,
// then validate fresh namespace reads at now without relabeling the journal.
func ValidateWorkspaceRemovalReplay(job CleanupJob, receipt WorkspaceRemoval, removalClaim EffectLease, removedAt Timestamp, now time.Time) error {
	if err := ValidateCleanupJob(job, now); err != nil {
		return err
	}
	if removalClaim.ClaimID == job.Claim.ClaimID {
		if !reflect.DeepEqual(removalClaim, job.Claim) {
			return launchInvalid("workspace removal claim revision differs")
		}
		return validateWorkspaceRemovalBody(job, receipt, job.Claim.ClaimID, now)
	}
	when, err := time.Parse(time.RFC3339Nano, string(removedAt))
	if err != nil || when.After(now) {
		return launchInvalid("workspace removal has no historical measurement time")
	}
	original := CleanupJob{Intent: job.Intent, Claim: removalClaim}
	if err := ValidateCleanupJob(original, when); err != nil {
		return err
	}
	if !reflect.DeepEqual(removalClaim.Record.Effect, job.Claim.Record.Effect) || removalClaim.Record.Generation >= job.Claim.Record.Generation {
		return launchInvalid("workspace removal was not performed by an earlier original claim")
	}
	return validateWorkspaceRemovalBody(job, receipt, removalClaim.ClaimID, now)
}

// An inventory object may be empty: the store retains zero-byte objects (box 104: an archived lane's empty
// output parts), and only a launch input's BlobRef must carry bytes.
func inventoryBlob(ref BlobRef) bool {
	return launchID(ref.ID) && bindingDigest.MatchString(string(ref.SHA256)) && ref.Bytes >= 0 && ref.Bytes <= MaxObjectBytes
}
