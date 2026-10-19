package api

import (
	"context"
	"reflect"
	"time"
)

// Installed service/native dependencies only. Journals authenticate the actual
// before/after operations; ReadObject and ReadWorkspace reopen current names.
// Reading the caller's proposed receipt back from a buffer is not this port.
type CleanupReadbacks interface {
	CheckCleanup(context.Context, CleanupJob, CleanupInventory) error
	ReadCleanupInventory(context.Context, CleanupJob, ID) (CleanupInventory, error)
	ReadCleanupReceipt(context.Context, CleanupJob, ID) (CleanupReceipt, error)
	ReadCleanupObjectResult(context.Context, CleanupJob, ID) (ObjectDisposition, error)
	ReadCleanupObject(context.Context, CleanupJob, CleanupObject) (ObjectReadback, error)
	ReadWorkspaceRemoval(context.Context, CleanupJob) (WorkspaceRemoval, error)
	ReadCleanupWorkspace(context.Context, CleanupJob) (WorkspaceReadback, error)
}

// Optional installed extension. It resolves the protected claim retained before
// removal, after authenticating the current job and exact native journal.
type CleanupRemovalReadbacks interface {
	ReadCleanupRemovalClaim(context.Context, CleanupJob, WorkspaceRemoval) (EffectLease, error)
}

// Optional private readback boundary for one verification operation. Native
// measurements may be memoized only until finish; a later VerifyCleanup call
// starts a fresh scope even if it reuses the same readback adapter or context.
type CleanupVerificationScope interface {
	BeginCleanupVerification(context.Context, CleanupJob) (context.Context, func(), error)
}

type CleanupVerification struct {
	Objects   []ObjectReadback
	Workspace WorkspaceReadback
	CheckedAt Timestamp
}

// Only VerifyCleanup creates this in-process value. Persisted receipt fields do
// not restore its authority: restart/reclaim requires the installed reads again.
type VerifiedCleanup struct {
	receipt                                                CleanupReceipt
	verification                                           CleanupVerification
	jobDigest, inventoryDigest, receiptDigest, proofDigest Digest
	removalClaim                                           EffectLease
	removalDigest                                          Digest
}

func cloneWorkspaceReadback(r WorkspaceReadback) WorkspaceReadback {
	if r.Dirty != nil {
		d := *r.Dirty
		r.Dirty = &d
	}
	return r
}

func cloneCleanupReceipt(r CleanupReceipt) CleanupReceipt {
	r.Objects = append([]ObjectDisposition(nil), r.Objects...)
	r.Workspace.Before = cloneWorkspaceReadback(r.Workspace.Before)
	r.Workspace.After = cloneWorkspaceReadback(r.Workspace.After)
	return r
}

func (v VerifiedCleanup) Receipt() CleanupReceipt { return cloneCleanupReceipt(v.receipt) }
func (v VerifiedCleanup) Evidence() CleanupVerification {
	r := v.verification
	r.Objects = append([]ObjectReadback(nil), r.Objects...)
	r.Workspace = cloneWorkspaceReadback(r.Workspace)
	return r
}

func cleanupIntegrity(owner, message string) error {
	return &Error{Code: CodeIntegrity, Owner: owner, Message: message,
		Instead: "Retain the original cleanup evidence and reconcile through the owning store or administrator."}
}

// This validator performs no removal. It requires protected journals AND fresh
// namespace/content reads before issuing the value accepted by completion.
func VerifyCleanup(ctx context.Context, source CleanupReadbacks, job CleanupJob, inventory CleanupInventory, receipt CleanupReceipt, clock Clock) (VerifiedCleanup, error) {
	var zero VerifiedCleanup
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if source == nil || reflect.ValueOf(source).Kind() == reflect.Pointer && reflect.ValueOf(source).IsNil() || clock == nil ||
		reflect.ValueOf(clock).Kind() == reflect.Pointer && reflect.ValueOf(clock).IsNil() {
		return zero, NotImplemented("lb-v2-service", "installed cleanup readback source")
	}
	if scoped, ok := source.(CleanupVerificationScope); ok {
		operation, finish, err := scoped.BeginCleanupVerification(ctx, job)
		if err != nil {
			return zero, err
		}
		if operation == nil || finish == nil {
			return zero, cleanupIntegrity("lb-v2-service", "cleanup verification scope is incomplete")
		}
		defer finish()
		ctx = operation
	}
	now := clock.Now()
	removalClaim := job.Claim
	if receipt.Workspace.ClaimID != job.Claim.ClaimID {
		claims, ok := source.(CleanupRemovalReadbacks)
		if !ok {
			return zero, cleanupIntegrity("lb-v2-service", "historical removal lacks its installed retained claim source")
		}
		var err error
		removalClaim, err = claims.ReadCleanupRemovalClaim(ctx, job, receipt.Workspace)
		if err != nil {
			return zero, err
		}
	}
	if err := validateCleanupReceiptClaim(job, inventory, receipt, removalClaim, now); err != nil {
		return zero, err
	}
	if err := source.CheckCleanup(ctx, job, inventory); err != nil {
		return zero, err
	}
	actualInventory, err := source.ReadCleanupInventory(ctx, job, inventory.ID)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(actualInventory, inventory) {
		return zero, cleanupIntegrity("lb-v2-service", "cleanup inventory differs from its protected complete inventory")
	}
	actualReceipt, err := source.ReadCleanupReceipt(ctx, job, receipt.ID)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(actualReceipt, receipt) {
		return zero, cleanupIntegrity("lb-v2-service", "cleanup receipt was not retained with its exact bytes")
	}
	proof := CleanupVerification{Objects: make([]ObjectReadback, 0, len(inventory.Objects))}
	observed := map[ID]bool{receipt.Workspace.Before.ID: true, receipt.Workspace.After.ID: true}
	for _, result := range receipt.Objects {
		observed[result.Before.ID], observed[result.After.ID] = true, true
	}
	for n, object := range inventory.Objects {
		journal, err := source.ReadCleanupObjectResult(ctx, job, object.Ref.ID)
		if err != nil {
			return zero, err
		}
		if !reflect.DeepEqual(journal, receipt.Objects[n]) {
			return zero, cleanupIntegrity("lb-v2-service", "cleanup object operation lacks its protected readback journal")
		}
		read, err := source.ReadCleanupObject(ctx, job, object)
		if err != nil {
			return zero, err
		}
		state := "present"
		if receipt.Objects[n].Action == "remove" {
			state = "absent"
		}
		if object.Role == "runtime" {
			state = read.State // Both states are independently measured and retain-only.
		}
		if observed[read.ID] || !cleanupObjectReadback(object, read, state, clock.Now()) || !cleanupOrder(receipt.Objects[n].After.ObservedAt, read.ObservedAt) {
			return zero, cleanupIntegrity("lb-v2-service", "cleanup object removal or retention failed independent readback")
		}
		observed[read.ID] = true
		proof.Objects = append(proof.Objects, read)
	}
	journal, err := source.ReadWorkspaceRemoval(ctx, job)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(journal, receipt.Workspace) {
		return zero, cleanupIntegrity("lb-v2-admin", "workspace removal lacks the actual unforced administrator journal")
	}
	workspace, err := source.ReadCleanupWorkspace(ctx, job)
	if err != nil {
		return zero, err
	}
	current := receipt.Workspace
	current.After = workspace
	if observed[workspace.ID] || ValidateWorkspaceRemovalReplay(job, current, removalClaim, receipt.Workspace.After.ObservedAt, clock.Now()) != nil || !cleanupOrder(receipt.Workspace.After.ObservedAt, workspace.ObservedAt) {
		return zero, cleanupIntegrity("lb-v2-admin", "workspace or branch failed independent absence readback")
	}
	proof.Workspace = workspace
	if err := source.CheckCleanup(ctx, job, inventory); err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	finished := clock.Now()
	if err := ValidateCleanupJob(job, finished); err != nil {
		return zero, err
	}
	proof.CheckedAt = Timestamp(finished.UTC().Format(time.RFC3339Nano))
	if owner := cleanupProofTimeOwner(proof); owner != "" {
		return zero, cleanupIntegrity(owner, "cleanup verification clock precedes a measured readback")
	}
	_, jd, err := cleanupCanonical(job)
	if err != nil {
		return zero, err
	}
	_, id, err := cleanupCanonical(inventory)
	if err != nil {
		return zero, err
	}
	_, rd, err := cleanupCanonical(receipt)
	if err != nil {
		return zero, err
	}
	_, pd, err := cleanupCanonical(proof)
	if err != nil {
		return zero, err
	}
	_, md, err := cleanupCanonical(removalClaim)
	if err != nil {
		return zero, err
	}
	return VerifiedCleanup{receipt: cloneCleanupReceipt(receipt), verification: proof,
		jobDigest: jd, inventoryDigest: id, receiptDigest: rd, proofDigest: pd, removalClaim: removalClaim, removalDigest: md}, nil
}

func cleanupProofTimeOwner(proof CleanupVerification) string {
	for _, read := range proof.Objects {
		if !cleanupOrder(read.ObservedAt, proof.CheckedAt) {
			return "lb-v2-service"
		}
	}
	if !cleanupOrder(proof.Workspace.ObservedAt, proof.CheckedAt) {
		return "lb-v2-admin"
	}
	return ""
}

// Called by the one writer with current authority/CAS still held. This is a
// structural completion check, not a substitute for that writer's live checks.
func ValidateCleanupCompletion(job CleanupJob, inventory CleanupInventory, verified VerifiedCleanup, lane Lane, event Event, outcome EffectOutcome, now time.Time) error {
	if err := validateCleanupReceiptClaim(job, inventory, verified.receipt, verified.removalClaim, now); err != nil {
		return err
	}
	_, jd, je := cleanupCanonical(job)
	_, id, ie := cleanupCanonical(inventory)
	_, rd, re := cleanupCanonical(verified.receipt)
	_, pd, pe := cleanupCanonical(verified.verification)
	_, md, me := cleanupCanonical(verified.removalClaim)
	if je != nil || ie != nil || re != nil || pe != nil || me != nil || md != verified.removalDigest || verified.jobDigest == "" || jd != verified.jobDigest || id != verified.inventoryDigest ||
		rd != verified.receiptDigest || pd != verified.proofDigest || !cleanupTime(verified.verification.CheckedAt, now) || cleanupProofTimeOwner(verified.verification) != "" {
		return launchInvalid("cleanup completion lacks its private readback verification")
	}
	if verified.receipt.Workspace.Action != "remove_clean" {
		return launchInvalid("retained dirty work cannot be marked cleaned")
	}
	removed, retained := []ID{}, []ID{}
	unowned := CleanupUnownedRetained(inventory, verified.receipt.Objects)
	for _, result := range verified.receipt.Objects {
		if result.Reason == "unknown" {
			return launchInvalid("unknown ownership cannot complete collection")
		}
		if result.Action == "remove" {
			removed = append(removed, result.ObjectID)
		} else {
			retained = append(retained, result.ObjectID)
		}
	}
	i, c := job.Intent, job.Intent.Cause
	expectedOutcome := EffectOutcome{EffectID: c.EffectID, ClaimID: job.Claim.ClaimID, ExpectedGeneration: job.Claim.Record.Generation, Status: "succeeded", Output: &verified.receipt.Manifest}
	if lane.LifeID != c.Target.LifeID || lane.Run != c.Target.Run || lane.Generation != i.ExpectedGeneration+1 || lane.CancellationEpoch != c.CancellationEpoch ||
		lane.State != i.Decision || !lane.Cleaned || lane.Workspace.ID != i.Workspace.ID ||
		event.Schema != SchemaVersion || !launchID(event.ID) || event.Origin != "service" || event.Kind != "lane.cleaned" || event.Config != c.Config || event.Actor != c.Actor || event.RequestedBy != c.RequestedBy ||
		event.OperationID != c.CauseOperationID || event.RequestID != c.CauseRequestID || event.LifeID != c.Target.LifeID || event.Run != c.Target.Run ||
		outcome.EffectID != c.EffectID || outcome.ClaimID != job.Claim.ClaimID || outcome.ExpectedGeneration != job.Claim.Record.Generation ||
		outcome.Status != "succeeded" || outcome.Error != nil || outcome.Output == nil || *outcome.Output != verified.receipt.Manifest || !reflect.DeepEqual(outcome, expectedOutcome) {
		return launchInvalid("cleanup completion lost its original lane, event or effect fence")
	}
	var body CleanEvent
	if DecodeObject(event.Payload, &body) != nil || !reflect.DeepEqual(body.ArchiveReceipt, i.Archive) ||
		!reflect.DeepEqual(body.Quiescence, i.Release.Quiescence) || !reflect.DeepEqual(body.RemovedObjectIDs, removed) || !reflect.DeepEqual(body.RetainedObjectIDs, retained) ||
		body.UnownedRetained != unowned {
		return launchInvalid("lane.cleaned differs from its measured cleanup receipt")
	}
	return nil
}

// CleanupUnownedRetained counts lane data, excluding the installed/historical
// runtime provenance catalog. Runtime nodes remain in the retained ID list.
func CleanupUnownedRetained(inventory CleanupInventory, objects []ObjectDisposition) UnownedRetained {
	runtime := map[ID]bool{}
	for _, object := range inventory.Objects {
		if object.Role == "runtime" {
			runtime[object.Ref.ID] = true
		}
	}
	var total UnownedRetained
	for _, object := range objects {
		if object.Reason == "unowned" && !runtime[object.ObjectID] {
			total.Objects++
			total.Bytes += object.Before.Bytes
		}
	}
	return total
}
