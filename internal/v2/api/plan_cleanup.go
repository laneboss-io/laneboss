package api

import (
	"context"
	"reflect"
)

// PlanCleanup is a private durable request, never a release/quiescence receipt.
// This preserves lifecycle 87f5dad's exact local port fields.
type PlanCleanup struct {
	ID            ID
	Kind          string
	Cause         InternalIntent
	ReservationID ID
	LaunchID      ID
	Slot          CredentialSlot
	SlotResult    BlobRef
	SlotKnown     bool
	Injection     *Injection
	InjectionIn   *BlobRef
	InjectionOut  *BlobRef
	Prepared      *PreparedLaunch
	Withdrawal    *CredentialWithdrawalRequest
	Issues        []*Error
}

// This extends the existing single writer. It is not a second effect union.
// The transaction and all cleanup rows commit together or neither.
type FailedPlanStore interface {
	FailPlan(context.Context, Transaction, []PlanCleanup) (Commit, error)
	PlanCleanup(context.Context, Scope, ID) (PlanCleanup, error)
}

// PlanCleanupClaim is an attempt at an immutable private cleanup request. It is
// deliberately separate from EffectLease: the failed planner grants no helper
// abort/release authority, and cleanup is not a new member of the Effect union.
type PlanCleanupClaim struct {
	Request    PlanCleanup
	Generation Generation
	ClaimID    ID
	ClaimantID ID
	ExpiresAt  Timestamp
}

// PlanCleanupReceipt retains the actual resource owners' terminal evidence.
// A broker acknowledgement is metadata, never credential material. Native and
// broker owners must read their original journals on retry, including after a
// new claimant replaces an expired attempt.
type PlanCleanupReceipt struct {
	ID            ID
	CleanupID     ID
	ReservationID ID
	LaunchID      ID
	Kind          string
	SlotID        ID
	Allocation    HelperLease
	Broker        BlobRef
	Release       *ReleaseReceipt
	Abort         *AbortReceipt
	Withdrawal    *CredentialProjectionRecord
	CompletedAt   Timestamp
}

// These exact bytes form Receipt.Broker. The credential owner retains them
// only after reading back its slot/injection tombstones and native journal.
type PlanCleanupBrokerReceipt struct {
	CleanupID       ID
	ReservationID   ID
	LaunchID        ID
	Kind            string
	Slot            CredentialSlot
	Injection       *Injection
	NativeReceiptID ID
	ProjectionID    ID
	CompletedAt     Timestamp
}

type PlanCleanupStatus struct {
	Request    PlanCleanup
	Generation Generation
	State      string
	Claim      *PlanCleanupClaim
	Receipt    *PlanCleanupReceipt
	Refusal    *Error
}

// PlanCleanupExecutor is a protected resource-owner capability, never an RPC
// argument. Both execution and independent journal read-back must resolve the
// original selectors and call CheckPlanCleanupClaim before external work.
type PlanCleanupExecutor interface {
	ExecutePlanCleanup(context.Context, Scope, PlanCleanupClaim) (PlanCleanupReceipt, error)
	ReadPlanCleanupReceipt(context.Context, Scope, PlanCleanupClaim) (PlanCleanupReceipt, error)
}

// PlanCleanupNativeReader independently reads the helper's original terminal
// journal. Execution itself uses the retained HelperAbort/HelperRelease effect
// and its actual EffectLease; this port never creates an execution attempt.
type PlanCleanupNativeReader interface {
	ReadPlanCleanupNative(context.Context, Scope, PlanCleanupClaim, Effect) (EffectOutcome, error)
}

type planCleanupClaimContextKey struct{}

// This private context carries a cleanup attempt separately from the immutable
// projection fence. Receivers must authenticate it against the live outbox.
func WithPlanCleanupClaim(ctx context.Context, claim PlanCleanupClaim) context.Context {
	return context.WithValue(ctx, planCleanupClaimContextKey{}, claim)
}

func PlanCleanupClaimFromContext(ctx context.Context) (PlanCleanupClaim, bool) {
	claim, ok := ctx.Value(planCleanupClaimContextKey{}).(PlanCleanupClaim)
	return claim, ok
}

// PlanCleanupStore extends the same single writer. Refused attempts stay
// pending with their full typed cause; only measured completion is terminal.
type PlanCleanupStore interface {
	FailedPlanStore
	PendingPlanCleanup(context.Context, Scope) ([]PlanCleanup, error)
	PlanCleanupStatus(context.Context, Scope, ID) (PlanCleanupStatus, error)
	ClaimPlanCleanup(context.Context, Scope, PlanCleanup, EffectClaimRequest) (PlanCleanupClaim, error)
	CheckPlanCleanupClaim(context.Context, Scope, PlanCleanupClaim) error
	PlanCleanupAllocation(context.Context, Scope, PlanCleanupClaim) (HelperLease, error)
	RecordPlanCleanupRefusal(context.Context, Scope, PlanCleanupClaim, *Error) error
	CompletePlanCleanup(context.Context, Scope, PlanCleanupClaim, PlanCleanupReceipt, PlanCleanupExecutor) (PlanCleanupReceipt, error)
}

// Correlation preflight only. The writer additionally resolves the live original
// claim, reservation, cancellation and projection under its lock.
func ValidateFailedPlanWrite(tx Transaction, jobs []PlanCleanup) error {
	if err := validateTransactionShape(tx, true); err != nil {
		return err
	}
	if tx.Internal == nil || tx.Internal.Kind != InternalLaunchPlan || len(tx.Writes.LaunchPlans) != 1 ||
		len(tx.Effects) != 0 || len(tx.Writes.Grants) != 0 || len(tx.Writes.WorkerLeases) != 0 || len(jobs) == 0 || len(jobs) > 2 {
		return launchInvalid("failed plan requires one atomic cleanup batch")
	}
	record := tx.Writes.LaunchPlans[0]
	r := record.Reservation
	if record.Phase != "failed" || record.Error == nil || !validLaunchPlanWriteMode(tx, record, true) {
		return launchInvalid("cleanup batch is not bound to its failed plan revision")
	}
	for _, event := range tx.Events {
		if event.Kind != "launch.planned" && event.Kind != "capture.refused" {
			return launchInvalid("failed plan carries a non-failure event")
		}
	}
	seen, kinds := map[ID]bool{tx.Internal.EffectID: true}, map[string]bool{}
	seenCauses := map[ID]bool{tx.Internal.ID: true}
	var common *PlanCleanup
	for _, job := range jobs {
		cause := job.Cause
		if !launchID(job.ID) || seen[job.ID] || kinds[job.Kind] || job.ReservationID != r.ID || job.LaunchID != r.LaunchID ||
			cause.Config != r.Config || cause.Target != r.Target || cause.CauseOperationID != r.OperationID ||
			cause.CauseRequestID != r.RequestID || cause.RequestedBy != r.RequestedBy || cause.CancellationEpoch != r.CancellationEpoch ||
			cause.Actor != tx.Internal.Actor || !launchID(cause.ID) || seenCauses[cause.ID] || cause.EffectID != job.ID ||
			r.Loop != nil && cause.LogicalTurnID != r.Loop.LogicalTurnID ||
			!launchBlob(job.SlotResult, "manifest") ||
			job.SlotKnown && (!launchID(job.Slot.ID) || !launchID(job.Slot.ProfileGrantID) || !launchID(job.Slot.ProfileID) ||
				!launchID(job.Slot.LeaseID) || job.Slot.ExpiresAt == "") ||
			!job.SlotKnown && (job.Slot != (CredentialSlot{}) || len(job.Issues) == 0) {
			return launchInvalid("cleanup request changed its original allocation or cause")
		}
		seen[job.ID], kinds[job.Kind] = true, true
		seenCauses[cause.ID] = true
		if record.Plan != nil && (!job.SlotKnown || job.Slot != record.Plan.Runner.Slot ||
			job.Injection != nil && !reflect.DeepEqual(*job.Injection, record.Plan.Injection)) {
			return launchInvalid("cleanup resources differ from the retained plan")
		}
		switch job.Kind {
		case "withdraw":
			if cause.Kind != InternalHelperAbort || job.Withdrawal == nil && len(job.Issues) == 0 {
				return launchInvalid("projection cleanup lacks its withdrawal or reconciliation issue")
			}
		case "release", "revoke_injection":
			if cause.Kind != InternalHelperRelease || job.Prepared != nil || job.Withdrawal != nil {
				return launchInvalid("unprojected cleanup carries a prepared projection")
			}
		default:
			return launchInvalid("unknown failed plan cleanup kind")
		}
		if job.Injection != nil && job.Injection.Target != r.Target {
			return launchInvalid("cleanup injection belongs to another life")
		}
		for _, ref := range []*BlobRef{job.InjectionIn, job.InjectionOut} {
			if ref != nil && !launchBlob(*ref, "manifest") {
				return launchInvalid("cleanup stage reference is invalid")
			}
		}
		for _, issue := range job.Issues {
			if issue == nil || issue.Code == "" || issue.Owner == "" {
				return launchInvalid("cleanup reconciliation issue lacks its owner")
			}
		}
		if job.Prepared != nil && (!launchID(job.Prepared.ID) || job.Prepared.ID == r.LaunchID ||
			!launchID(job.Prepared.ContainmentID) || !launchGeneration(job.Prepared.EndpointGeneration) ||
			!launchID(job.Prepared.GateID) || job.Prepared.ProcessGeneration == "" ||
			job.Prepared.Target != r.Target || record.Handoff == nil || job.Prepared.SpecSHA256 != record.Handoff.SpecSHA256 ||
			record.Plan != nil && (job.Prepared.ContainmentID != record.Plan.Lease.ContainmentID || job.Prepared.EndpointGeneration != record.Plan.Lease.EndpointGeneration)) {
			return launchInvalid("cleanup prepared gate differs from the retained plan")
		}
		if w := job.Withdrawal; w != nil {
			if job.Kind != "withdraw" || job.Prepared == nil || !launchID(w.ProjectionID) || !launchGeneration(w.ExpectedGeneration) ||
				!reflect.DeepEqual(w.Cause, cause) || w.Reason != "refused" {
				return launchInvalid("cleanup withdrawal changed its original projection fence")
			}
		}
		normalized := job
		normalized.ID, normalized.Kind, normalized.Cause = "", "", InternalIntent{}
		if common != nil && !reflect.DeepEqual(*common, normalized) {
			return launchInvalid("cleanup batch mixed different allocations")
		}
		common = &normalized
	}
	if kinds["withdraw"] && len(jobs) != 1 || !kinds["withdraw"] && !(kinds["release"] && kinds["revoke_injection"]) {
		return launchInvalid("failed plan omitted a required cleanup request")
	}
	return nil
}
