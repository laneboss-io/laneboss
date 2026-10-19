package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// The shared API owns the exact atomic writer and request types. These aliases
// retain source compatibility without a lifecycle-specific port or field copy.
type PlanCleanup = api.PlanCleanup
type FailedPlanStore = api.FailedPlanStore

func (execution *planExecution) stageResult(ctx context.Context, stage string) (launchStageResult, *api.BlobRef, error) {
	meta, err := execution.service.deps.Store.ObjectMetadata(ctx, execution.scope, launchObjectID(execution.record.Reservation.ID, "result-"+stage))
	if err != nil {
		return launchStageResult{}, nil, failure(err)
	}
	if meta.Origin != "service" || meta.SourceOperationID != execution.record.Reservation.OperationID || meta.Ref.Class != "manifest" {
		return launchStageResult{}, nil, integrity("failed plan stage lost its original provenance")
	}
	raw, err := execution.service.readBlob(ctx, execution.scope, meta.Ref)
	if err != nil {
		return launchStageResult{}, &meta.Ref, err
	}
	var result launchStageResult
	if api.DecodeObject(raw, &result) != nil || result.Schema != "laneboss.launch-stage.v2" || !validDigest(result.Input) {
		return launchStageResult{}, &meta.Ref, integrity("failed plan stage has no retained outcome")
	}
	return result, &meta.Ref, nil
}

func (execution *planExecution) failPlan(ctx context.Context, original error) error {
	if transientPlan(original) {
		return original
	}
	execution.input.turn = execution.lease.Record.Effect.Context.LogicalTurnID
	base, needed := execution.cleanupSlot(ctx)
	if !needed {
		return original
	}
	jobs := execution.cleanupJobs(ctx, base)
	store, ok := execution.service.deps.Store.(FailedPlanStore)
	if !ok || absent(store) {
		return errors.Join(original, api.NotImplemented("lb-v2-service", "atomic failed-plan credential cleanup outbox"))
	}
	if err := execution.checkClaim(ctx); err != nil {
		return errors.Join(original, err)
	}
	next := execution.record
	next.Phase, next.Error, next.Generation = "failed", failure(original).(*api.Error), next.Generation+1
	if next.Error.Owner == "" {
		terminal := *next.Error
		terminal.Owner = owner
		next.Error = &terminal
	}
	if api.ValidateLaunchPlanRecord(next) != nil {
		return errors.Join(original, integrity("failed plan cannot retain its terminal revision"))
	}
	r := next.Reservation
	cause := execution.writeCause(api.InternalLaunchPlan, "write")
	tx := api.Transaction{Scope: execution.scope, Internal: &cause,
		Writes:  api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{next}},
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: execution.record.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}
	if err := api.ValidateFailedPlanWrite(tx, jobs); err != nil {
		return errors.Join(original, failure(err))
	}
	if _, err := store.FailPlan(ctx, tx, jobs); err != nil {
		return errors.Join(original, failure(err))
	}
	retained, err := execution.service.deps.Store.LaunchPlan(ctx, execution.scope, r.ID)
	if err != nil || !sameFailedPlanBytes(retained, next) {
		return errors.Join(original, integrity("failed plan was not retained with its cleanup outbox"), failure(err))
	}
	for _, job := range jobs {
		actual, err := store.PlanCleanup(ctx, execution.scope, job.ID)
		if err != nil || !sameFailedPlanBytes(actual, job) {
			return errors.Join(original, integrity("failed plan cleanup was not retained exactly"), failure(err))
		}
	}
	execution.record = retained
	return original
}

// Error components are private diagnostics, absent from durable JSON. Compare
// every persisted field while preserving the original live error for its
// effect journal; process-local labels cannot make a correct readback fail.
func sameFailedPlanBytes(left, right any) bool {
	a, first := json.Marshal(left)
	b, second := json.Marshal(right)
	return first == nil && second == nil && bytes.Equal(a, b)
}

func (execution *planExecution) cleanupSlot(ctx context.Context) (PlanCleanup, bool) {
	r := execution.record.Reservation
	base := PlanCleanup{ReservationID: r.ID, LaunchID: r.LaunchID}
	result, ref, resultErr := execution.stageResult(ctx, "credential-slot")
	input, inputErr := execution.service.deps.Store.ObjectMetadata(ctx, execution.scope, launchObjectID(r.ID, "input-credential-slot"))
	if notFound(resultErr) && notFound(inputErr) && execution.input.slot == nil && execution.record.Plan == nil && execution.record.Phase != "bound" {
		return base, false
	}
	if ref != nil {
		base.SlotResult = *ref
	}
	if inputErr == nil {
		if input.Origin != "service" || input.SourceOperationID != r.OperationID || input.Ref.ID != launchObjectID(r.ID, "input-credential-slot") || input.Ref.Class != "manifest" {
			base.Issues = append(base.Issues, integrity("failed plan slot input has foreign provenance"))
		}
	} else if !notFound(inputErr) {
		base.Issues = append(base.Issues, cleanupIssue(inputErr))
	}
	var slot api.CredentialSlot
	resultSlot := resultErr == nil && result.Error == nil && api.DecodeObject(result.Value, &slot) == nil && cleanupSlotValid(slot)
	if resultErr == nil && result.Error == nil && !resultSlot {
		base.Issues = append(base.Issues, integrity("failed plan slot result is corrupt or incomplete"))
	}
	conflict := execution.input.slot != nil && execution.record.Plan != nil &&
		*execution.input.slot != execution.record.Plan.Runner.Slot
	conflict = conflict || resultSlot && (execution.input.slot != nil && slot != *execution.input.slot ||
		execution.record.Plan != nil && slot != execution.record.Plan.Runner.Slot)
	if conflict {
		resultSlot = false
		base.Issues = append(base.Issues, integrity("failed plan has conflicting retained slot selectors"))
	}
	base.SlotKnown = resultSlot
	if !base.SlotKnown && execution.record.Plan != nil && cleanupSlotValid(execution.record.Plan.Runner.Slot) {
		slot, base.SlotKnown = execution.record.Plan.Runner.Slot, true
	}
	if !base.SlotKnown && !conflict && execution.input.slot != nil && cleanupSlotValid(*execution.input.slot) {
		slot, base.SlotKnown = *execution.input.slot, true
	}
	if base.SlotKnown {
		base.Slot = slot
	}
	if resultErr != nil {
		base.Issues = append(base.Issues, cleanupIssue(resultErr))
	}
	return base, true
}

func cleanupSlotValid(slot api.CredentialSlot) bool {
	return validID(slot.ID) && validID(slot.LeaseID) && validID(slot.ProfileGrantID) && validID(slot.ProfileID) && slot.ExpiresAt != ""
}

// These errors come from protected Store reads. Preserve their full value and
// supply the dependency owner when the port returned an unowned typed error.
func cleanupIssue(err error) *api.Error {
	typed := failure(err).(*api.Error)
	if typed.Owner == "" {
		owned := *typed
		owned.Owner = "lb-v2-service"
		return &owned
	}
	return typed
}

func (execution *planExecution) cleanupJobs(ctx context.Context, base PlanCleanup) []PlanCleanup {
	r := execution.record.Reservation
	if !base.SlotKnown {
		base.Issues = append(base.Issues, problem(api.CodeContainmentUnknown, "failed plan slot requires original broker reconciliation", "Retain its original allocation until the broker resolves the retained result."))
	}
	result, ref, err := execution.stageResult(ctx, "injection")
	if err != nil && !notFound(err) {
		base.Issues = append(base.Issues, cleanupIssue(err))
	}
	base.InjectionOut = ref
	if err == nil && result.Error == nil {
		var injection api.Injection
		if api.DecodeObject(result.Value, &injection) == nil && injection.Target == r.Target {
			if execution.record.Plan != nil && !reflect.DeepEqual(injection, execution.record.Plan.Injection) {
				base.Issues = append(base.Issues, integrity("failed plan injection conflicts with its retained plan"))
			} else {
				base.Injection = &injection
			}
		} else {
			base.Issues = append(base.Issues, integrity("failed plan injection result is corrupt or foreign"))
		}
	}
	meta, err := execution.service.deps.Store.ObjectMetadata(ctx, execution.scope, launchObjectID(r.ID, "input-injection"))
	if err == nil {
		if meta.Origin != "service" || meta.SourceOperationID != r.OperationID || meta.Ref.Class != "manifest" {
			base.Issues = append(base.Issues, integrity("failed plan injection input has foreign provenance"))
		} else {
			base.InjectionIn = &meta.Ref
		}
	} else if !notFound(err) {
		base.Issues = append(base.Issues, cleanupIssue(err))
	}
	if base.InjectionIn != nil && base.InjectionOut == nil {
		base.Issues = append(base.Issues, problem(api.CodeContainmentUnknown, "failed injection has an unacknowledged outcome", "Reconcile the original injection journal before release."))
	}
	binding, err := execution.service.deps.Store.LaunchBinding(ctx, r.LaunchID)
	uncertain := err != nil && !notFound(err)
	if uncertain || notFound(err) && execution.record.Phase == "bound" {
		base.Issues = append(base.Issues, cleanupIssue(err))
	}
	kinds := []string{"release", "revoke_injection"}
	if err == nil || execution.record.Phase == "bound" || uncertain {
		kinds = []string{"withdraw"}
		if err == nil {
			if cleanupBinding(binding, execution.record) {
				base.Prepared = &binding.Prepared
			} else {
				base.Issues = append(base.Issues, integrity("failed plan binding requires original launch reconciliation"))
			}
		}
	}
	jobs := make([]PlanCleanup, 0, len(kinds))
	for _, kind := range kinds {
		job := base
		job.Kind, job.ID = kind, launchObjectID(r.ID, "cleanup-"+kind)
		job.Cause = execution.cause(api.InternalHelperRelease, "cleanup-"+kind)
		// This terminal batch is authored once by the current writer. Its
		// recorded cause must match that atomic commit, then remains retained.
		job.Cause.Actor = execution.scope.Actor
		job.Cause.EffectID = job.ID
		if kind == "withdraw" {
			job.Cause.Kind = api.InternalHelperAbort
			if job.Prepared != nil {
				projection, err := execution.service.deps.Store.CredentialProjection(ctx, r.Config, job.Prepared.ID)
				if err != nil {
					job.Issues = append(job.Issues, cleanupIssue(err))
				}
				if err == nil {
					if projection.Authority.Request.Prepared == *job.Prepared && execution.record.Handoff != nil &&
						reflect.DeepEqual(projection.Authority.Request.Handoff, *execution.record.Handoff) {
						withdrawal := api.CredentialWithdrawalRequest{ProjectionID: projection.Authority.ID,
							ExpectedGeneration: projection.Generation, Cause: job.Cause, Reason: "refused"}
						if api.ValidateCredentialWithdrawalRequest(projection, withdrawal) == nil && execution.prepareEffect(ctx, projection.Authority.Request) == nil {
							job.Withdrawal = &withdrawal
						} else {
							job.Issues = append(job.Issues, integrity("failed projection withdrawal requires current original authority"))
						}
					} else {
						job.Issues = append(job.Issues, integrity("failed projection requires original handoff reconciliation"))
					}
				}
			}
		}
		jobs = append(jobs, job)
	}
	return jobs
}

func cleanupBinding(binding api.LaunchBindingRequest, record api.LaunchPlanRecord) bool {
	r := record.Reservation
	return binding.Record.ID == r.LaunchID && binding.Record.Config == r.Config && binding.Record.Target == r.Target &&
		binding.Prepared.Target == r.Target && validID(binding.Prepared.ID) &&
		(record.Plan == nil || api.ValidateLaunchBindingPlan(binding, *record.Plan) == nil)
}
