package lifecycle

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

type failedPlanWrite struct {
	Transaction api.Transaction
	Cleanup     []PlanCleanup
}

var _ api.FailedPlanStore = (*launchFixtureStore)(nil)

func (store *launchFixtureStore) FailPlan(ctx context.Context, tx api.Transaction, jobs []PlanCleanup) (api.Commit, error) {
	if err := ctx.Err(); err != nil {
		return api.Commit{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.failPlanErr != nil {
		return api.Commit{}, store.failPlanErr
	}
	return store.writeLaunch(ctx, tx, jobs)
}

func (store *launchFixtureStore) PlanCleanup(ctx context.Context, scope api.Scope, id api.ID) (PlanCleanup, error) {
	if err := ctx.Err(); err != nil {
		return PlanCleanup{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	job, ok := store.cleanups[id]
	if !ok || job.Cause.Config != scope.Config || job.Cause.Actor != scope.Actor {
		return PlanCleanup{}, launchMissing()
	}
	return job, nil
}

// This validation runs inside the same writer boundary as CAS, plan revision,
// events and the private outbox. A separate failed write or enqueue refuses.
func (store *launchFixtureStore) checkFailedPlan(tx api.Transaction, jobs []PlanCleanup) error {
	failed := len(tx.Writes.LaunchPlans) == 1 && tx.Writes.LaunchPlans[0].Phase == "failed" &&
		tx.Internal != nil && tx.Internal.Kind == api.InternalLaunchPlan
	if !failed {
		if len(jobs) != 0 {
			return launchConflict()
		}
		return nil
	}
	if len(jobs) != 1 && len(jobs) != 2 {
		return launchConflict()
	}
	record := tx.Writes.LaunchPlans[0]
	r := record.Reservation
	binding, bound := store.bindings[r.LaunchID]
	wantCount := 2
	if bound || store.plans[r.ID].Phase == "bound" || len(jobs) == 1 && jobs[0].Kind == "withdraw" && len(jobs[0].Issues) != 0 {
		wantCount = 1
	}
	if len(jobs) != 0 && len(jobs) != wantCount {
		return launchConflict()
	}
	var result launchStageResult
	meta, hasResult := store.metadata[launchObjectID(r.ID, "result-credential-slot")]
	_, hasInput := store.metadata[launchObjectID(r.ID, "input-credential-slot")]
	var resultRef api.BlobRef
	if hasResult && meta.SourceOperationID == r.OperationID && meta.Origin == "service" && meta.Ref.Class == "manifest" {
		resultRef = meta.Ref
	}
	var slot api.CredentialSlot
	known := resultRef != (api.BlobRef{}) && api.DecodeObject(store.blobs[meta.Ref.ID], &result) == nil && result.Schema == "laneboss.launch-stage.v2" &&
		validDigest(result.Input) && result.Error == nil &&
		api.DecodeObject(result.Value, &slot) == nil && cleanupSlotValid(slot)
	var inputSlot *api.CredentialSlot
	if r.Mode == "continue" {
		for _, intent := range store.continuations {
			if intent.OperationID == r.OperationID && intent.Target.LifeID == r.Target.LifeID && intent.Target.Run+1 == r.Target.Run &&
				intent.LogicalTurnID == tx.Internal.LogicalTurnID && intent.Slot != nil {
				value := *intent.Slot
				inputSlot = &value
				break
			}
		}
	}
	conflict := inputSlot != nil && store.plans[r.ID].Plan != nil && *inputSlot != store.plans[r.ID].Plan.Runner.Slot
	conflict = conflict || known && (inputSlot != nil && slot != *inputSlot ||
		store.plans[r.ID].Plan != nil && slot != store.plans[r.ID].Plan.Runner.Slot)
	if conflict {
		known = false
	}
	if !known && !conflict && inputSlot != nil && cleanupSlotValid(*inputSlot) {
		slot, known = *inputSlot, true
	}
	if !known && store.plans[r.ID].Plan != nil && cleanupSlotValid(store.plans[r.ID].Plan.Runner.Slot) {
		slot, known = store.plans[r.ID].Plan.Runner.Slot, true
	}
	if !hasResult && !hasInput && !known && store.plans[r.ID].Phase != "bound" {
		return launchConflict()
	}
	if !known {
		slot = api.CredentialSlot{}
	}
	for i, job := range jobs {
		kind := "withdraw"
		if len(jobs) == 2 {
			kind = []string{"release", "revoke_injection"}[i]
		}
		wantKind := api.InternalHelperRelease
		if kind == "withdraw" {
			wantKind = api.InternalHelperAbort
		}
		cause := job.Cause
		if job.Kind != kind || job.ID != launchObjectID(r.ID, "cleanup-"+kind) || job.ReservationID != r.ID || job.LaunchID != r.LaunchID ||
			job.Slot != slot || job.SlotKnown != known || job.SlotResult != resultRef || cause.ID != launchObjectID(r.ID, "cause-cleanup-"+kind) || cause.EffectID != job.ID ||
			cause.Kind != wantKind || cause.Config != r.Config || cause.Actor != tx.Scope.Actor || cause.RequestedBy != r.RequestedBy || cause.Target != r.Target ||
			cause.CauseOperationID != r.OperationID || cause.CauseRequestID != r.RequestID || cause.CancellationEpoch != r.CancellationEpoch ||
			cause.LogicalTurnID != tx.Internal.LogicalTurnID {
			return launchConflict()
		}
		validBinding := bound && binding.Record.ID == r.LaunchID && binding.Record.Config == r.Config && binding.Record.Target == r.Target &&
			binding.Prepared.Target == r.Target && validID(binding.Prepared.ID) && (record.Plan == nil || api.ValidateLaunchBindingPlan(binding, *record.Plan) == nil)
		if validBinding && (job.Prepared == nil || *job.Prepared != binding.Prepared) ||
			bound && !validBinding && (job.Prepared != nil || len(job.Issues) == 0) ||
			job.Withdrawal != nil && (job.Withdrawal.Cause != cause || job.Withdrawal.Reason != "refused") {
			return launchConflict()
		}
		if previous, exists := store.cleanups[job.ID]; exists && !reflect.DeepEqual(previous, job) {
			return launchConflict()
		}
	}
	return nil
}
