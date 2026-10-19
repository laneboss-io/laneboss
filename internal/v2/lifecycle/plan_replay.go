package lifecycle

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// A retained plan is a claim about measured stages, not permission to recreate
// a missing allocation, data receipt, prompt or home after restart.
func (execution *planExecution) verifyPlanned(ctx context.Context, plan api.LaunchPlan) error {
	r, s := plan.Reservation, execution.service
	if err := execution.checkClaim(ctx); err != nil {
		return err
	}
	allocated, err := s.deps.Store.Effect(ctx, execution.scope, launchObjectID(r.ID, "allocate-effect"))
	if err != nil {
		return failure(err)
	}
	if effectRecord(allocated) != nil || allocated.Effect.HelperAllocate == nil || allocated.Effect.OperationID != r.OperationID ||
		allocated.Effect.HelperAllocate.ReservationID != r.ID || allocated.Outcome == nil ||
		allocated.State != api.EffectCompleted ||
		allocated.Outcome.Status != "succeeded" || allocated.Outcome.EffectID != allocated.Effect.ID ||
		allocated.Outcome.HelperLease == nil || *allocated.Outcome.HelperLease != plan.Lease || allocated.Outcome.Error != nil {
		return integrity("retained plan has no original measured allocation receipt")
	}
	data, err := execution.materialize(ctx, plan.Inputs, plan.Lease)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(data, plan.Data) {
		return integrity("retained plan changed its measured data receipt")
	}
	if err := retainedStage(ctx, execution, "credential-slot", plan.Runner.Slot); err != nil {
		return err
	}
	if err := retainedStage(ctx, execution, "injection", plan.Injection); err != nil {
		return err
	}
	if err := retainedStage(ctx, execution, "runner", plan.Runner); err != nil {
		return err
	}
	resolver, ok := s.deps.Sources.(api.LaunchStorageResolver)
	if !ok || absent(resolver) {
		return api.NotImplemented("lb-v2-admin", "LaunchStorageResolver.ResolveLaunchStorage")
	}
	storage, err := resolver.ResolveLaunchStorage(ctx, api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: plan.Lease.ID, Claim: api.PlanningClaim(r.ID, execution.lease)})
	if err != nil {
		return failure(err)
	}
	if storage.ReservationID != r.ID || storage.Target != r.Target || storage.LeaseID != plan.Lease.ID ||
		storage.WorkspaceID != plan.Data.Workspace.ID || storage.Home != plan.Data.Home {
		return integrity("launch restart changed its registered private storage")
	}
	for _, ref := range []api.BlobRef{plan.Runner.Prompt, plan.Data.Workspace.Snapshot, plan.Data.Materialization.Manifest,
		plan.Inputs.Sources.Runtime.Manifest, plan.Inputs.Sources.Project.Object} {
		if _, err := s.readBlob(ctx, execution.scope, ref); err != nil {
			return err
		}
	}
	return execution.checkClaim(ctx)
}

func retainedStage[T any](ctx context.Context, execution *planExecution, name string, want T) error {
	result, _, err := execution.stageResult(ctx, name)
	if err != nil {
		return err
	}
	var actual T
	if result.Error != nil || api.DecodeObject(result.Value, &actual) != nil || !reflect.DeepEqual(actual, want) {
		return integrity("retained plan changed its credential stage: " + name)
	}
	return nil
}
