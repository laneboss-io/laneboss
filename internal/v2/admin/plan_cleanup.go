package admin

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.PlanCleanupNativeReader = (*Service)(nil)

// The live cleanup claim selects the retained helper effect. Neither a caller
// supplied receipt nor the expired planning effect can replace its journal.
func (s *Service) ReadPlanCleanupNative(ctx context.Context, scope api.Scope, claim api.PlanCleanupClaim, effect api.Effect) (api.EffectOutcome, error) {
	store, ok := s.deps.Store.(api.PlanCleanupStore)
	if !ok || store == nil {
		return api.EffectOutcome{}, api.NotImplemented(owner, "live failed-plan cleanup authority")
	}
	if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.EffectOutcome{}, err
	}
	allocation, err := store.PlanCleanupAllocation(ctx, scope, claim)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	id := claim.Request.ID
	if claim.Request.Kind == "revoke_injection" {
		id = api.ID(digestBytes([]byte("launch\x00" + string(claim.Request.ReservationID) + "\x00cleanup-release")))
	}
	current, err := s.deps.Store.Effect(ctx, scope, id)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	if effect.ID != id || !reflect.DeepEqual(current.Effect, effect) || effect.Context == nil ||
		effect.Context.Config != s.deps.Config || effect.Context.Target != claim.Request.Cause.Target ||
		(effect.HelperAbort == nil || effect.HelperAbort.LeaseID != allocation.ID) &&
			(effect.HelperRelease == nil || effect.HelperRelease.LeaseID != allocation.ID) {
		return api.EffectOutcome{}, failure(api.CodeForbidden, "native cleanup read differs from its original allocation and retained effect")
	}
	var result api.EffectOutcome
	if err := s.call(ctx, "plan_cleanup_native_read", effect, &result); err != nil {
		return api.EffectOutcome{}, err
	}
	if err := store.CheckPlanCleanupClaim(ctx, scope, claim); err != nil {
		return api.EffectOutcome{}, err
	}
	if result.EffectID != effect.ID || result.Status != "succeeded" || result.Error != nil ||
		(result.Abort == nil) == (result.Release == nil) ||
		result.Abort != nil && (effect.HelperAbort == nil || result.Abort.LeaseID != allocation.ID || result.Abort.Quiescence.Handle.ContainmentID != allocation.ContainmentID) ||
		result.Release != nil && (effect.HelperRelease == nil || result.Release.LeaseID != allocation.ID || result.Release.ContainmentID != allocation.ContainmentID) {
		return api.EffectOutcome{}, failure(api.CodeIntegrity, "native cleanup journal returned another terminal measurement")
	}
	return result, nil
}

func (m *leaseManager) readPlanCleanupNative(ctx context.Context, effect api.Effect) (api.EffectOutcome, error) {
	if err := contextError(ctx); err != nil {
		return api.EffectOutcome{}, err
	}
	if effect.Context == nil || effect.ID != effect.Context.EffectID || effect.OperationID != effect.Context.CauseOperationID ||
		!reflect.DeepEqual(effect, api.Effect{ID: effect.ID, OperationID: effect.OperationID, Context: effect.Context, HelperAbort: effect.HelperAbort, HelperRelease: effect.HelperRelease}) {
		return api.EffectOutcome{}, failure(api.CodeForbidden, "native cleanup read changed its retained effect envelope")
	}
	var lease api.ID
	if effect.HelperAbort != nil && effect.HelperRelease == nil {
		lease = effect.HelperAbort.LeaseID
	}
	if effect.HelperRelease != nil && effect.HelperAbort == nil {
		lease = effect.HelperRelease.LeaseID
	}
	if !validID(lease) {
		return api.EffectOutcome{}, failure(api.CodeForbidden, "native cleanup read requires one retained teardown effect")
	}
	record, err := m.find(lease)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	result := api.EffectOutcome{EffectID: effect.ID, Status: "succeeded"}
	// The journal keeps the request as the native stage accepted it: its cause may carry the live claimant of this
	// effect in place of the retained author, and nothing else may differ.
	claimant := attemptClaimant(ctx, effect.ID)
	if effect.HelperAbort != nil {
		if record.Phase != "aborted" || record.Abort == nil || record.AbortReceipt == nil || !retainedAbort(effect.HelperAbort, *record.Abort, claimant) {
			return api.EffectOutcome{}, failure(api.CodeContainmentUnknown, "native abort has no matching terminal helper journal")
		}
		if err := validateAbortReceipt(record, *record.Abort, *record.AbortReceipt); err != nil {
			return api.EffectOutcome{}, err
		}
		result.Abort = record.AbortReceipt
	} else {
		if record.Phase != "released" || record.Release == nil || record.Receipt == nil || !retainedRelease(effect.HelperRelease, *record.Release, claimant) {
			return api.EffectOutcome{}, failure(api.CodeContainmentUnknown, "native release has no matching terminal helper journal")
		}
		if err := validateReceipt(record, *record.Release, *record.Receipt); err != nil {
			return api.EffectOutcome{}, err
		}
		result.Release = record.Receipt
	}
	return result, nil
}
