package lifecycle

import (
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Correlate the original measured holding at its recorded time. This grants
// no fresh opening authority and does not require a still-live prepare claim,
// a closed gate, or currently unrevoked sources for an already-opened process.
func historicalProjection(record api.CredentialProjectionRecord, binding api.LaunchBindingRequest, plan api.LaunchPlan) error {
	a, receipt := record.Authority, record.Receipt
	if !validGeneration(a.Generation) || !validGeneration(record.Generation) || receipt == nil ||
		receipt.ProjectionID != a.ID || receipt.Generation != a.Generation+1 || receipt.Prepared != binding.Prepared ||
		receipt.HelperLeaseID != plan.Lease.ID || receipt.SpecSHA256 != binding.Prepared.SpecSHA256 ||
		receipt.Home != plan.Data.Home || receipt.CancellationEpoch != plan.Reservation.CancellationEpoch || !validTime(receipt.ObservedAt) ||
		len(a.Targets) == 0 || len(receipt.Targets) != len(a.Targets) || len(a.Sources) != len(a.Targets) ||
		receipt.HeldDescriptors == nil || *receipt.HeldDescriptors != uint64(len(a.Targets)) || receipt.InheritedSources == nil || *receipt.InheritedSources != 0 {
		return integrity("opened projection lost its original holding receipt")
	}
	observed, _ := time.Parse(time.RFC3339Nano, string(receipt.ObservedAt))
	targets, err := api.CredentialTargets(a.Request, observed)
	if err != nil || !reflect.DeepEqual(targets, a.Targets) {
		return integrity("opened projection changed its retained credential targets")
	}
	objects := map[string]bool{}
	for i, target := range targets {
		source, held := a.Sources[i], receipt.Targets[i]
		if source.Key != target.Key || !validGeneration(source.Generation) || source.Version == "" || target.SlotID == "" && source.Version != target.Version ||
			held.Target != target || held.RootID != plan.Data.Home.RootID || held.HomeGeneration != plan.Data.Home.Generation ||
			held.ObjectID == "" || held.SourceObjectID == "" || held.ObjectID == held.SourceObjectID || objects[held.ObjectID] || held.WritableByOthers ||
			target.Delivery == "file" && (held.OwnerUID != plan.Lease.UID || held.Mode != target.FileMode || held.Links != 1) ||
			target.FileMode == 0400 && (!held.ReadOnlyView || held.ParentMode != 0500) ||
			target.FileMode == 0600 && held.ParentMode != 0700 ||
			target.Delivery == "env" && (held.OwnerUID != 0 || held.Mode != 0600 || held.ParentMode != 0700) {
			return integrity("opened projection changed its original sources or held objects")
		}
		objects[held.ObjectID] = true
	}
	if record.State == "held" {
		if record.Fence != nil || record.Withdrawal != nil || record.Generation != receipt.Generation {
			return integrity("opened held projection has an inconsistent fence")
		}
		return nil
	}
	fence := record.Fence
	if fence == nil || fence.ProjectionID != a.ID || fence.ExpectedGeneration != receipt.Generation ||
		fence.Cause.Config != plan.Reservation.Config || fence.Cause.Target != binding.Prepared.Target ||
		fence.Cause.Actor.Kind != "service" || !validID(fence.Cause.Actor.ID) || !validID(fence.Cause.ID) ||
		!validID(fence.Cause.EffectID) || !validID(fence.Cause.CauseOperationID) ||
		fence.Cause.CancellationEpoch < plan.Reservation.CancellationEpoch || uint64(fence.Cause.CancellationEpoch) > maxInteger ||
		fence.Cause.Kind != api.InternalHelperStop && fence.Cause.Kind != api.InternalHelperAbort && fence.Cause.Kind != api.InternalHelperRelease {
		return integrity("opened withdrawing projection lost its original fence")
	}
	switch fence.Reason {
	case "refused", "revoked", "expired", "cancelled", "release", "restart":
	default:
		return integrity("opened projection has an invalid withdrawal reason")
	}
	if record.State == "withdrawing" && (record.Generation != receipt.Generation+1 || record.Withdrawal != nil) ||
		record.State == "withdrawn" && record.Generation != receipt.Generation+2 {
		return integrity("opened projection changed its withdrawal revision")
	}
	if w := record.Withdrawal; w != nil && (w.ProjectionID != a.ID || w.Generation != record.Generation || w.Cause != fence.Cause ||
		w.Prepared != binding.Prepared || w.HelperLeaseID != plan.Lease.ID || w.Home != plan.Data.Home || !validTime(w.ObservedAt)) {
		return integrity("opened projection changed its withdrawal receipt")
	}
	return nil
}
