package admin

import (
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// A terminal decision advances cancellation without sending another native
// Stop to a naturally ended process. Keep its immutable launch/release epochs
// and separately retain the exact writer-verified archive decision.
func validateArchiveEpoch(record leaseRecord) error {
	fence := record.ArchiveEpoch
	if fence == nil {
		return nil
	}
	if err := archivejob.ValidateEpochFence(*fence); err != nil {
		return err
	}
	if record.Revoked && fence.Stop == nil || record.Phase != "released" || record.Storage == nil || !record.Storage.Ready ||
		!record.Storage.Withdrawn || record.Storage.Withdrawing ||
		record.Gate == nil || record.Gate.State != "ended" || record.Gate.Observation == nil ||
		record.Release == nil || record.Receipt == nil || len(record.LaunchAllocations) == 0 {
		return failure(api.CodeContainmentUnknown, "archive epoch handoff lacks its released natural storage owner")
	}
	releaseEpoch := fence.LaunchEpoch
	if fence.Stop != nil {
		if err := archiveStopPin(record, *fence.Stop); err != nil {
			return err
		}
		releaseEpoch = fence.Stop.Release.CancellationEpoch
		release := record.Release.Cause
		// A live retry may carry its claimant instead of the immutable author.
		release.Actor = fence.Stop.Release.Actor
		if release != fence.Stop.Release {
			return failure(api.CodeConflict, "archive stop handoff changed its original native release cause")
		}
		if record.Revoked && (record.Credentials == nil || record.Credentials.Stop == nil ||
			!api.RetainedCause(&record.Credentials.Stop.Cause, *record.Gate.Stop, record.Gate.Stop.Actor.ID)) {
			return failure(api.CodeConflict, "archive stop handoff changed its credential stop fence")
		}
	}
	allocation := record.LaunchAllocations[len(record.LaunchAllocations)-1].Reservation
	if allocation.Target != fence.Intent.Request.Target || allocation.LaunchID != fence.LaunchID ||
		fence.Decision.Config != record.Request.Config ||
		allocation.CancellationEpoch != fence.LaunchEpoch || record.Release.Cause.CancellationEpoch != releaseEpoch ||
		record.Release.Cause.Target != allocation.Target || fence.End.Observation.Handle != gateHandle(record) ||
		validateReceipt(record, *record.Release, *record.Receipt) != nil ||
		record.Credentials != nil && record.Credentials.State != "withdrawn" {
		return failure(api.CodeConflict, "archive epoch handoff changed its native launch or release pin")
	}
	ended, released, native := fence.End.Observation, record.Receipt.Quiescence, *record.Gate.Observation
	ended.ObservedAt, released.ObservedAt, native.ObservedAt = "", "", ""
	if !reflect.DeepEqual(ended, released) || !reflect.DeepEqual(native, released) {
		return failure(api.CodeContainmentUnknown, "archive epoch handoff changed its measured native end")
	}
	if record.Archive != nil && record.Archive.Intent != fence.Intent {
		return failure(api.CodeConflict, "archive epoch handoff changed its original frozen intent")
	}
	return nil
}

// The writer's extra stop transition must match the gate's independently
// retained stop, even when there never was a credential projection.
func archiveStopPin(record leaseRecord, stop archivejob.StopEpoch) error {
	if record.Gate == nil || record.Gate.Stop == nil {
		return failure(api.CodeConflict, "archive stop handoff lacks its independent native stop fence")
	}
	cause, release := *record.Gate.Stop, stop.Release
	if validateCause(cause, record.Request.Config, api.InternalHelperStop) != nil || cause.Target != release.Target ||
		cause.CancellationEpoch != release.CancellationEpoch || cause.CauseOperationID != stop.Event.OperationID ||
		cause.CauseRequestID != stop.Event.RequestID || cause.RequestedBy != stop.Event.RequestedBy || cause.LogicalTurnID != release.LogicalTurnID {
		return failure(api.CodeConflict, "archive stop handoff changed its independent native stop fence")
	}
	return nil
}

func archiveEpochState(fence archivejob.EpochFence) (api.StateEvent, error) {
	var state api.StateEvent
	if err := api.DecodeObject(fence.Decision.Payload, &state); err != nil {
		return state, err
	}
	return state, nil
}
