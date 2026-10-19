//go:build linux && laneboss_root_canary

package admin

import (
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// ExerciseTerminalArchiveEpoch connects the real vendor/lifecycle component to
// the production native epoch comparison. Native process/storage ownership are
// declared inputs here; the separate root canary measures those resources.
func ExerciseTerminalArchiveEpoch(base api.Generation, lane api.Lane, end api.Event, decisions []api.Event) error {
	intent := archivejob.Intent{OperationID: "component-archive-operation", Request: api.ArchiveRequest{Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, ExpectedGeneration: lane.Generation},
		CancellationEpoch: lane.CancellationEpoch, EndEventID: end.ID, EndSeq: end.Seq}
	record := leaseRecord{LaunchAllocations: []launchAllocation{{Reservation: api.LaunchReservation{CancellationEpoch: base}}}}
	var observed api.RunEndEvent
	if err := api.DecodeObject(end.Payload, &observed); err != nil {
		return err
	}
	if len(decisions) == 0 {
		return failure(api.CodeConflict, "component archive has no committed terminal decision")
	}
	fence := &archivejob.EpochFence{Intent: intent, LaunchID: lane.LaunchID, LaunchEpoch: base, End: observed, Decision: decisions[len(decisions)-1]}
	if err := archivejob.ValidateEpochFence(*fence); err != nil {
		return err
	}
	// The real writer independently supplies this private fence in installed
	// operation. This component supplies its own retained lifecycle records.
	record.ArchiveEpoch = fence
	return archiveNativeEpoch(record, intent)
}
