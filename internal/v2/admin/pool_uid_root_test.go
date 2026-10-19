//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// The capture wait, EOF and acknowledgement are explicit protocol inputs.
// Cleanup executes the real Git/native collectors and reopens the real helper
// file store. The second launch uses the production planning allocator with
// only resource creation doubled; no runner or AI service is executed here.
func TestCollectedPoolUID(t *testing.T) {
	m, enrollment, query, _ := cleanupPathFixture(t, false, false)
	ctx := context.Background()
	parent, err := m.find(enrollment.LeaseID)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the original lane and archive worker identities distinct, then put
	// the old capture UID first so the next launch must actually reuse it.
	captureAccount := account{Name: "lb-capture", UID: m.binding.Lanes[1].UID + 1, GID: m.binding.Lanes[1].GID + 1}
	m.binding.Lanes = append([]account{captureAccount}, m.binding.Lanes...)
	capture := collectedCapture(t, parent, captureAccount)
	parent.Captures = []captureJournal{capture}
	if err := m.save(parent); err != nil {
		t.Fatal("capture protocol fixture failed real journal validation", err)
	}
	removal, err := m.removeCleanup(ctx, query)
	if err != nil || removal.Action != "remove_clean" || removal.After.WorktreeState != "absent" || removal.After.BranchState != "absent" {
		t.Fatal("lane A did not finish actual native cleanup", err)
	}
	if _, err := os.Lstat(filepath.Join(enrollment.Parent, string(enrollment.Workspace.ID))); !os.IsNotExist(err) {
		t.Fatal("lane A kept its collected workspace", err)
	}
	parent, err = m.find(parent.Lease.ID)
	if err != nil || parent.Cleanup == nil || parent.Cleanup.Phase != "complete" || !parent.Archive.Worker.Collected || !cleanupReleasesUIDs(parent) {
		t.Fatal("lane A did not retain completed collection", err)
	}
	before := encodeLaunchFixture(t, parent)
	// Reconstruct over the file store so the regression cannot pass by using
	// only the collector's process-local copy or by forgetting old records.
	resources := &observedResources{}
	restarted := newLeaseManager(m.binding, m.bootID, m.store, resources)
	request := testAllocation()
	request.LifeID, request.Cause.Target.LifeID = "life-b", "life-b"
	request.Cause.ID, request.Cause.EffectID = "intent-b", "effect-b"
	lease, err := restarted.allocate(ctx, request)
	if err != nil {
		t.Fatal("lane B planning allocation rejected the collected capture UID", err)
	}
	if lease.UID != capture.Native.Lease.UID || lease.ID == parent.Lease.ID || !reflect.DeepEqual(resources.ensured, []api.ID{lease.ID}) {
		t.Fatal("lane B did not reuse the same pool UID through its real allocation")
	}
	retained, err := restarted.find(parent.Lease.ID)
	if err != nil || !reflect.DeepEqual(before, encodeLaunchFixture(t, retained)) {
		t.Fatal("UID reuse edited or discarded lane A's retained record", err)
	}
	if _, err := restarted.find(lease.ID); err != nil {
		t.Fatal("lane B allocation did not survive real journal readback", err)
	}
}

func collectedCapture(t *testing.T, parent leaseRecord, a account) captureJournal {
	t.Helper()
	allocation := parent.LaunchAllocations[0]
	r := allocation.Reservation
	binding := api.CaptureBinding{ID: "collected-capture", Config: r.Config, ReservationID: r.ID, Target: r.Target,
		LaunchID: r.LaunchID, HelperLeaseID: parent.Lease.ID, OperationID: r.OperationID, RequestID: r.RequestID,
		RequestedBy: r.RequestedBy, Generation: 1, Status: "registered", WorkerLeaseID: "capture-worker", EffectID: "capture-effect",
		ProducerID: "capture-producer", ProducerGeneration: parent.BootID + ":capture", BootID: parent.BootID,
		Supervisor: &api.Executable{ID: "capture-spool", SHA256: testDigest("capture"), Version: "component-v1"},
		Streams:    []api.CaptureStreamBinding{{ID: "capture-out", PipeID: "capture-out-pipe", Stream: "stdout"}, {ID: "capture-err", PipeID: "capture-err-pipe", Stream: "stderr"}}}
	lease := api.HelperLease{ID: binding.ID, UID: a.UID, GID: a.GID, ContainmentID: "capture-group", EndpointGeneration: parent.Lease.EndpointGeneration}
	zero, exit := uint64(0), 0
	observation := api.ProcessObservation{Handle: api.ProcessHandle{ID: binding.ProducerID, Target: r.Target,
		ContainmentID: lease.ContainmentID, Generation: binding.ProducerGeneration}, State: "exited", ExitCode: &exit,
		Survivors: &zero, PromptStatus: "not_written", ObservedAt: gateTimestamp()}
	snapshot := api.CaptureDrainSnapshot{Binding: binding, Release: *parent.Release, Producer: observation, SpoolIdentity: "component-spool"}
	for _, stream := range binding.Streams {
		snapshot.Streams = append(snapshot.Streams, api.CaptureDrainStream{StreamID: stream.ID, PipeID: stream.PipeID, SHA256: digestBytes(nil), EOF: true})
	}
	pin, err := api.CaptureDrainDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	receipt := api.CaptureDrainReceipt{EffectID: parent.Release.Cause.EffectID, LeaseID: parent.Lease.ID, SnapshotSHA256: pin,
		State: api.CaptureState{Binding: binding, Generation: 2, LastSeq: 1}}
	for _, stream := range binding.Streams {
		receipt.State.Positions = append(receipt.State.Positions, api.CapturePosition{StreamID: stream.ID, EOF: true})
	}
	if err := api.ValidateCaptureDrainReceipt(snapshot, receipt); err != nil {
		t.Fatal(err)
	}
	registration, _ := capturePlanFixture()
	registration.Reservation, registration.Policy = r, allocation.Policy
	registration.Request.ReservationID, registration.Request.HelperLeaseID = r.ID, parent.Lease.ID
	registration.Request.WorkerLeaseID = binding.WorkerLeaseID
	registration.Request.Cause = allocation.Request.Cause
	registration.Request.Cause.Kind = api.InternalLaunchPlan
	registration.Request.Cause.EffectID = binding.EffectID
	registration.Worker.ID, registration.Worker.Target = binding.WorkerLeaseID, r.Target
	registration.Worker.OperationID, registration.Worker.EffectID = r.OperationID, binding.EffectID
	registration.Worker.GrantSetID = r.GrantSetID
	registration.Worker.RuntimeManifest = allocation.Inputs.Sources.Runtime.Manifest
	if err := validateCaptureRegistration(registration); err != nil {
		t.Fatal(err)
	}
	return captureJournal{Registration: registration, Binding: binding,
		Native: &captureNativeJournal{Phase: "registered", Lease: lease, PID: 2, BindingID: binding.ID,
			ArchiveObservation: &observation, SpoolIdentity: snapshot.SpoolIdentity,
			Drain: &captureDrainJournal{Snapshot: snapshot, Receipt: &receipt, Discharged: true}}}
}
