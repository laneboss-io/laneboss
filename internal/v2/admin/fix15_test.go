package admin

import (
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestDeniedData(t *testing.T) {
	calls := 0
	missing := failure(api.CodeNotFound, "unopened helper job")
	err := deniedDataLaunch(false, func() error { calls++; return missing })
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || calls != 0 {
		t.Fatal("acceptance: unopened revoked launch lost its forbidden refusal")
	}
	want := failure(api.CodeContainmentUnknown, "retained job still owns processes")
	err = deniedDataLaunch(true, func() error { calls++; return want })
	if !errors.Is(err, want) || calls != 1 {
		t.Fatal("retained job revocation failure was swallowed")
	}
}

func laneIdentityFixture() []leaseRecord {
	records := identityRecords()
	for i := range records {
		suffix := "a"
		if i == 1 {
			suffix = "b"
		}
		launch := api.ID("lane-" + suffix)
		records[i].Spec = &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{LaunchID: launch}}}
		records[i].LaunchAllocations = []launchAllocation{{Reservation: api.LaunchReservation{ID: api.ID("reservation-" + suffix), LaunchID: launch}}}
		captureID := api.ID("capture-" + suffix)
		records[i].Captures = []captureJournal{{Binding: api.CaptureBinding{ID: captureID}, Native: &captureNativeJournal{Lease: api.HelperLease{ID: captureID, ContainmentID: api.ID("capture-cg-" + suffix)}}}}
		records[i].Network = &networkJournal{Lease: api.NetworkLease{ID: api.ID("network-" + suffix), NamespaceID: api.ID("namespace-" + suffix)}}
	}
	return records
}

func TestLaneIdentity(t *testing.T) {
	for _, field := range []string{"spec", "allocation", "worker", "capture", "network", "namespace"} {
		t.Run(field, func(t *testing.T) {
			records := laneIdentityFixture()
			if err := validateDataIdentities(records); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "spec":
				records[1].Spec.Handoff.Spec.LaunchID = records[0].Spec.Handoff.Spec.LaunchID
			case "allocation":
				records[1].LaunchAllocations[0].Reservation.LaunchID = records[0].LaunchAllocations[0].Reservation.LaunchID
			case "worker":
				records[1].DataJobs[0].Reg.LaunchID = records[0].Spec.Handoff.Spec.LaunchID
			case "capture":
				records[1].Captures[0].Binding.ID = records[0].Captures[0].Binding.ID
			case "network":
				records[1].Network.Lease.ID = records[0].Network.Lease.ID
			case "namespace":
				records[1].Network.Lease.NamespaceID = records[0].Network.Lease.NamespaceID
			}
			// Even damage in the second owner cannot leave the first alias usable.
			records[1].Schema = "damaged"
			for _, record := range records {
				if err := validateIdentityScope(records, record.Lease.ID); err == nil {
					t.Fatal("acceptance: retained lane capture or network alias left an owner usable")
				}
			}
		})
	}
}

func TestWorkerLaneAlias(t *testing.T) {
	records := laneIdentityFixture()
	records[0].LaunchAllocations = nil
	reg := dataReg{LaunchID: "new-launch", Worker: api.WorkerLease{ID: "new-worker", EffectID: "new-effect"}, Request: api.StorageProjectionRequest{StageID: "new-stage"}}
	if err := newDataIdentity(records, reg); err != nil {
		t.Fatal(err)
	}
	reg.LaunchID = records[0].Spec.Handoff.Spec.LaunchID
	if err := newDataIdentity(records, reg); err == nil {
		t.Fatal("new worker launch reused a retained lane identity")
	}
}
