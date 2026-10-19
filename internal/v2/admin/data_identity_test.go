package admin

import (
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCaptureUIDOwnership(t *testing.T) {
	for _, phase := range []string{"active", "reserved", "released"} {
		for _, drain := range []string{"absent", "pending", "acknowledged", "discharged"} {
			t.Run(phase+"/"+drain, func(t *testing.T) {
				records := identityRecords()
				records[0].Phase = phase
				records[0].Lease.UID = 61001
				records[1].Phase = "reserved"
				records[1].Lease.UID = 61002
				capture := captureJournal{Binding: api.CaptureBinding{ID: "outside-a"},
					Native: &captureNativeJournal{Lease: api.HelperLease{ID: "outside-a", ContainmentID: "outside-cg-a", UID: 61002}}}
				if drain != "absent" {
					capture.Native.Drain = &captureDrainJournal{}
					if drain != "pending" {
						capture.Native.Drain.Receipt = &api.CaptureDrainReceipt{}
					}
					capture.Native.Drain.Discharged = drain == "discharged"
				}
				records[0].Captures = []captureJournal{capture}
				err := validateDataIdentities(records)
				if drain == "discharged" {
					if err != nil {
						t.Fatal("discharged capture still owns its reusable pool UID", err)
					}
					// Discharge releases only the numeric UID, never retained IDs.
					records[1].Lease.ContainmentID = capture.Native.Lease.ContainmentID
					if err := validateDataIdentities(records); err == nil {
						t.Fatal("discharged capture lost its retained containment identity")
					}
					return
				}
				for _, owner := range []api.ID{records[0].Lease.ID, records[1].Lease.ID} {
					err = validateIdentityScope(records, owner)
					var typed *api.Error
					if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "native pool UID has multiple live owners" {
						t.Fatal("live or uncertain capture stopped fencing both owners", err)
					}
				}
			})
		}
	}
	for _, phase := range []string{"active", "reserved", "releasing", "aborting"} {
		records := identityRecords()
		for i := range records {
			records[i].Phase, records[i].Lease.UID = phase, 61001
		}
		if err := validateDataIdentities(records); err == nil {
			t.Fatal("two live lane owners shared a pool UID", phase)
		}
	}
}

func identityRecords() []leaseRecord {
	var records []leaseRecord
	for _, suffix := range []string{"a", "b"} {
		id := func(prefix string) api.ID { return api.ID(prefix + "-" + suffix) }
		job := dataJob{State: "collected", Reg: dataReg{Request: api.StorageProjectionRequest{StageID: id("stage")}, LaunchID: id("launch"), Worker: api.WorkerLease{ID: id("worker"), EffectID: id("effect")}},
			Lease: api.HelperLease{ID: id("job"), ContainmentID: id("job-cg")}, Projection: api.StorageProjection{OpenToken: id("token")}, Gate: &dataGate{Record: &api.LaunchRecord{Actor: api.Actor{ID: id("principal")}}}}
		records = append(records, leaseRecord{Lease: api.HelperLease{ID: id("parent"), ContainmentID: id("parent-cg")}, Request: api.HelperLeaseRequest{Cause: api.InternalIntent{Actor: api.Actor{ID: id("service")}, RequestedBy: api.Actor{ID: id("human")}}}, DataJobs: []dataJob{job}})
	}
	return records
}

// This boundary tests identity reuse after collection, independent of the
// native UID collection protocol. These inputs are not native job receipts.
func TestWorkerIdentity(t *testing.T) {
	for _, field := range []string{"worker", "launch", "effect", "stage", "lease", "group", "token", "actor", "requester", "parent"} {
		t.Run(field, func(t *testing.T) {
			records := identityRecords()
			if err := validateDataIdentities(records); err != nil {
				t.Fatal(err)
			}
			a, b := &records[0].DataJobs[0], &records[1].DataJobs[0]
			switch field {
			case "worker":
				b.Reg.Worker.ID = a.Reg.Worker.ID
			case "launch":
				b.Reg.LaunchID = a.Reg.LaunchID
			case "effect":
				b.Reg.Worker.EffectID = a.Reg.Worker.EffectID
			case "stage":
				b.Reg.Request.StageID = a.Reg.Request.StageID
			case "lease":
				b.Lease.ID = a.Lease.ID
			case "group":
				b.Lease.ContainmentID = a.Lease.ContainmentID
			case "token":
				b.Projection.OpenToken = a.Projection.OpenToken
			case "actor":
				b.Gate.Record.Actor.ID = a.Gate.Record.Actor.ID
			case "requester":
				b.Gate.Record.Actor.ID = records[0].Request.Cause.RequestedBy.ID
			case "parent":
				b.Gate.Record.Actor.ID = records[0].Request.Cause.Actor.ID
			}
			if err := validateDataIdentities(records); err == nil {
				t.Fatal("acceptance: retained worker identity was reused")
			}
		})
	}
}

func TestNewWorkerIdentity(t *testing.T) {
	for _, field := range []string{"worker", "launch", "effect", "stage"} {
		t.Run(field, func(t *testing.T) {
			records := identityRecords()
			reg := dataReg{Request: api.StorageProjectionRequest{StageID: "new-stage"}, Worker: api.WorkerLease{ID: "new-worker", EffectID: "new-effect"}, LaunchID: "new-launch"}
			if err := newDataIdentity(records, reg); err != nil {
				t.Fatal(err)
			}
			prior := records[0].DataJobs[0].Reg
			switch field {
			case "worker":
				reg.Worker.ID = prior.Worker.ID
			case "launch":
				reg.LaunchID = prior.LaunchID
			case "effect":
				reg.Worker.EffectID = prior.Worker.EffectID
			case "stage":
				reg.Request.StageID = prior.Request.StageID
			}
			if err := newDataIdentity(records, reg); err == nil {
				t.Fatal("acceptance: new worker reused a retained identity")
			}
		})
	}
}

func TestNewWorkerPrincipal(t *testing.T) {
	records := identityRecords()
	reg := dataReg{LaunchID: "new-launch"}
	if err := newWorkerPrincipal(records, reg, api.Actor{Kind: "worker", ID: "new-principal"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []api.ID{records[0].DataJobs[0].Gate.Record.Actor.ID, records[0].Request.Cause.Actor.ID, records[0].Request.Cause.RequestedBy.ID} {
		if err := newWorkerPrincipal(records, reg, api.Actor{Kind: "worker", ID: id}); err == nil {
			t.Fatal("acceptance: new worker borrowed a retained principal")
		}
	}
}
