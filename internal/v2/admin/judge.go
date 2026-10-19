package admin

import (
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/job"
)

type judgeReg = job.Job

type judgeNative struct {
	Reg         judgeReg
	Lease       api.HelperLease
	State       string
	Created     api.Timestamp
	Revoked     bool
	Collected   bool
	Spec        *specRegistration       `json:",omitempty"`
	Endpoint    *api.InstalledBinding   `json:",omitempty"`
	Input       []byte                  `json:",omitempty"`
	Gate        *dataGate               `json:",omitempty"`
	Observation *api.ProcessObservation `json:",omitempty"`
}

type judgeSeal struct {
	Reg      judgeReg
	Spec     specRegistration
	Endpoint api.InstalledBinding
	Input    []byte
}

func validJudgeReg(r judgeReg, config string) error {
	if r.Execution.Intent.Config != config {
		return failure(api.CodeForbidden, "judge native job selects another installation")
	}
	return job.Validate(r, time.Now())
}

func judgeChild(parent leaseRecord, w judgeNative) leaseRecord {
	r := leaseRecord{Schema: parent.Schema, BootID: parent.BootID, Lease: w.Lease, Request: parent.Request, Phase: "active", IssuedAt: w.Created, Spec: w.Spec}
	r.Request.ReservationID = ""
	r.Request.Budget, r.Request.RuntimeManifestID = w.Reg.Plan.Budget, w.Reg.Lease.RuntimeManifest.ID
	if w.Spec != nil {
		h := w.Spec.Handoff
		r.SpecReceipt = &api.PreparedSpecReceipt{SpecID: h.Spec.ID, Config: h.Config, Target: h.Spec.Target, LeaseID: w.Lease.ID,
			SpecSHA256: h.SpecSHA256, RuntimeManifest: h.Spec.RuntimeManifest, OperationID: h.OperationID}
	}
	if w.Gate != nil {
		r.Gate = &gateJournal{Prepared: w.Gate.Prepared, PID: w.Gate.PID, State: w.Gate.State, Permit: w.Gate.Permit}
	}
	return r
}

func sameJudgeReg(a, b judgeReg) bool { return reflect.DeepEqual(a, b) }
