package admin

import (
	"reflect"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type usageReg struct {
	Job           api.UsageJob
	Claim         api.EffectLease
	Plan          api.WorkerPlan
	LaunchID      api.ID
	ParentLeaseID api.ID
}

type usageNative struct {
	Reg              usageReg
	Lease            api.HelperLease
	State            string
	Created          api.Timestamp
	Revoked          bool
	Collected        bool
	ProviderEnrolled bool
	Spec             *specRegistration       `json:",omitempty"`
	Endpoint         *api.InstalledBinding   `json:",omitempty"`
	Input            []byte                  `json:",omitempty"`
	Gate             *dataGate               `json:",omitempty"`
	Observation      *api.ProcessObservation `json:",omitempty"`
}

type usageSeal struct {
	Reg      usageReg
	Spec     specRegistration
	Endpoint api.InstalledBinding
	Input    []byte
}

func validUsageReg(r usageReg, config string) error {
	if err := api.ValidateUsageJob(r.Job, time.Now()); err != nil {
		return err
	}
	j, e, c := r.Job, r.Claim.Record.Effect, r.Claim
	if !validID(r.LaunchID) || r.LaunchID != j.LaunchID || r.ParentLeaseID != j.ParentLeaseID || !api.EffectLeaseClaimed(c) || c.Record.Outcome != nil ||
		e.Worker == nil || !reflect.DeepEqual(*e.Worker, j.Plan) || !reflect.DeepEqual(r.Plan, j.Plan) || e.Context == nil ||
		e.Context.Config != config || e.Context.Target != j.Lease.Target || e.Context.Kind != api.InternalObjectRetain ||
		e.ID != j.Lease.EffectID || e.OperationID != j.Lease.OperationID || c.ClaimID != c.Record.ClaimID || c.ExpiresAt != c.Record.ClaimExpiresAt ||
		!slices.Equal(r.Plan.Argv, []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(j.Lease.ID)}) {
		return failure(api.CodeForbidden, "usage native job differs from its original fixed claim")
	}
	deadline, err := time.Parse(time.RFC3339Nano, string(c.ExpiresAt))
	end, endErr := time.Parse(time.RFC3339Nano, string(j.Lease.ExpiresAt))
	if err != nil || endErr != nil || !deadline.After(time.Now()) || !end.After(time.Now()) || deadline.After(end) {
		return failure(api.CodeConflict, "usage native claim or worker lease expired")
	}
	return nil
}

func usageChild(parent leaseRecord, w usageNative) leaseRecord {
	r := leaseRecord{Schema: parent.Schema, BootID: parent.BootID, Lease: w.Lease, Request: parent.Request, Phase: "active", IssuedAt: w.Created, Spec: w.Spec}
	r.Request.ReservationID = ""
	r.Request.Budget, r.Request.RuntimeManifestID = w.Reg.Plan.Budget, w.Reg.Job.Lease.RuntimeManifest.ID
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
