package admin

import (
	"reflect"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type channelReg struct {
	Job           api.ChannelJob
	Claim         api.EffectLease
	Plan          api.WorkerPlan
	LaunchID      api.ID
	ParentLeaseID api.ID
}

type channelNative struct {
	Reg         channelReg
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

type channelSeal struct {
	Reg      channelReg
	Spec     specRegistration
	Endpoint api.InstalledBinding
	Input    []byte
}

func validChannelReg(r channelReg, config string) error {
	if err := api.ValidateChannelJob(r.Job); err != nil {
		return err
	}
	j, e, c := r.Job, r.Claim.Record.Effect, r.Claim
	if !validID(r.LaunchID) || !validID(r.ParentLeaseID) || !api.EffectLeaseClaimed(c) || c.Record.Outcome != nil || e.Channel == nil ||
		!reflect.DeepEqual(*e.Channel, j) || e.Context == nil || e.Context.Config != config || e.Context.Target != j.Lease.Target ||
		e.ID != j.Lease.EffectID || e.OperationID != j.Lease.OperationID || c.ClaimID != c.Record.ClaimID || c.ExpiresAt != c.Record.ClaimExpiresAt ||
		r.Plan.Schema != "laneboss.worker-plan.v2" || r.Plan.Kind != "channel" || r.Plan.Input != j.Lease.Input ||
		r.Plan.Executable != j.Runtime.Executable || r.Plan.GrantSetID != j.Lease.GrantSetID ||
		!slices.Equal(r.Plan.Argv, []string{"laneboss", "internal", "channel", "--binding", "/runtime/laneboss-worker.json", "--lease", string(j.Lease.ID)}) {
		return failure(api.CodeForbidden, "channel native job differs from its original fixed claim")
	}
	deadline, err := time.Parse(time.RFC3339Nano, string(c.ExpiresAt))
	end, endErr := time.Parse(time.RFC3339Nano, string(j.Lease.ExpiresAt))
	if err != nil || endErr != nil || !deadline.After(time.Now()) || !end.After(time.Now()) || deadline.After(end) {
		return failure(api.CodeConflict, "channel native claim or worker lease expired")
	}
	return nil
}

func channelChild(parent leaseRecord, w channelNative) leaseRecord {
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
