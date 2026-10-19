package admin

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) usageOwner(ctx context.Context, r usageReg) (leaseRecord, int, error) {
	if err := contextError(ctx); err != nil {
		return leaseRecord{}, 0, err
	}
	if err := validUsageReg(r, m.binding.Config); err != nil {
		return leaseRecord{}, 0, err
	}
	p, err := m.find(r.ParentLeaseID)
	if err != nil {
		return p, 0, err
	}
	if p.BootID != m.bootID || p.Revoked || p.Phase != "active" && p.Phase != "released" || p.Request.LifeID != r.Job.Lease.Target.LifeID ||
		p.Request.Cause.Target.Run != r.Job.Lease.Target.Run || !withinBudget(r.Plan.Budget, p.Request.Budget) {
		return p, 0, failure(api.CodeConflict, "usage worker has no current native parent or resource envelope")
	}
	for i := range p.Usages {
		w := &p.Usages[i]
		if w.Reg.Job.Lease.ID != r.Job.Lease.ID {
			continue
		}
		if w.Collected || w.Revoked || !reflect.DeepEqual(w.Reg.Job, r.Job) || !reflect.DeepEqual(w.Reg.Plan, r.Plan) ||
			w.Reg.LaunchID != r.LaunchID || r.Claim.Record.Generation < w.Reg.Claim.Record.Generation {
			return p, i, failure(api.CodeConflict, "usage retry changed its original native worker")
		}
		w.Reg.Claim = r.Claim
		if w.Spec != nil {
			w.Spec.Handoff.Cause.Actor = api.Actor{Kind: "service", ID: r.Claim.Record.ClaimantID}
		}
		return p, i, nil
	}
	return p, -1, nil
}

func (m *leaseManager) allocateUsage(ctx context.Context, r usageReg) (api.HelperLease, error) {
	p, index, err := m.usageOwner(ctx, r)
	if err != nil {
		return api.HelperLease{}, err
	}
	if index >= 0 {
		w := p.Usages[index]
		if w.State == "reserved" {
			return api.HelperLease{}, failure(api.CodeContainmentUnknown, "usage native allocation is uncertain; retain the original job")
		}
		return w.Lease, m.save(p)
	}
	records, err := m.records()
	if err != nil {
		return api.HelperLease{}, err
	}
	used := map[uint32]bool{m.binding.Service.UID: true, p.Lease.UID: true}
	reserveArchiveUIDs(records, used)
	for _, owner := range records {
		if owner.Phase != "released" && owner.Phase != "aborted" {
			used[owner.Lease.UID] = true
		}
		for _, job := range owner.DataJobs {
			if job.State != "collected" {
				used[job.Lease.UID] = true
			}
		}
		for _, capture := range owner.Captures {
			if capture.Native != nil && captureReservesUID(capture) {
				used[capture.Native.Lease.UID] = true
			}
		}
	}
	var selected account
	for _, candidate := range m.binding.Lanes {
		if !used[candidate.UID] {
			selected = candidate
			break
		}
	}
	if selected.UID == 0 {
		return api.HelperLease{}, failure(api.CodeUnavailable, "usage needs a distinct free installed worker UID")
	}
	id, err := randomID("usage-job-")
	if err != nil {
		return api.HelperLease{}, err
	}
	group, err := randomID("usage-cg-")
	if err != nil {
		return api.HelperLease{}, err
	}
	w := usageNative{Reg: r, Lease: api.HelperLease{ID: id, UID: selected.UID, GID: selected.GID, ContainmentID: group, EndpointGeneration: m.binding.Generation}, State: "reserved", Created: gateTimestamp()}
	p.Usages = append(p.Usages, w)
	if err := m.save(p); err != nil {
		return api.HelperLease{}, err
	}
	child := usageChild(p, w)
	child.Phase = "reserved"
	if err := m.resources.Ensure(ctx, child); err != nil {
		return api.HelperLease{}, err
	}
	p.Usages[len(p.Usages)-1].State = "allocated"
	return w.Lease, m.save(p)
}

func validateUsageSeal(seal usageSeal, b installation, live bool) error {
	if live {
		if err := validUsageReg(seal.Reg, b.Config); err != nil {
			return err
		}
	}
	if err := validateSpecEnvelope(seal.Spec, b.Config); err != nil {
		return err
	}
	r, s, e := seal.Reg, seal.Spec.Handoff.Spec, seal.Endpoint
	j := r.Job
	if s.Kind != "worker" || s.Runner != nil || s.Worker == nil || !reflect.DeepEqual(*s.Worker, r.Plan) || s.PlanID != "" || s.Capture != nil ||
		s.LaunchID != r.LaunchID || s.Target != j.Lease.Target || s.RuntimeManifest != j.Lease.RuntimeManifest || s.Grants.ID != j.Lease.GrantSetID ||
		s.Budget != r.Plan.Budget || api.ValidateBinding(e, b.Config, b.Release.Version) != nil || e.Class != api.EndpointWorker ||
		e.LaunchID != r.LaunchID || e.WorkerLeaseID != j.Lease.ID || e.Target == nil || *e.Target != j.Lease.Target || e.Socket != "/runtime/laneboss-worker.sock" ||
		e.EndpointGeneration != b.Generation || e.InstallationGeneration != b.Generation || e.ServiceUID != b.Service.UID || e.ServiceGID != b.Service.GID ||
		e.ArtifactSHA256 != b.Artifact.SHA256 || digestBytes(seal.Input) != j.Lease.Input.SHA256 || int64(len(seal.Input)) != j.Lease.Input.Bytes {
		return failure(api.CodeForbidden, "usage native seal changed its fixed worker or endpoint")
	}
	var input api.UsageCredentialInput
	if err := api.DecodeObject(seal.Input, &input); err != nil {
		return err
	}
	if input != j.Input {
		return failure(api.CodeIntegrity, "usage input changed its protected from-profile selection")
	}
	cause := *r.Claim.Record.Effect.Context
	cause.Kind, cause.Actor = api.InternalHelperRegister, api.Actor{Kind: "service", ID: r.Claim.Record.ClaimantID}
	if seal.Spec.Handoff.Cause != cause {
		return failure(api.CodeConflict, "usage native seal changed its original claim cause")
	}
	return nil
}

func (m *leaseManager) registerUsage(ctx context.Context, seal usageSeal) (api.PreparedSpecReceipt, error) {
	if err := validateUsageSeal(seal, m.binding, true); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	p, i, err := m.usageOwner(ctx, seal.Reg)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	if i < 0 || seal.Spec.Handoff.Spec.UIDLeaseID != p.Usages[i].Lease.ID {
		return api.PreparedSpecReceipt{}, failure(api.CodeConflict, "usage has no original native allocation")
	}
	w := &p.Usages[i]
	if w.Spec != nil {
		prior := *w.Spec
		prior.Handoff.Cause.Actor = seal.Spec.Handoff.Cause.Actor
		if !reflect.DeepEqual(prior, seal.Spec) || !reflect.DeepEqual(*w.Endpoint, seal.Endpoint) || !reflect.DeepEqual(w.Input, seal.Input) {
			return api.PreparedSpecReceipt{}, failure(api.CodeIdempotencyConflict, "usage registration changed its original sealed bytes")
		}
	} else {
		if w.State != "allocated" {
			return api.PreparedSpecReceipt{}, failure(api.CodeConflict, "usage registration was already attempted")
		}
		if err := validateRuntimePins(ctx, m.binding, seal.Spec.Handoff.Spec); err != nil {
			return api.PreparedSpecReceipt{}, err
		}
		w.Endpoint, w.Input, w.State = &seal.Endpoint, append([]byte{}, seal.Input...), "registered"
	}
	w.Spec = &seal.Spec
	if err := m.save(p); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	return *usageChild(p, *w).SpecReceipt, nil
}

func (m *leaseManager) prepareUsage(ctx context.Context, r usageReg) (api.PreparedLaunch, error) {
	p, i, err := m.usageOwner(ctx, r)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	if i < 0 || p.Usages[i].Spec == nil {
		return api.PreparedLaunch{}, failure(api.CodePrerequisite, "usage has no retained native spec")
	}
	w := &p.Usages[i]
	if w.Gate != nil {
		live := m.gates[w.Lease.ID]
		if w.Gate.State != "prepared" && w.Gate.State != "opened" || live == nil || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
			return api.PreparedLaunch{}, failure(api.CodeContainmentUnknown, "usage lost its original native gate; no replacement")
		}
		return w.Gate.Prepared, m.save(p)
	}
	if w.State != "registered" {
		return api.PreparedLaunch{}, failure(api.CodeConflict, "usage gate was already attempted")
	}
	id, err := randomID("prepared-")
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	gate, err := randomID("gate-")
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	w.Gate = &dataGate{State: "preparing", Prepared: api.PreparedLaunch{ID: id, GateID: gate, Target: r.Job.Lease.Target, SpecSHA256: w.Spec.Handoff.SpecSHA256,
		ContainmentID: w.Lease.ContainmentID, EndpointGeneration: w.Lease.EndpointGeneration}}
	w.State = "preparing"
	if err := m.save(p); err != nil {
		return api.PreparedLaunch{}, err
	}
	live, err := m.startUsageGate(ctx, p, *w)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	if m.gates == nil {
		m.gates = map[api.ID]ownedGate{}
	}
	m.gates[w.Lease.ID] = live
	if err := m.usageProvider(ctx, w.Reg.Job, w.Lease, true); err != nil {
		live.Close()
		return api.PreparedLaunch{}, err
	}
	w.ProviderEnrolled = true
	w.Gate.PID, w.Gate.Prepared.ProcessGeneration, w.Gate.State, w.State = live.PID(), live.Generation(), "prepared", "prepared"
	if err := m.save(p); err != nil {
		live.Close()
		return api.PreparedLaunch{}, err
	}
	return w.Gate.Prepared, nil
}
