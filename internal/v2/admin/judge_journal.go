package admin

import "laneboss.io/laneboss/internal/v2/api"

func validateJudgeOwners(records []leaseRecord, binding installation) error {
	uids := map[uint32]bool{binding.Service.UID: true}
	ids := map[api.ID]bool{}
	for _, p := range records {
		ids[p.Lease.ID], ids[p.Lease.ContainmentID] = true, true
		if p.Phase != "released" && p.Phase != "aborted" {
			uids[p.Lease.UID] = true
		}
		for _, w := range p.DataJobs {
			ids[w.Lease.ID], ids[w.Lease.ContainmentID] = true, true
			if w.State != "collected" {
				uids[w.Lease.UID] = true
			}
		}
		if p.Archive != nil && p.Archive.Worker != nil {
			w := p.Archive.Worker
			ids[w.Lease.ID], ids[w.Lease.ContainmentID] = true, true
			if !w.Collected {
				uids[w.Lease.UID] = true
			}
		}
		for _, other := range p.Channels {
			ids[other.Lease.ID], ids[other.Lease.ContainmentID] = true, true
			if !other.Collected {
				uids[other.Lease.UID] = true
			}
		}
		for _, c := range p.Captures {
			if c.Native != nil {
				ids[c.Native.Lease.ID], ids[c.Native.Lease.ContainmentID] = true, true
				if captureReservesUID(c) {
					uids[c.Native.Lease.UID] = true
				}
			}
		}
	}
	for _, p := range records {
		for _, w := range p.Judges {
			if validateLease(w.Lease, binding) != nil || w.Reg.ParentLeaseID != p.Lease.ID || w.Reg.Lease.Target.LifeID != p.Request.LifeID ||
				w.Created == "" || !w.Collected && uids[w.Lease.UID] {
				return failure(api.CodeIntegrity, "judge native owner overlaps another retained allocation")
			}
			if !w.Collected {
				uids[w.Lease.UID] = true
			}
			for _, id := range []api.ID{w.Lease.ID, w.Lease.ContainmentID, w.Reg.Lease.ID, w.Reg.LaunchID} {
				if !validID(id) || ids[id] {
					return failure(api.CodeIntegrity, "judge native identity is absent or already retained")
				}
				ids[id] = true
			}
			switch w.State {
			case "reserved", "allocated", "registered", "preparing", "prepared", "opening", "opened", "exited":
			default:
				return failure(api.CodeIntegrity, "judge native journal has an unknown phase")
			}
			if (w.Spec == nil) != (w.Endpoint == nil) || (w.Spec == nil) != (len(w.Input) == 0) {
				return failure(api.CodeIntegrity, "judge native journal lost its sealed input or endpoint")
			}
			if w.Spec != nil {
				if w.Spec.Handoff.Spec.UIDLeaseID != w.Lease.ID {
					return failure(api.CodeIntegrity, "judge native spec replaced its assigned lease")
				}
				if err := validateJudgeSeal(judgeSeal{Reg: w.Reg, Spec: *w.Spec, Endpoint: *w.Endpoint, Input: w.Input}, binding, false); err != nil {
					return err
				}
			}
			if w.Gate != nil && (w.Spec == nil || w.Gate.Prepared.Target != w.Reg.Lease.Target || w.Gate.Prepared.ContainmentID != w.Lease.ContainmentID ||
				w.Gate.Prepared.SpecSHA256 != w.Spec.Handoff.SpecSHA256 || !validID(w.Gate.Prepared.ID) || !validID(w.Gate.Prepared.GateID) ||
				w.Gate.State != "preparing" && (w.Gate.PID <= 1 || w.Gate.Prepared.ProcessGeneration == "")) {
				return failure(api.CodeIntegrity, "judge native gate lost its measured lifetime")
			}
		}
	}
	return nil
}
