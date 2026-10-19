package admin

import (
	"context"
	"encoding/json"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) usageByLease(id api.ID) (leaseRecord, int, bool, error) {
	records, err := m.records()
	if err != nil {
		return leaseRecord{}, 0, false, err
	}
	for _, parent := range records {
		for i, worker := range parent.Usages {
			if worker.Lease.ID == id {
				return parent, i, true, nil
			}
		}
	}
	return leaseRecord{}, 0, false, nil
}

func usageHandle(w usageNative) api.ProcessHandle {
	return api.ProcessHandle{ID: w.Reg.LaunchID, Target: w.Reg.Job.Lease.Target, ContainmentID: w.Lease.ContainmentID, Generation: w.Gate.Prepared.ProcessGeneration}
}

// Prepared recovery reads the original kernel owner and never creates or
// releases a process. Opening with projected usage credentials is separate.
func (m *leaseManager) reconcileUsage(ctx context.Context, r usageReg) (api.LaunchReconciliation, error) {
	p, i, err := m.usageOwner(ctx, r)
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	if i < 0 || p.Usages[i].Gate == nil {
		return api.LaunchReconciliation{}, failure(api.CodePrerequisite, "usage has no retained native gate")
	}
	w := p.Usages[i]
	live := m.gates[w.Lease.ID]
	if live == nil || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
		return api.LaunchReconciliation{}, failure(api.CodeContainmentUnknown, "usage reconciliation lost the original native lifetime")
	}
	if w.Gate.State != "prepared" || w.Gate.Permit != nil {
		return api.LaunchReconciliation{}, failure(api.CodeContainmentUnknown, "usage preparation is not known unopened")
	}
	observation, err := live.Observe(ctx, usageHandle(w))
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	if observation.State != "running" {
		return api.LaunchReconciliation{}, failure(api.CodeContainmentUnknown, "usage prepared gate is no longer live")
	}
	observation.State = "prepared"
	return api.LaunchReconciliation{Prepared: &w.Gate.Prepared, GateState: "prepared", Observation: observation}, nil
}

// Collection cancels only an unopened preparation. Native stop, UID/cgroup
// quiescence and resource removal precede the durable release of its pool UID.
func (m *leaseManager) collectUsage(ctx context.Context, r usageReg) error {
	if err := validUsageReg(r, m.binding.Config); err != nil {
		return err
	}
	p, err := m.find(r.ParentLeaseID)
	if err != nil {
		return err
	}
	for i := range p.Usages {
		w := &p.Usages[i]
		if w.Reg.Job.Lease.ID != r.Job.Lease.ID {
			continue
		}
		if w.Reg.LaunchID != r.LaunchID || !reflect.DeepEqual(w.Reg.Job, r.Job) {
			return failure(api.CodeConflict, "usage collection changed its original job")
		}
		if w.Collected {
			return nil
		}
		child := usageChild(p, *w)
		if live := m.gates[w.Lease.ID]; live != nil {
			if err := m.killContainment(ctx, child); err != nil {
				return err
			}
			if err := live.Close(); err != nil {
				return err
			}
			observation, err := live.Stop(ctx, usageHandle(*w))
			if err != nil {
				return err
			}
			w.Observation = &observation
		}
		if err := m.waitContainmentEmpty(ctx, child); err != nil {
			return err
		}
		if err := m.resources.Quiescent(ctx, child); err != nil {
			return err
		}
		if w.Observation != nil {
			zero := uint64(0)
			w.Observation.Survivors = &zero
		}
		if err := m.resources.Remove(ctx, child); err != nil {
			return err
		}
		if w.ProviderEnrolled {
			if err := m.usageProvider(ctx, w.Reg.Job, w.Lease, false); err != nil {
				return err
			}
			w.ProviderEnrolled = false
		}
		if err := m.collectUsageHome(w.Lease); err != nil {
			return err
		}
		w.Collected = true
		if err := m.save(p); err != nil {
			return err
		}
		delete(m.gates, w.Lease.ID)
		return nil
	}
	return failure(api.CodeNotFound, "usage collection has no original native worker")
}

func (m *leaseManager) dispatchUsage(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	if method == "usage_register" {
		var seal usageSeal
		if err := decodeStrict(raw, &seal); err != nil {
			return nil, err
		}
		return m.registerUsage(ctx, seal)
	}
	var r usageReg
	if err := decodeStrict(raw, &r); err != nil {
		return nil, err
	}
	switch method {
	case "usage_lease":
		return m.allocateUsage(ctx, r)
	case "usage_prepare":
		return m.prepareUsage(ctx, r)
	case "usage_reconcile":
		return m.reconcileUsage(ctx, r)
	case "usage_collect":
		return api.Empty{}, m.collectUsage(ctx, r)
	case "usage_observe":
		return m.observeUsage(ctx, r)
	}
	return nil, failure(api.CodeInvalid, "unknown usage native operation")
}
