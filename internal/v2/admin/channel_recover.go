package admin

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) channelByLease(id api.ID) (leaseRecord, int, bool, error) {
	records, err := m.records()
	if err != nil {
		return leaseRecord{}, 0, false, err
	}
	for _, parent := range records {
		for i, worker := range parent.Channels {
			if worker.Lease.ID == id {
				return parent, i, true, nil
			}
		}
	}
	return leaseRecord{}, 0, false, nil
}

func channelHandle(w channelNative) api.ProcessHandle {
	return api.ProcessHandle{ID: w.Reg.LaunchID, Target: w.Reg.Job.Lease.Target, ContainmentID: w.Lease.ContainmentID, Generation: w.Gate.Prepared.ProcessGeneration}
}

// Prepared recovery reads the original kernel owner and never creates or
// releases a process. Opening with projected channel credentials is separate.
func (m *leaseManager) reconcileChannel(ctx context.Context, r channelReg) (api.LaunchReconciliation, error) {
	p, i, err := m.channelOwner(ctx, r)
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	if i < 0 || p.Channels[i].Gate == nil {
		return api.LaunchReconciliation{}, failure(api.CodePrerequisite, "channel has no retained native gate")
	}
	w := p.Channels[i]
	live := m.gates[w.Lease.ID]
	if live == nil || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
		return api.LaunchReconciliation{}, failure(api.CodeContainmentUnknown, "channel reconciliation lost the original native lifetime")
	}
	if w.Gate.State != "prepared" || w.Gate.Permit != nil {
		return api.LaunchReconciliation{}, failure(api.CodeContainmentUnknown, "channel preparation is not known unopened")
	}
	observation, err := live.Observe(ctx, channelHandle(w))
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	if observation.State != "running" {
		return api.LaunchReconciliation{}, failure(api.CodeContainmentUnknown, "channel prepared gate is no longer live")
	}
	observation.State = "prepared"
	return api.LaunchReconciliation{Prepared: &w.Gate.Prepared, GateState: "prepared", Observation: observation}, nil
}

// Collection cancels only an unopened preparation. Native stop, UID/cgroup
// quiescence and resource removal precede the durable release of its pool UID.
func (m *leaseManager) collectChannel(ctx context.Context, r channelReg) error {
	if err := validChannelReg(r, m.binding.Config); err != nil {
		return err
	}
	p, err := m.find(r.ParentLeaseID)
	if err != nil {
		return err
	}
	for i := range p.Channels {
		w := &p.Channels[i]
		if w.Reg.Job.Lease.ID != r.Job.Lease.ID {
			continue
		}
		if w.Reg.LaunchID != r.LaunchID || w.Reg.Job.ProviderIdempotencyKey != r.Job.ProviderIdempotencyKey {
			return failure(api.CodeConflict, "channel collection changed its original job")
		}
		if w.Collected {
			return nil
		}
		if w.Gate != nil && w.Gate.Permit != nil {
			return failure(api.CodeConflict, "opened channel requires its measured execution retirement")
		}
		child := channelChild(p, *w)
		if live := m.gates[w.Lease.ID]; live != nil {
			if err := m.killContainment(ctx, child); err != nil {
				return err
			}
			if err := live.Close(); err != nil {
				return err
			}
			observation, err := live.Stop(ctx, channelHandle(*w))
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
		w.Collected = true
		if err := m.save(p); err != nil {
			return err
		}
		delete(m.gates, w.Lease.ID)
		return nil
	}
	return failure(api.CodeNotFound, "channel collection has no original native worker")
}

func (m *leaseManager) dispatchChannel(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	if method == "channel_register" {
		var seal channelSeal
		if err := decodeStrict(raw, &seal); err != nil {
			return nil, err
		}
		return m.registerChannel(ctx, seal)
	}
	var r channelReg
	if err := decodeStrict(raw, &r); err != nil {
		return nil, err
	}
	switch method {
	case "channel_lease":
		return m.allocateChannel(ctx, r)
	case "channel_prepare":
		return m.prepareChannel(ctx, r)
	case "channel_reconcile":
		return m.reconcileChannel(ctx, r)
	case "channel_collect":
		return api.Empty{}, m.collectChannel(ctx, r)
	}
	return nil, failure(api.CodeInvalid, "unknown channel native operation")
}
