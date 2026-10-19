package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) reconcileArchiveWorker(ctx context.Context, r archiveReg) (api.LaunchReconciliation, error) {
	p, err := m.archiveWorker(ctx, r)
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	w := p.Archive.Worker
	if w == nil || w.Gate == nil {
		return api.LaunchReconciliation{}, failure(api.CodePrerequisite, "archive has no retained prepared gate")
	}
	g := w.Gate
	live := m.gates[w.Lease.ID]
	if live == nil || live.PID() != g.PID || live.Generation() != g.Prepared.ProcessGeneration {
		return api.LaunchReconciliation{}, failure(api.CodeContainmentUnknown, "archive reconciliation lost its original native wait owner")
	}
	result := api.LaunchReconciliation{Prepared: &g.Prepared, GateState: g.State}
	if g.State == "prepared" && g.Permit == nil && g.Record == nil && g.Identity == nil {
		observation, err := live.Observe(ctx, archiveHandle(*w))
		if err != nil {
			return api.LaunchReconciliation{}, err
		}
		if observation.State != "running" {
			return api.LaunchReconciliation{}, failure(api.CodeContainmentUnknown, "archive prepared bootstrap is no longer live")
		}
		observation.State = "prepared"
		result.Observation = observation
		return result, nil
	}
	if g.State != "opened" || g.Permit == nil || g.Record == nil || g.Identity == nil {
		return api.LaunchReconciliation{}, failure(api.CodeContainmentUnknown, "archive release outcome is uncertain")
	}
	observation, err := m.observeArchive(ctx, r)
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	process := archiveHandle(*w)
	result.Process, result.ConsumedPermit, result.Observation = &process, g.Permit, observation
	return result, nil
}
