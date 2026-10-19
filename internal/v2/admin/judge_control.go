package admin

import (
	"context"
	"encoding/json"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

type judgeOpen struct {
	Reg     judgeReg
	Request api.HelperOpenRequest
	Binding api.LaunchBindingRequest
}

func judgeHandle(w judgeNative) api.ProcessHandle {
	return api.ProcessHandle{ID: w.Reg.LaunchID, Target: w.Reg.Lease.Target, ContainmentID: w.Lease.ContainmentID, Generation: w.Gate.Prepared.ProcessGeneration}
}

func (m *leaseManager) openJudge(ctx context.Context, q judgeOpen) (api.ProcessHandle, error) {
	p, i, err := m.judgeOwner(ctx, q.Reg)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if i < 0 || p.Judges[i].Gate == nil || m.workerLaunch == nil {
		return api.ProcessHandle{}, failure(api.CodeForbidden, "judge open requires the original borrowed native gate")
	}
	w := &p.Judges[i]
	if err := validateOpenCommit(q.Request, q.Binding, m.binding.Config); err != nil {
		return api.ProcessHandle{}, err
	}
	if q.Request.Prepared != w.Gate.Prepared || q.Binding.Record.ID != w.Reg.LaunchID || q.Binding.Record.UIDLeaseID != w.Lease.ID ||
		q.Binding.Record.Actor != w.Reg.Actor || q.Binding.Record.HostUID != w.Lease.UID ||
		q.Request.OperationID != w.Reg.Lease.OperationID || q.Request.EffectID != w.Reg.Lease.EffectID ||
		w.State != "prepared" || w.Gate.State != "prepared" || w.Gate.Permit != nil {
		return api.ProcessHandle{}, failure(api.CodeConflict, "judge gate changed or its one-use release was consumed")
	}
	live := m.gates[w.Lease.ID]
	if live == nil || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "judge original native gate owner was lost")
	}
	permit := q.Request.Permit
	w.State, w.Gate.State, w.Gate.Permit = "opening", "opening", &permit
	if err := m.save(p); err != nil {
		return api.ProcessHandle{}, err
	}
	if err := live.Release(); err != nil {
		return api.ProcessHandle{}, err
	}
	w.State, w.Gate.State = "opened", "opened"
	return judgeHandle(*w), m.save(p)
}

func (m *leaseManager) findJudge(r judgeReg) (leaseRecord, int, error) {
	p, err := m.find(r.ParentLeaseID)
	if err != nil {
		return p, 0, err
	}
	for i, w := range p.Judges {
		if w.Reg.Lease.ID == r.Lease.ID {
			if !reflect.DeepEqual(w.Reg, r) {
				return p, i, failure(api.CodeConflict, "judge observation changed its original job")
			}
			return p, i, nil
		}
	}
	return p, 0, failure(api.CodeNotFound, "judge original native worker is absent")
}

func (m *leaseManager) observeJudge(ctx context.Context, r judgeReg, collect bool) (api.ProcessObservation, error) {
	p, i, err := m.findJudge(r)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	w := &p.Judges[i]
	if w.Collected && w.Observation != nil {
		return *w.Observation, nil
	}
	if w.Gate == nil {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "judge native preparation is incomplete")
	}
	live := m.gates[w.Lease.ID]
	if live == nil || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "judge native lifetime was lost; retain its original unknown cost reservation")
	}
	child := judgeChild(p, *w)
	var observation api.ProcessObservation
	if collect {
		if err := m.killContainment(ctx, child); err != nil {
			return observation, err
		}
		if err := live.Close(); err != nil {
			return observation, err
		}
		observation, err = live.Stop(ctx, judgeHandle(*w))
	} else {
		observation, err = live.Observe(ctx, judgeHandle(*w))
	}
	if err != nil {
		return observation, err
	}
	if collect {
		if err := m.waitContainmentEmpty(ctx, child); err != nil {
			return observation, err
		}
		if err := m.resources.Quiescent(ctx, child); err != nil {
			return observation, err
		}
		zero := uint64(0)
		observation.Survivors = &zero
		if err := m.resources.Remove(ctx, child); err != nil {
			return observation, err
		}
		if err := m.closeJudgeRelay(w.Lease.ID); err != nil {
			return observation, err
		}
		w.Collected = true
		delete(m.gates, w.Lease.ID)
	}
	w.Observation = &observation
	return observation, m.save(p)
}

func (m *leaseManager) dispatchJudge(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	if method == "judge_register" {
		var q judgeSeal
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return m.registerJudge(ctx, q)
	}
	if method == "judge_open" {
		var q judgeOpen
		if err := decodeStrict(raw, &q); err != nil {
			return nil, err
		}
		return m.openJudge(ctx, q)
	}
	var r judgeReg
	if err := decodeStrict(raw, &r); err != nil {
		return nil, err
	}
	switch method {
	case "judge_lease":
		return m.allocateJudge(ctx, r)
	case "judge_prepare":
		return m.prepareJudge(ctx, r)
	case "judge_observe":
		return m.observeJudge(ctx, r, false)
	case "judge_collect":
		return m.observeJudge(ctx, r, true)
	}
	return nil, failure(api.CodeInvalid, "unknown native judge operation")
}
