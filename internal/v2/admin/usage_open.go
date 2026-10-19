//go:build linux

package admin

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

type usageOpen struct {
	Reg      usageReg
	Request  api.HelperOpenRequest
	Record   api.LaunchRecord
	Identity api.IdentityCommit
}

func (s *Service) OpenUsageWorker(ctx context.Context, job api.UsageJob, claim api.EffectLease, request api.HelperOpenRequest) (api.ProcessHandle, error) {
	r, _, err := s.usageAuthority(ctx, job, claim)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, job.LaunchID)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if err := validateOpenCommit(request, binding, s.deps.Config); err != nil {
		return api.ProcessHandle{}, err
	}
	session := s.workerSession(ctx)
	if session == nil {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "usage release requires its enclosing native transaction")
	}
	var result api.ProcessHandle
	err = session.call(ctx, "usage_open", usageOpen{Reg: r, Request: request, Record: binding.Record, Identity: binding.Identity}, &result)
	return result, err
}

func (s *Service) ObserveUsageWorker(ctx context.Context, job api.UsageJob, claim api.EffectLease) (api.ProcessObservation, error) {
	r, _, err := s.usageAuthority(ctx, job, claim)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	var result api.ProcessObservation
	err = s.call(ctx, "usage_observe", r, &result)
	return result, err
}

func (m *leaseManager) openUsage(ctx context.Context, q usageOpen) (api.ProcessHandle, error) {
	p, i, err := m.usageOwner(ctx, q.Reg)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if i < 0 {
		return api.ProcessHandle{}, failure(api.CodePrerequisite, "usage has no native allocation")
	}
	w := &p.Usages[i]
	if w.Gate == nil || w.Spec == nil {
		return api.ProcessHandle{}, failure(api.CodePrerequisite, "usage gate was not prepared")
	}
	binding := api.LaunchBindingRequest{Record: q.Record, Prepared: q.Request.Prepared, Identity: q.Identity}
	if err := validateOpenCommit(q.Request, binding, m.binding.Config); err != nil {
		return api.ProcessHandle{}, err
	}
	cause := *q.Reg.Claim.Record.Effect.Context
	cause.Kind, cause.Actor = api.InternalHelperOpen, api.Actor{Kind: "service", ID: q.Reg.Claim.Record.ClaimantID}
	r := binding.Record
	if q.Request.Cause != cause || q.Request.Prepared != w.Gate.Prepared || r.ID != q.Reg.LaunchID || r.Kind != "worker" || r.Actor != q.Reg.Job.Actor ||
		r.Target != q.Reg.Job.Lease.Target || r.UIDLeaseID != w.Lease.ID || r.HostUID != w.Lease.UID || r.ContainmentID != w.Lease.ContainmentID || r.ProcessGeneration != w.Gate.Prepared.ProcessGeneration ||
		r.GrantSetID != q.Reg.Job.Grants.ID || r.GrantsSHA256 != q.Reg.Job.Grants.SHA256 || r.Revoked {
		return api.ProcessHandle{}, failure(api.CodeForbidden, "usage release changed its committed worker tuple")
	}
	guard, ok := m.workerLaunch.(*workerHelperGuard)
	if !ok || guard.snapshot.Usage == nil || !reflect.DeepEqual(*guard.snapshot.Usage, q.Reg) {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "usage release lost its original native guard")
	}
	if err := guard.check(ctx); err != nil {
		return api.ProcessHandle{}, err
	}
	if w.Gate.State == "opened" {
		if w.Gate.Permit == nil || *w.Gate.Permit != q.Request.Permit || w.Gate.Record == nil || !reflect.DeepEqual(*w.Gate.Record, r) {
			return api.ProcessHandle{}, failure(api.CodeConflict, "usage retry changed its consumed permit")
		}
		return usageHandle(*w), nil
	}
	if w.Gate.State != "prepared" || w.Gate.Permit != nil {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "usage release outcome is uncertain")
	}
	live := m.gates[w.Lease.ID]
	if live == nil || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "usage lost its original native gate owner")
	}
	w.Gate.Permit, w.Gate.Record, w.Gate.Identity = &q.Request.Permit, &binding.Record, &binding.Identity
	w.Gate.State, w.State = "opening", "opening"
	if err := m.save(p); err != nil {
		return api.ProcessHandle{}, err
	}
	if err := live.Release(); err != nil {
		return api.ProcessHandle{}, err
	}
	w.Gate.State, w.State = "opened", "opened"
	if err := m.save(p); err != nil {
		return api.ProcessHandle{}, err
	}
	return usageHandle(*w), nil
}

func (m *leaseManager) observeUsage(ctx context.Context, r usageReg) (api.ProcessObservation, error) {
	p, i, err := m.usageOwner(ctx, r)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if i < 0 || p.Usages[i].Gate == nil {
		return api.ProcessObservation{}, failure(api.CodePrerequisite, "usage has no original process")
	}
	w := &p.Usages[i]
	live := m.gates[w.Lease.ID]
	if live == nil || live.PID() != w.Gate.PID || live.Generation() != w.Gate.Prepared.ProcessGeneration {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "usage native wait ownership changed")
	}
	observation, err := live.Observe(ctx, usageHandle(*w))
	if err != nil {
		return observation, err
	}
	if err := m.measureRunningSurvivors(ctx, usageChild(p, *w), &observation); err != nil {
		return api.ProcessObservation{}, err
	}
	if observation.State == "exited" {
		if err := m.waitContainmentEmpty(ctx, usageChild(p, *w)); err != nil {
			return api.ProcessObservation{}, err
		}
		if err := m.resources.Quiescent(ctx, usageChild(p, *w)); err != nil {
			return api.ProcessObservation{}, err
		}
		zero := uint64(0)
		observation.Survivors = &zero
		w.Observation, w.State = &observation, "exited"
		if err := m.save(p); err != nil {
			return api.ProcessObservation{}, err
		}
	}
	return observation, nil
}
