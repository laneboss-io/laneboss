package admin

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

type channelStore interface {
	api.ChannelPlanSource
	ChannelWorkerID(context.Context, api.Scope, api.EffectLease) (api.ID, error)
}

func (s *Service) channelAuthority(ctx context.Context, job api.ChannelJob, claim api.EffectLease) (channelReg, api.Scope, error) {
	r := channelReg{Job: job, Claim: claim}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: claim.Record.ClaimantID}, Source: "service"}
	current, err := s.deps.Store.Effect(ctx, scope, job.Lease.EffectID)
	if err != nil {
		return r, scope, err
	}
	if !reflect.DeepEqual(current, claim.Record) || current.Effect.Channel == nil || !reflect.DeepEqual(*current.Effect.Channel, job) {
		return r, scope, failure(api.CodeConflict, "channel helper requires its original current store claim")
	}
	control, ok := s.deps.Store.(channelStore)
	if !ok {
		return r, scope, api.NotImplemented("lb-v2-service", "channel native plan and identity reservation")
	}
	r.LaunchID, err = control.ChannelWorkerID(ctx, scope, claim)
	if err != nil {
		return r, scope, err
	}
	r.Plan, err = control.ChannelPlan(ctx, scope, claim)
	if err != nil {
		return r, scope, err
	}
	lane, err := s.deps.Store.Lane(ctx, scope, job.Lease.Target)
	if err != nil {
		return r, scope, err
	}
	parent, err := s.deps.Store.LaunchBinding(ctx, lane.LaunchID)
	if err != nil {
		return r, scope, err
	}
	if parent.Record.Target != job.Lease.Target || parent.Record.Kind != "agent" || parent.Record.Revoked {
		return r, scope, failure(api.CodeConflict, "channel helper parent is outside the current sender run")
	}
	r.ParentLeaseID = parent.Record.UIDLeaseID
	return r, scope, validChannelReg(r, s.deps.Config)
}

func (s *Service) ChannelWorkerLease(ctx context.Context, job api.ChannelJob, claim api.EffectLease) (api.HelperLease, error) {
	r, _, err := s.channelAuthority(ctx, job, claim)
	if err != nil {
		return api.HelperLease{}, err
	}
	var result api.HelperLease
	if err := s.call(ctx, "channel_lease", r, &result); err != nil {
		return result, err
	}
	return result, validateLease(result, s.binding)
}

func (s *Service) RegisterChannelWorker(ctx context.Context, job api.ChannelJob, claim api.EffectLease, handoff api.PreparedSpecHandoff, endpoint api.InstalledBinding) (api.PreparedSpecReceipt, error) {
	r, scope, err := s.channelAuthority(ctx, job, claim)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	original, err := s.readLaunchObject(ctx, scope, handoff.Original, job.Lease.OperationID, job.Lease.Target.LifeID, false)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	input, err := s.readLaunchObject(ctx, scope, job.Lease.Input, job.Lease.OperationID, job.Lease.Target.LifeID, false)
	if err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	registrar, ok := s.deps.Store.(api.CredentialWorkerRegistrationStore)
	if !ok {
		return api.PreparedSpecReceipt{}, failure(api.CodePrerequisite, "channel requires its protected credential worker registration")
	}
	if err := registrar.RegisterCredentialWorker(api.WithEffectLease(ctx, claim), scope, handoff); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	var result api.PreparedSpecReceipt
	err = s.call(ctx, "channel_register", channelSeal{Reg: r, Spec: specRegistration{Handoff: handoff, Original: original}, Endpoint: endpoint, Input: input}, &result)
	return result, err
}

func (s *Service) PrepareChannelWorker(ctx context.Context, job api.ChannelJob, claim api.EffectLease) (api.PreparedLaunch, error) {
	r, _, err := s.channelAuthority(ctx, job, claim)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	var result api.PreparedLaunch
	if err := s.call(ctx, "channel_prepare", r, &result); err != nil {
		return result, err
	}
	return result, s.bindChannelContainment(ctx, r)
}

func (s *Service) ReconcileChannelWorker(ctx context.Context, job api.ChannelJob, claim api.EffectLease) (api.LaunchReconciliation, error) {
	r, _, err := s.channelAuthority(ctx, job, claim)
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	var result api.LaunchReconciliation
	err = s.call(ctx, "channel_reconcile", r, &result)
	return result, err
}

func (s *Service) CollectChannelWorker(ctx context.Context, job api.ChannelJob, claim api.EffectLease) error {
	r, _, err := s.channelAuthority(ctx, job, claim)
	if err != nil {
		return err
	}
	var result api.Empty
	return s.call(ctx, "channel_collect", r, &result)
}
