package admin

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) usageAuthority(ctx context.Context, job api.UsageJob, claim api.EffectLease) (usageReg, api.Scope, error) {
	r := usageReg{Job: job, Claim: claim, Plan: job.Plan, LaunchID: job.LaunchID, ParentLeaseID: job.ParentLeaseID}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: claim.Record.ClaimantID}, Source: "service"}
	current, err := s.deps.Store.Effect(ctx, scope, job.Lease.EffectID)
	if err != nil {
		return r, scope, err
	}
	if !reflect.DeepEqual(current, claim.Record) || current.Effect.Worker == nil || !reflect.DeepEqual(*current.Effect.Worker, job.Plan) {
		return r, scope, failure(api.CodeConflict, "usage helper requires its original current store claim")
	}
	control, ok := s.deps.Store.(interface {
		UsageJobForClaim(context.Context, api.Scope, api.EffectLease) (api.UsageJob, error)
	})
	if !ok {
		return r, scope, api.NotImplemented("lb-v2-service", "usage native plan and identity reservation")
	}
	retained, err := control.UsageJobForClaim(ctx, scope, claim)
	if err != nil {
		return r, scope, err
	}
	if !reflect.DeepEqual(retained, job) {
		return r, scope, failure(api.CodeIntegrity, "usage helper job changed")
	}
	parent, err := s.deps.Store.LaunchBinding(ctx, job.Input.Request.LaunchID)
	if err != nil {
		return r, scope, err
	}
	if parent.Record.Target != job.Lease.Target || parent.Record.UIDLeaseID != job.ParentLeaseID || parent.Record.Kind != "agent" || parent.Record.Revoked {
		return r, scope, failure(api.CodeConflict, "usage helper parent is outside the causing run")
	}
	return r, scope, validUsageReg(r, s.deps.Config)
}

func (s *Service) UsageWorkerLease(ctx context.Context, job api.UsageJob, claim api.EffectLease) (api.HelperLease, error) {
	r, _, err := s.usageAuthority(ctx, job, claim)
	if err != nil {
		return api.HelperLease{}, err
	}
	var result api.HelperLease
	if err := s.call(ctx, "usage_lease", r, &result); err != nil {
		return result, err
	}
	return result, validateLease(result, s.binding)
}

func (s *Service) RegisterUsageWorker(ctx context.Context, job api.UsageJob, claim api.EffectLease, handoff api.PreparedSpecHandoff, endpoint api.InstalledBinding) (api.PreparedSpecReceipt, error) {
	r, scope, err := s.usageAuthority(ctx, job, claim)
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
		return api.PreparedSpecReceipt{}, failure(api.CodePrerequisite, "usage requires its protected credential worker registration")
	}
	if err := registrar.RegisterCredentialWorker(api.WithEffectLease(ctx, claim), scope, handoff); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	var result api.PreparedSpecReceipt
	err = s.call(ctx, "usage_register", usageSeal{Reg: r, Spec: specRegistration{Handoff: handoff, Original: original}, Endpoint: endpoint, Input: input}, &result)
	return result, err
}

func (s *Service) PrepareUsageWorker(ctx context.Context, job api.UsageJob, claim api.EffectLease) (api.PreparedLaunch, error) {
	r, _, err := s.usageAuthority(ctx, job, claim)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	var result api.PreparedLaunch
	if err := s.call(ctx, "usage_prepare", r, &result); err != nil {
		return result, err
	}
	return result, s.bindUsageContainment(ctx, r)
}

func (s *Service) ReconcileUsageWorker(ctx context.Context, job api.UsageJob, claim api.EffectLease) (api.LaunchReconciliation, error) {
	r, _, err := s.usageAuthority(ctx, job, claim)
	if err != nil {
		return api.LaunchReconciliation{}, err
	}
	var result api.LaunchReconciliation
	err = s.call(ctx, "usage_reconcile", r, &result)
	return result, err
}

func (s *Service) CollectUsageWorker(ctx context.Context, job api.UsageJob, claim api.EffectLease) error {
	r, _, err := s.usageAuthority(ctx, job, claim)
	if err != nil {
		return err
	}
	var result api.Empty
	return s.call(ctx, "usage_collect", r, &result)
}
