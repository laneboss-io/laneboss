package lifecycle

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// Recovery consumes identity's protected projection check and the actual store
// record. It does not perform descriptor transfer as the service UID or bind a
// second helper. Assembly owns the one-use broker/identity/helper binding;
// identity and helper own the live projection guard through actual OpenGate.
func (execution *planExecution) credentialProjection(ctx context.Context, binding api.LaunchBindingRequest, plan api.LaunchPlan) error {
	s, r := execution.service, plan.Reservation
	if execution.record.Phase == "opened" {
		return execution.openedProjection(ctx, binding, plan)
	}
	control := s.deps.CredentialIdentity
	if absent(control) {
		control, _ = s.deps.Identity.(api.CredentialProjectionIdentity)
	}
	if absent(control) {
		record, err := s.CheckLaunchCredentials(ctx, binding)
		if err != nil {
			return err
		}
		return execution.prepareEffect(ctx, record.Authority.Request)
	}
	record, err := control.CheckLaunchCredentials(ctx, binding)
	if err != nil {
		return failure(err)
	}
	request := record.Authority.Request
	if api.ValidateCredentialProjectionGate(record, binding, s.deps.Clock.Now()) != nil ||
		execution.record.Handoff == nil || !reflect.DeepEqual(request.Handoff, *execution.record.Handoff) ||
		request.Home != plan.Data.Home || request.Lease != plan.Lease ||
		request.Cause.CancellationEpoch != r.CancellationEpoch || request.Cause.LogicalTurnID != execution.input.turn {
		return integrity("launch recovery has no exact held credential projection")
	}
	retained, err := s.deps.Store.CredentialProjection(ctx, r.Config, binding.Prepared.ID)
	if err != nil {
		return failure(err)
	}
	if retained.Authority.ID != record.Authority.ID {
		return integrity("credential projection read-back changed its original authority")
	}
	if !reflect.DeepEqual(retained, record) {
		return integrity("credential projection differs from its protected store record")
	}
	return execution.prepareEffect(ctx, request)
}

// CheckLaunchCredentials consumes protected durable holding metadata. It does
// not authorize native peers or issue a LaunchPermit; those remain identity's
// and the helper's responsibilities at their existing native boundaries.
func (s *Service) CheckLaunchCredentials(ctx context.Context, binding api.LaunchBindingRequest) (api.CredentialProjectionRecord, error) {
	var empty api.CredentialProjectionRecord
	if err := contextReady(ctx); err != nil {
		return empty, err
	}
	if err := s.ready(); err != nil {
		return empty, err
	}
	durable, err := s.deps.Store.LaunchBinding(ctx, binding.Record.ID)
	if err != nil {
		return empty, failure(err)
	}
	if !reflect.DeepEqual(durable, binding) || binding.Record.Revoked || binding.Recovery == nil {
		return empty, integrity("credential check differs from the durable launch binding")
	}
	record, err := s.deps.Store.CredentialProjection(ctx, binding.Record.Config, binding.Prepared.ID)
	if err != nil {
		return empty, failure(err)
	}
	if err := api.ValidateCredentialProjectionGate(record, binding, s.deps.Clock.Now()); err != nil {
		return empty, failure(err)
	}
	r := record.Authority.Request
	if !reflect.DeepEqual(r.Handoff, binding.Recovery.Handoff) {
		return empty, integrity("credential holding differs from the retained handoff")
	}
	grants, err := s.deps.Store.Grants(ctx, binding.Record.GrantSetID)
	if err != nil {
		return empty, failure(err)
	}
	if grants.Revoked || !reflect.DeepEqual(grants, r.Handoff.Spec.Grants) || grants.ID != binding.Record.GrantSetID || grants.SHA256 != binding.Record.GrantsSHA256 {
		return empty, problem(api.CodeForbidden, "credential holding differs from current issued grants", "Withdraw the original projection before releasing its allocation.")
	}
	scope := api.Scope{Config: binding.Record.Config, Actor: api.Actor{Kind: "service", ID: r.Claim.Record.ClaimantID}, Source: "worker"}
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, scope)
	if err != nil {
		return empty, failure(err)
	}
	if policy.Generation != grants.PolicyGeneration || policy.Generation != r.Handoff.Spec.PolicyGeneration {
		return empty, problem(api.CodeConflict, "credential holding policy generation changed", "Reconcile the original held projection.")
	}
	plan, err := s.deps.Store.LaunchPlan(ctx, scope, binding.Recovery.PlanID)
	if err != nil {
		return empty, failure(err)
	}
	if plan.Plan == nil || plan.Phase != "bound" || api.ValidateLaunchBindingPlan(binding, *plan.Plan) != nil {
		return empty, integrity("credential holding has no exact bound launch plan")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, binding.Record.Target)
	if err != nil {
		return empty, failure(err)
	}
	if lane.Cleaned || lane.LaunchID != binding.Record.ID || lane.CancellationEpoch != r.Cause.CancellationEpoch || lane.GrantSetID != grants.ID ||
		lane.LogicalTurnID != r.Cause.LogicalTurnID || lane.PolicyGeneration != grants.PolicyGeneration {
		return empty, problem(api.CodeConflict, "credential holding lost its current life fence", "Withdraw the original projection.")
	}
	if checker, ok := s.deps.Store.(interface {
		CheckCredentialProjection(context.Context, string, api.ID, api.Generation) error
	}); ok {
		if err := checker.CheckCredentialProjection(ctx, binding.Record.Config, binding.Prepared.ID, record.Generation); err != nil {
			return empty, failure(err)
		}
	}
	execution := &planExecution{service: s, scope: scope, record: plan}
	if err := execution.prepareEffect(ctx, r); err != nil {
		return empty, err
	}
	live, err := s.deps.Store.CredentialProjection(ctx, binding.Record.Config, binding.Prepared.ID)
	if err != nil {
		return empty, failure(err)
	}
	if !reflect.DeepEqual(live, record) {
		return empty, problem(api.CodeConflict, "credential holding changed during validation", "Reload its current protected record.")
	}
	return live, nil
}

// Historical correlation never obtains a new permit or rechecks an expired
// opening claim. A fenced/withdrawn record still names the original process.
func (execution *planExecution) openedProjection(ctx context.Context, binding api.LaunchBindingRequest, plan api.LaunchPlan) error {
	record, err := execution.service.deps.Store.CredentialProjection(ctx, plan.Reservation.Config, binding.Prepared.ID)
	if err != nil {
		return failure(err)
	}
	request := record.Authority.Request
	if !validID(record.Authority.ID) || request.Prepared != binding.Prepared || execution.record.Handoff == nil ||
		!reflect.DeepEqual(request.Handoff, *execution.record.Handoff) || request.Home != plan.Data.Home || request.Lease != plan.Lease ||
		request.Cause.CancellationEpoch != plan.Reservation.CancellationEpoch || request.Cause.LogicalTurnID != execution.input.turn ||
		record.State != "held" && record.State != "withdrawing" && record.State != "withdrawn" {
		return integrity("opened launch lost its original credential projection")
	}
	if err := historicalProjection(record, binding, plan); err != nil {
		return err
	}
	return execution.prepareEffect(ctx, request)
}

func (execution *planExecution) prepareEffect(ctx context.Context, request api.CredentialProjectionRequest) error {
	claim := request.Claim
	prepare := claim.Record.Effect.HelperPrepare
	if request.Cause.Actor.Kind != "service" || !validID(request.Cause.Actor.ID) || !validID(claim.Record.ClaimantID) ||
		request.Cause.Kind != api.InternalHelperPrepare || prepare == nil ||
		request.Cause.Config != request.Handoff.Config || request.Cause.Target != request.Prepared.Target ||
		request.Cause.CauseOperationID != request.Handoff.OperationID || request.Cause.CauseRequestID != request.Handoff.RequestID ||
		request.Cause.RequestedBy != request.Handoff.Cause.RequestedBy || request.Lease.ID != request.Handoff.Spec.UIDLeaseID ||
		claim.Record.Effect.ID != request.Cause.EffectID || claim.Record.Effect.OperationID != request.Cause.CauseOperationID ||
		!api.RetainedCause(&prepare.Cause, request.Cause, claim.Record.ClaimantID) || prepare.LeaseID != request.Lease.ID || prepare.PreparedSpecID != request.Handoff.Spec.ID ||
		prepare.SpecSHA256 != request.Handoff.SpecSHA256 ||
		!api.RetainedCause(claim.Record.Effect.Context, request.Cause, claim.Record.ClaimantID) || effectRecord(claim.Record) != nil ||
		!api.EffectLeaseClaimed(claim) || claim.Record.ClaimID != claim.ClaimID || claim.Record.ClaimExpiresAt != claim.ExpiresAt {
		return integrity("credential projection has no original service prepare claim")
	}
	record, err := execution.service.deps.Store.Effect(ctx, execution.scope, claim.Record.Effect.ID)
	if err != nil {
		return failure(err)
	}
	if effectRecord(record) != nil || !reflect.DeepEqual(record.Effect, claim.Record.Effect) ||
		record.ClaimID != claim.ClaimID || record.ClaimantID != claim.Record.ClaimantID ||
		record.State != api.EffectClaimed && record.State != api.EffectCompleted || record.Generation < claim.Record.Generation ||
		record.State == api.EffectClaimed && !reflect.DeepEqual(record, claim.Record) ||
		record.State == api.EffectCompleted && (effectCompletion(record, claim) != nil || record.Outcome.Prepared == nil || *record.Outcome.Prepared != request.Prepared) {
		return integrity("credential projection differs from its retained helper prepare effect")
	}
	return nil
}
