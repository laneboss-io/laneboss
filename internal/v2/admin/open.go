package admin

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func validateOpenCommit(request api.HelperOpenRequest, stored api.LaunchBindingRequest, config string) error {
	if err := validateCause(request.Cause, config, api.InternalHelperOpen); err != nil {
		return err
	}
	permit, prepared, record, commit := request.Permit, request.Prepared, stored.Record, stored.Identity
	if request.OperationID != request.Cause.CauseOperationID || request.EffectID != request.Cause.EffectID || request.Cause.Target != prepared.Target ||
		(record.Kind != "agent" && record.Kind != "worker") ||
		!validID(permit.LaunchID) || !validID(prepared.ID) || !validID(prepared.GateID) || !validID(prepared.ContainmentID) ||
		!validDigest(prepared.SpecSHA256) || prepared.ProcessGeneration == "" || prepared.EndpointGeneration == 0 ||
		stored.Prepared != prepared || record.ID != permit.LaunchID || record.ID == prepared.ID || record.Config != config || record.Revoked ||
		record.Target != prepared.Target || record.ProcessGeneration != prepared.ProcessGeneration || record.ContainmentID != prepared.ContainmentID ||
		record.EndpointGeneration != prepared.EndpointGeneration || record.HostUID == 0 || !validID(record.UIDLeaseID) ||
		!validID(record.GrantSetID) || !validDigest(record.GrantsSHA256) || record.PolicyGeneration == 0 ||
		permit.PreparedID != prepared.ID || commit.LaunchID != record.ID || !validID(commit.EventID) ||
		commit.CommittedSeq == 0 || commit.CommittedSeq > 1<<53-1 || commit.CommittedSeq != permit.CommittedSeq ||
		!validDigest(commit.RecordSHA256) || commit.RecordSHA256 != permit.RecordSHA256 {
		return failure(api.CodeIntegrity, "open request differs from the actual committed identity tuple")
	}
	return nil
}

func (s *Service) OpenGate(ctx context.Context, request api.HelperOpenRequest) (api.ProcessHandle, error) {
	if err := contextError(ctx); err != nil {
		return api.ProcessHandle{}, err
	}
	if err := validateCause(request.Cause, s.deps.Config, api.InternalHelperOpen); err != nil {
		return api.ProcessHandle{}, err
	}
	if !validID(request.Permit.LaunchID) {
		return api.ProcessHandle{}, failure(api.CodeInvalid, "open request lacks its launch identity")
	}
	if s.deps.Store == nil {
		return api.ProcessHandle{}, api.NotImplemented("lb-v2-service", "committed launch binding lookup")
	}
	stored, err := s.deps.Store.LaunchBinding(ctx, request.Permit.LaunchID)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if err := validateOpenCommit(request, stored, s.deps.Config); err != nil {
		return api.ProcessHandle{}, err
	}
	if stored.Record.Kind == "worker" {
		selector, err := s.dataSelector(ctx, stored.Record.UIDLeaseID)
		if err != nil {
			return api.ProcessHandle{}, err
		}
		return s.OpenDataWorker(ctx, selector, request)
	}
	claim, err := s.currentStage(ctx, request.Cause, api.InternalHelperOpen)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if stored.Recovery == nil {
		return api.ProcessHandle{}, failure(api.CodeIntegrity, "open requires the retained launch recovery binding")
	}
	scope := api.Scope{Config: s.deps.Config, Actor: request.Cause.Actor, Source: "service", PolicyGeneration: stored.Record.PolicyGeneration}
	retained, err := s.deps.Store.LaunchPlan(ctx, scope, stored.Recovery.PlanID)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if retained.Plan == nil || retained.Phase != "bound" && retained.Phase != "opened" {
		return api.ProcessHandle{}, failure(api.CodeIntegrity, "open has no committed bound plan")
	}
	r := retained.Reservation
	selected := claim.Effect.Launch != nil && reflect.DeepEqual(*claim.Effect.Launch, stored.Recovery.Handoff.Spec) ||
		claim.Effect.PlanLaunch != nil && claim.Effect.PlanLaunch.ReservationID == r.ID
	if r.OperationID != request.Cause.CauseOperationID || r.RequestID != request.Cause.CauseRequestID ||
		r.RequestedBy != request.Cause.RequestedBy || r.CancellationEpoch != request.Cause.CancellationEpoch ||
		!selected {
		return api.ProcessHandle{}, failure(api.CodeForbidden, "open effect selects a foreign retained launch")
	}
	if err := api.ValidateLaunchBindingPlan(stored, *retained.Plan); err != nil {
		return api.ProcessHandle{}, err
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if policy.Generation != stored.Record.PolicyGeneration {
		allowAndLog("open_policy_generation")
	}
	if err := api.ValidateCapturePolicy(retained.Plan.Capture, policy); err != nil {
		return api.ProcessHandle{}, err
	}
	knownUID := false
	for _, account := range s.binding.Lanes {
		knownUID = knownUID || account.UID == stored.Record.HostUID
	}
	// A lane running as the service account would hold the service's credentials: that stays refused.
	if stored.Record.HostUID == s.deps.ServiceUID {
		return api.ProcessHandle{}, failure(api.CodeIntegrity, "committed launch does not use this helper installation's lane lease")
	}
	if !knownUID || stored.Record.EndpointGeneration != s.binding.Generation {
		allowAndLog("open_lane_uid_lease")
	}
	grants, err := s.deps.Store.Grants(ctx, stored.Record.GrantSetID)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt))
	if parseErr != nil || !expires.After(time.Now()) || grants.Revoked || grants.LifeID != stored.Record.Target.LifeID ||
		grants.SHA256 != stored.Record.GrantsSHA256 || grants.PolicyGeneration != stored.Record.PolicyGeneration || !reflect.DeepEqual(grants, retained.Plan.Inputs.Grants) {
		return api.ProcessHandle{}, failure(api.CodeForbidden, "committed launch grants are stale or revoked")
	}
	currentClaim, err := s.currentStage(ctx, request.Cause, api.InternalHelperOpen)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if !reflect.DeepEqual(currentClaim, claim) {
		return api.ProcessHandle{}, failure(api.CodeConflict, "open effect claim changed before native release")
	}
	if _, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: scope, Internal: &request.Cause,
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: retained.Generation},
			{Kind: api.CompareGrants, ID: grants.ID, Generation: grants.Generation},
			{Kind: api.CompareOrg, ID: api.ID(s.deps.Config), Generation: policy.Generation}},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}); err != nil {
		return api.ProcessHandle{}, err
	}
	currentBinding, err := s.deps.Store.LaunchBinding(ctx, request.Permit.LaunchID)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if !reflect.DeepEqual(currentBinding, stored) {
		return api.ProcessHandle{}, failure(api.CodeConflict, "committed binding changed before native release")
	}
	if credentialRequired(stored.Recovery.Handoff.Spec) {
		s.credentialMu.Lock()
		identity := s.credentialIdentity
		bound := nonnilCredentialClient(s.credentialBroker)
		s.credentialMu.Unlock()
		if !bound || !nonnilCredentialClient(identity) {
			return api.ProcessHandle{}, failure(api.CodeUnavailable, "credential metadata owners are not bound")
		}
		projection, err := identity.CheckLaunchCredentials(ctx, stored)
		if err != nil {
			return api.ProcessHandle{}, err
		}
		if err := api.ValidateCredentialProjectionGate(projection, stored, time.Now()); err != nil {
			return api.ProcessHandle{}, err
		}
	}
	var result api.ProcessHandle
	if err := s.call(ctx, "open_gate", gateOpenRegistration{Request: request, Binding: stored, Policy: policy}, &result); err != nil {
		return api.ProcessHandle{}, err
	}
	if result.ID != stored.Record.ID || result.Target != request.Prepared.Target || result.ContainmentID != request.Prepared.ContainmentID || result.Generation != request.Prepared.ProcessGeneration {
		return api.ProcessHandle{}, failure(api.CodeIntegrity, "helper open substituted the committed prepared process")
	}
	return result, nil
}
