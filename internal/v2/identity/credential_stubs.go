package identity

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.CredentialProjectionIdentity = (*Service)(nil)

// CredentialProjectionPeers is an installed native dependency, never an RPC
// assertion or a property inferred from a socket pathname. Implementations must
// remeasure both pinned executables/lifetimes, boot and installation generation,
// and authenticate this message's writer on the distinct private helper/broker
// channel. Ordinary lane/human PeerVerifier implementations do not satisfy it.
// The native owner must supply this port; missing support refuses every export.
type CredentialProjectionPeers interface {
	VerifyCredentialProjection(context.Context, api.VerifiedPeer, api.CredentialProjectionAuthority) error
}

func (s *Service) AuthorizeCredentialProjection(ctx context.Context, peer api.VerifiedPeer, request api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	var empty api.CredentialProjectionAuthority
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if nilDependency(peer) {
		return empty, refusal(api.CodeUnauthenticated, "credential projection requires its native control peer")
	}
	if err := api.ValidateCredentialProjectionRequest(request, s.deps.Clock.Now()); err != nil {
		return empty, err
	}
	if err := peer.Alive(ctx); err != nil {
		return empty, err
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return empty, err
	}
	record, err := s.deps.Store.CredentialProjection(ctx, request.Handoff.Config, request.Prepared.ID)
	if err != nil {
		return empty, err
	}
	record, err = copyProjection(record)
	if err != nil {
		return empty, err
	}
	a := record.Authority
	if !reflect.DeepEqual(a.Request, request) {
		return empty, refusal(api.CodeConflict, "credential request differs from its protected reservation")
	}
	if err := s.checkProjectionRecord(record); err != nil {
		return empty, err
	}
	if facts != a.HelperPeer {
		return empty, refusal(api.CodeUnauthenticated, "credential channel peer differs from the pinned root helper")
	}
	if err := s.checkProjectionState(ctx, a.Request); err != nil {
		return empty, err
	}
	verifier, ok := s.deps.Peers.(CredentialProjectionPeers)
	if !ok || nilDependency(verifier) {
		return empty, gap("AuthorizeCredentialProjection", "installed native credential-channel executable and lifetime verification")
	}
	if err := verifier.VerifyCredentialProjection(ctx, peer, a); err != nil {
		return empty, err
	}
	// No in-memory authorization cache: a changed source/fence or expired claim
	// during native verification invalidates this same projection, not a new one.
	live, err := s.deps.Store.CredentialProjection(ctx, request.Handoff.Config, request.Prepared.ID)
	if err != nil {
		return empty, err
	}
	if !reflect.DeepEqual(live, record) {
		return empty, refusal(api.CodeConflict, "credential projection changed during peer verification")
	}
	if err := s.checkProjectionState(ctx, a.Request); err != nil {
		return empty, err
	}
	current, err := peer.Facts(ctx)
	if err != nil {
		return empty, err
	}
	if current != facts {
		return empty, refusal(api.CodeUnauthenticated, "credential channel writer changed during authorization")
	}
	return copyProjection(a)
}

func (s *Service) checkProjectionRecord(record api.CredentialProjectionRecord) error {
	a := record.Authority
	if err := api.ValidateCredentialProjectionRequest(a.Request, s.deps.Clock.Now()); err != nil {
		return err
	}
	if !validID(a.ID) || a.Generation == 0 || a.Generation >= 1<<53-1 || a.Revoked || record.Fence != nil || record.Withdrawal != nil ||
		record.State != "reserved" && record.State != "held" ||
		record.State == "reserved" && (record.Generation != a.Generation || record.Receipt != nil) ||
		record.State == "held" && (record.Generation != a.Generation+1 || record.Receipt == nil) {
		return refusal(api.CodeForbidden, "credential projection is fenced, revoked or not current")
	}
	if !validID(a.Helper.ID) || !validDigest(a.Helper.SHA256) || a.Helper.Version == "" ||
		!validID(a.Broker.ID) || !validDigest(a.Broker.SHA256) || a.Broker.Version == "" || a.Helper == a.Broker ||
		a.InstallationGeneration == 0 || a.InstallationGeneration >= 1<<53 || a.BootID == "" ||
		a.HelperPeer.HostUID != 0 || a.HelperPeer.HostPID <= 1 ||
		a.BrokerPeer.HostUID == 0 || a.ServiceUID == 0 || a.ServiceUID == a.Request.Lease.UID ||
		a.BrokerPeer.HostUID == a.ServiceUID || a.BrokerPeer.HostUID == a.Request.Lease.UID || a.BrokerPeer.HostGID == 0 ||
		a.BrokerPeer.HostPID <= 1 || a.BrokerPeer.HostPID == a.HelperPeer.HostPID ||
		!validID(a.BrokerPeer.ContainmentID) || a.BrokerPeer.ContainmentID == a.Request.Lease.ContainmentID {
		return refusal(api.CodeUnauthenticated, "credential projection lacks distinct installed helper and outside broker pins")
	}
	for _, facts := range []api.PeerFacts{a.HelperPeer, a.BrokerPeer} {
		boot, lifetime, ok := strings.Cut(facts.ProcessGeneration, ":")
		if !ok || boot != a.BootID || lifetime == "" {
			return refusal(api.CodeUnauthenticated, "credential peer boot differs from protected installation")
		}
	}
	targets, err := api.CredentialTargets(a.Request, s.deps.Clock.Now())
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(a.Targets, targets) || len(a.Sources) != len(targets) {
		return refusal(api.CodeIntegrity, "credential projection changed its complete selected targets")
	}
	for index, source := range a.Sources {
		if source.Revoked || source.Generation == 0 || source.Generation >= 1<<53 || source.Key != targets[index].Key ||
			source.Version == "" || targets[index].SlotID == "" && source.Version != targets[index].Version {
			return refusal(api.CodeForbidden, "credential projection source is revoked or changed")
		}
	}
	return nil
}

func (s *Service) checkProjectionState(ctx context.Context, request api.CredentialProjectionRequest) error {
	return s.checkCredentialState(ctx, request, false)
}

func (s *Service) checkCredentialState(ctx context.Context, request api.CredentialProjectionRequest, opening bool) error {
	scope := api.Scope{Config: request.Handoff.Config, Actor: request.Cause.Actor,
		EndpointGeneration: request.Prepared.EndpointGeneration, PolicyGeneration: request.Handoff.Spec.PolicyGeneration}
	effect, err := s.deps.Store.Effect(ctx, scope, request.Cause.EffectID)
	if err != nil {
		return err
	}
	claimed := reflect.DeepEqual(effect, request.Claim.Record) && api.EffectLeaseClaimed(request.Claim)
	completed := opening && effect.State == api.EffectCompleted && effect.Generation == request.Claim.Record.Generation+1 &&
		reflect.DeepEqual(effect.Effect, request.Claim.Record.Effect) && effect.ClaimID == request.Claim.ClaimID && effect.ClaimantID == request.Claim.Record.ClaimantID &&
		effect.Outcome != nil && effect.Outcome.Status == "succeeded" && effect.Outcome.EffectID == request.Cause.EffectID &&
		effect.Outcome.ClaimID == request.Claim.ClaimID && effect.Outcome.ExpectedGeneration == request.Claim.Record.Generation &&
		effect.Outcome.Prepared != nil && *effect.Outcome.Prepared == request.Prepared
	if !claimed && !completed {
		return refusal(api.CodeConflict, "credential projection lost its current prepare claim")
	}
	if err := api.ValidateCredentialProjectionRequest(request, s.deps.Clock.Now()); err != nil {
		return err
	}
	lane, err := s.deps.Store.Lane(ctx, scope, request.Prepared.Target)
	if err != nil {
		var missing *api.Error
		if opening || request.Handoff.Spec.Kind != "agent" || !errors.As(err, &missing) || missing.Code != api.CodeNotFound {
			return err
		}
		// A first root has no lane until the original closed prepare is
		// committed. Its issued plan, exact handoff and allocation are authority.
		plan, readErr := s.deps.Store.LaunchPlan(ctx, scope, request.Handoff.Spec.PlanID)
		if readErr != nil {
			return readErr
		}
		if plan.Phase != "spec_retained" || plan.Plan == nil || plan.Handoff == nil || !reflect.DeepEqual(*plan.Handoff, request.Handoff) ||
			plan.Plan.Lease != request.Lease || plan.Plan.Data.Home != request.Home ||
			plan.Reservation.CancellationEpoch != request.Cause.CancellationEpoch || api.ValidateAgentLaunchSpec(request.Handoff.Spec, *plan.Plan) != nil {
			return refusal(api.CodeConflict, "credential projection has no current retained pre-bind launch")
		}
	} else if lane.Cleaned || lane.LifeID != request.Prepared.Target.LifeID || lane.Run != request.Prepared.Target.Run ||
		lane.CancellationEpoch != request.Cause.CancellationEpoch || request.Handoff.Spec.Kind == "agent" && lane.GrantSetID != request.Handoff.Spec.Grants.ID {
		return refusal(api.CodeConflict, "credential projection lost its current life or cancellation fence")
	}
	grants, err := s.deps.Store.Grants(ctx, request.Handoff.Spec.Grants.ID)
	if err != nil {
		return err
	}
	if !equalLaunchGrants(grants, request.Handoff.Spec.Grants) {
		return refusal(api.CodeForbidden, "credential projection differs from current issued grants")
	}
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, scope)
	if err != nil {
		return err
	}
	if policy.Generation == 0 || policy.Generation < request.Handoff.Spec.PolicyGeneration ||
		request.Handoff.Spec.Kind == "agent" && (policy.Generation != request.Handoff.Spec.PolicyGeneration || policy.Generation != grants.PolicyGeneration) {
		return refusal(api.CodeConflict, "credential projection policy changed before opening")
	}
	return nil
}

func (s *Service) CheckLaunchCredentials(ctx context.Context, binding api.LaunchBindingRequest) (api.CredentialProjectionRecord, error) {
	var empty api.CredentialProjectionRecord
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := validateBindingRequest(binding); err != nil {
		return empty, err
	}
	durable, err := s.deps.Store.LaunchBinding(ctx, binding.Record.ID)
	if err != nil {
		return empty, err
	}
	if !reflect.DeepEqual(durable, binding) {
		return empty, refusal(api.CodeConflict, "credential opening differs from its durable launch binding")
	}
	record, err := s.deps.Store.CredentialProjection(ctx, durable.Record.Config, durable.Prepared.ID)
	if err != nil {
		return empty, err
	}
	record, err = copyProjection(record)
	if err != nil {
		return empty, err
	}
	if err := s.checkProjectionRecord(record); err != nil {
		return empty, err
	}
	if durable.Record.Kind == "agent" && (durable.Recovery == nil || !reflect.DeepEqual(record.Authority.Request.Handoff, durable.Recovery.Handoff)) {
		return empty, refusal(api.CodeIntegrity, "credential holding differs from the retained prepared spec")
	}
	if err := s.checkCredentialState(ctx, record.Authority.Request, true); err != nil {
		return empty, err
	}
	if checker, ok := s.deps.Store.(interface {
		CheckCredentialProjection(context.Context, string, api.ID, api.Generation) error
	}); ok {
		if err := checker.CheckCredentialProjection(ctx, durable.Record.Config, durable.Prepared.ID, record.Generation); err != nil {
			return empty, err
		}
	}
	live, err := s.deps.Store.CredentialProjection(ctx, durable.Record.Config, durable.Prepared.ID)
	if err != nil {
		return empty, err
	}
	if !reflect.DeepEqual(live, record) {
		return empty, refusal(api.CodeConflict, "credential holding changed before its launch permit")
	}
	if err := api.ValidateCredentialProjectionGate(record, durable, s.deps.Clock.Now()); err != nil {
		return empty, err
	}
	return copyProjection(record)
}

// Return independent metadata, never aliases into a protected store record.
// These private DTOs contain no credential values or descriptor handles.
func copyProjection[T any](value T) (T, error) {
	var result T
	data, err := json.Marshal(value)
	if err != nil || json.Unmarshal(data, &result) != nil {
		return result, refusal(api.CodeIntegrity, "credential authority metadata cannot be copied")
	}
	return result, nil
}
