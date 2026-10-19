package secrets

import (
	"context"
	"reflect"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func future(value api.Timestamp, now time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, string(value))
	return err == nil && strings.HasSuffix(string(value), "Z") && now.Before(t)
}

func validateGrant(grant api.SecretGrant, now time.Time) error {
	if !wire.ID(string(grant.ID)) || !wire.ID(string(grant.SourceHandle)) ||
		!wire.Name(grant.Name) || !wire.Name(grant.Version) ||
		grant.ParentGrantID != "" && !wire.ID(string(grant.ParentGrantID)) {
		return wire.Error(api.CodeInvalid, "secret selection requires an exact enrolled grant")
	}
	if !future(grant.ExpiresAt, now) {
		return wire.Error(api.CodeForbidden, "secret grant expired or has invalid expiry")
	}
	switch grant.Delivery {
	case "env":
		if !wire.EnvTarget(grant.Target) {
			return wire.Error(api.CodeForbidden, "secret target is a reserved or invalid environment name")
		}
	case "file":
		if !wire.FileTarget(grant.Target) {
			return wire.Error(api.CodeForbidden, "secret file target must remain beneath its private runtime directory")
		}
	default:
		return wire.Error(api.CodeInvalid, "secret delivery must be env or file")
	}
	return nil
}

func validateProfile(grant api.ProfileGrant, now time.Time) error {
	if !wire.ID(string(grant.ID)) || !wire.ID(string(grant.ProfileID)) ||
		!wire.Name(grant.Provider) || grant.ParentGrantID != "" && !wire.ID(string(grant.ParentGrantID)) {
		return wire.Error(api.CodeInvalid, "credential selection requires an exact delegated profile")
	}
	if grant.Driver != api.DriverClaudock && grant.Driver != api.DriverCodex {
		return wire.Error(api.CodeUnsupported, "credential driver is unsupported")
	}
	if !future(grant.ExpiresAt, now) {
		return wire.Error(api.CodeForbidden, "profile grant expired or has invalid expiry")
	}
	return nil
}

// currentGrants verifies the exact run and delegates ancestry/revocation/policy
// revalidation to the frozen grant resolver. It never fabricates a worker actor
// from a lane name; the composition root supplies the trusted service scope.
func (s *Service) currentGrants(ctx context.Context, target api.LifeRef, selections ...launchSelection) (api.GrantSet, error) {
	if err := wire.Context(ctx); err != nil {
		return api.GrantSet{}, err
	}
	if !wire.ID(string(target.LifeID)) || target.Run == 0 {
		return api.GrantSet{}, wire.Error(api.CodeInvalid, "credential target must identify an exact life and run")
	}
	if s.deps.ServiceScope.Config != s.deps.Config || s.deps.ServiceScope.Actor.Kind != "service" {
		return api.GrantSet{}, wire.Error(api.CodePrerequisite, "credential worker requires its installed service scope")
	}
	var lane api.Lane
	var grantSetID api.ID
	var policyGeneration api.Generation
	retained := len(selections) == 0
	if !retained {
		if len(selections) != 1 {
			return api.GrantSet{}, wire.Error(api.CodeInvalid, "credential launch requires one planning selector")
		}
		launch, err := s.reservedPlan(ctx, target, selections[0])
		if err != nil {
			return api.GrantSet{}, err
		}
		grantSetID, policyGeneration = launch.record.Reservation.GrantSetID, launch.record.Reservation.PolicyGeneration
	} else {
		var err error
		lane, err = s.deps.Store.Lane(ctx, s.deps.ServiceScope, target)
		if err != nil {
			return api.GrantSet{}, err
		}
		if lane.LifeID != target.LifeID || lane.Run != target.Run || lane.Cleaned ||
			lane.State == "merged" || lane.State == "abandoned" || !wire.ID(string(lane.GrantSetID)) {
			return api.GrantSet{}, wire.Error(api.CodeConflict, "credential target life or run is no longer current")
		}
		grantSetID, policyGeneration = lane.GrantSetID, lane.PolicyGeneration
	}
	grants, err := s.deps.Store.Grants(ctx, grantSetID)
	if err != nil {
		return api.GrantSet{}, err
	}
	if grants.ID != grantSetID || grants.LifeID != target.LifeID || grants.Revoked ||
		!retained && grants.PolicyGeneration != policyGeneration || !wire.Digest(grants.SHA256) ||
		!future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return api.GrantSet{}, wire.Error(api.CodeForbidden, "credential target grants are stale or revoked")
	}
	if wire.Nil(s.deps.Grants) {
		return api.GrantSet{}, wire.Error(api.CodePrerequisite, "credential broker requires its installed grant resolver")
	}
	var current api.GrantSet
	if len(selections) == 1 {
		current, err = s.deps.Grants.Resolve(ctx, s.deps.ServiceScope, api.GrantResolveRequest{ReservationID: selections[0].Claim.ReservationID})
	} else {
		current, err = s.deps.Grants.Revalidate(ctx, grants)
	}
	if err != nil {
		return api.GrantSet{}, err
	}
	if current.ID != grants.ID || current.LifeID != grants.LifeID || current.Revoked ||
		current.SHA256 != grants.SHA256 || current.Generation != grants.Generation ||
		current.PolicyGeneration != grants.PolicyGeneration ||
		!reflect.DeepEqual(current, grants) ||
		!future(current.ExpiresAt, s.deps.Clock.Now()) {
		return api.GrantSet{}, wire.Error(api.CodeConflict, "credential grants changed during validation")
	}
	policy, err := s.deps.Store.CurrentApprovedPolicy(ctx, s.deps.ServiceScope)
	if err != nil {
		return api.GrantSet{}, err
	}
	if !retained && policy.Generation != current.PolicyGeneration || !wire.Digest(policy.SHA256) {
		return api.GrantSet{}, wire.Error(api.CodeConflict, "credential grants no longer match current policy")
	}
	if retained {
		if lane.PolicyGeneration != policy.Generation {
			return api.GrantSet{}, wire.Error(api.CodeConflict, "credential live lane policy projection requires refresh")
		}
		if _, err := api.PolicyGenerationFor(api.PolicyRetainedSelection, policy.Generation, current.PolicyGeneration); err != nil {
			return api.GrantSet{}, err
		}
	}
	return current, nil
}

func (s *Service) selectedGrants(ctx context.Context, target api.LifeRef, selection launchSelection) (api.GrantSet, error) {
	if selection.Claim == (api.LaunchClaim{}) {
		return s.currentGrants(ctx, target)
	}
	return s.currentGrants(ctx, target, selection)
}

func (s *Service) Inject(ctx context.Context, target api.LifeRef, grants []api.SecretGrant) (api.Injection, error) {
	return s.inject(ctx, target, grants, launchSelection{})
}
func (s *Service) InjectLaunch(ctx context.Context, request api.LaunchInjectionRequest) (api.Injection, error) {
	return s.inject(ctx, request.Target, request.Grants, launchSelection{Claim: request.Claim, HelperLeaseID: request.HelperLeaseID})
}
func (s *Service) inject(ctx context.Context, target api.LifeRef, grants []api.SecretGrant, selection launchSelection) (api.Injection, error) {
	if grants == nil || len(grants) > 256 {
		return api.Injection{}, wire.Error(api.CodeInvalid, "secret grant selection must be a bounded array")
	}
	now := s.deps.Clock.Now()
	ids, targets := make(map[api.ID]bool), make(map[string]bool)
	for _, grant := range grants {
		if err := validateGrant(grant, now); err != nil {
			return api.Injection{}, err
		}
		key := grant.Delivery + ":" + grant.Target
		if ids[grant.ID] || targets[key] {
			return api.Injection{}, wire.Error(api.CodeInvalid, "secret grants or runtime targets collide")
		}
		ids[grant.ID], targets[key] = true, true
		if grant.Delivery == "file" {
			for _, other := range grants {
				if other.ID != grant.ID && other.Delivery == "file" &&
					strings.HasPrefix(other.Target, grant.Target+"/") {
					return api.Injection{}, wire.Error(api.CodeInvalid, "secret runtime file paths overlap")
				}
			}
		}
	}
	current, err := s.selectedGrants(ctx, target, selection)
	if err != nil {
		return api.Injection{}, err
	}
	for _, requested := range grants {
		found := false
		for _, enrolled := range current.Secrets {
			if enrolled == requested {
				found = true
				break
			}
		}
		if !found {
			return api.Injection{}, wire.Error(api.CodeForbidden, "secret selection exceeds the target's current grants")
		}
	}
	return s.prepareInjection(ctx, target, grants, current, selection)
}

func (s *Service) Acquire(ctx context.Context, target api.LifeRef, grant api.ProfileGrant) (api.CredentialSlot, error) {
	return s.acquire(ctx, target, grant, launchSelection{})
}
func (s *Service) AcquireLaunch(ctx context.Context, request api.LaunchProfileRequest) (api.CredentialSlot, error) {
	return s.acquire(ctx, request.Target, request.Grant, launchSelection{Claim: request.Claim, HelperLeaseID: request.HelperLeaseID})
}
func (s *Service) acquire(ctx context.Context, target api.LifeRef, grant api.ProfileGrant, selection launchSelection) (api.CredentialSlot, error) {
	if err := validateProfile(grant, s.deps.Clock.Now()); err != nil {
		return api.CredentialSlot{}, err
	}
	current, err := s.selectedGrants(ctx, target, selection)
	if err != nil {
		return api.CredentialSlot{}, err
	}
	found := false
	for _, enrolled := range current.Profiles {
		if enrolled == grant {
			found = true
			break
		}
	}
	if !found {
		return api.CredentialSlot{}, wire.Error(api.CodeForbidden, "profile selection exceeds the target's current grants")
	}
	return s.acquireProfile(ctx, target, grant, current, selection)
}

func quiescent(ctx context.Context, observation api.ProcessObservation, target api.LifeRef) error {
	if err := wire.Context(ctx); err != nil {
		return err
	}
	if observation.State != "exited" || observation.Survivors == nil || *observation.Survivors != 0 ||
		!wire.ID(string(target.LifeID)) || target.Run == 0 ||
		observation.Handle.Target != target || !wire.ID(string(observation.Handle.ID)) ||
		!wire.ID(string(observation.Handle.ContainmentID)) || observation.Handle.Generation == "" ||
		observation.ExitCode == nil && observation.Signal == nil {
		return wire.Error(api.CodeContainmentUnknown, "credential cleanup requires exact exited containment with zero survivors")
	}
	return nil
}

func (s *Service) Release(ctx context.Context, slot api.CredentialSlot, observation api.ProcessObservation) error {
	if !wire.ID(string(slot.ID)) || !wire.ID(string(slot.LeaseID)) ||
		!wire.ID(string(slot.ProfileGrantID)) || !wire.ID(string(slot.ProfileID)) {
		return wire.Error(api.CodeInvalid, "credential release requires an issued slot and lease")
	}
	if err := quiescent(ctx, observation, observation.Handle.Target); err != nil {
		return err
	}
	return s.releaseCredential(ctx, slot, observation)
}

func (s *Service) RevokeInjection(ctx context.Context, injection api.Injection, observation api.ProcessObservation) error {
	if !wire.ID(string(injection.Target.LifeID)) || injection.Target.Run == 0 || injection.SlotIDs == nil {
		return wire.Error(api.CodeInvalid, "injection cleanup requires an issued target and slot array")
	}
	if err := quiescent(ctx, observation, injection.Target); err != nil {
		return err
	}
	return s.releaseInjection(ctx, injection, observation)
}

func (s *Service) Room(ctx context.Context, grant api.ProfileGrant) (api.Room, error) {
	if err := wire.Context(ctx); err != nil {
		return api.Room{}, err
	}
	if err := validateProfile(grant, s.deps.Clock.Now()); err != nil {
		return api.Room{}, err
	}
	profile, err := s.loadProfile(ctx, grant)
	if err != nil {
		return api.Room{}, err
	}
	if profile.Usage != nil {
		return s.usageRoom(ctx, grant, profile)
	}
	return s.roomForProfile(ctx, grant, profile)
}
