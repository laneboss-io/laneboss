package grants

import (
	"context"
	"errors"
	"reflect"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// ReservedProfileResolver is a service-only optional capability alongside the
// frozen GrantResolver. Only a protected reservation selects the original
// profile; no caller-provided parent/member/profile name is accepted.
type ReservedProfileResolver interface {
	ResolveProfile(context.Context, api.Scope, api.GrantResolveRequest) (api.ProfileGrant, error)
}

var _ ReservedProfileResolver = (*Service)(nil)

type profileResolution struct {
	Reservation api.LaunchReservation
	Grants      api.GrantSet
	Profile     api.ProfileGrant
}

// ResolveProfile maps a start/adopt's approved parent member to the exact
// reservation-issued member. A root member has no ParentGrantID after issuance,
// so its original retained request, not a label or child-field guess, is used.
// This read neither acquires credentials nor commits/releases a launch.
func (s *Service) ResolveProfile(ctx context.Context, scope api.Scope, request api.GrantResolveRequest) (api.ProfileGrant, error) {
	ctx = verificationContext(ctx)
	first, err := s.resolveProfile(ctx, scope, request.ReservationID)
	if err != nil {
		return api.ProfileGrant{}, err
	}
	current, err := s.resolveProfile(ctx, scope, request.ReservationID)
	if err != nil {
		return api.ProfileGrant{}, err
	}
	if !reflect.DeepEqual(first, current) {
		return api.ProfileGrant{}, conflict("reserved profile authority changed during source reads")
	}
	return current.Profile, nil
}

func (s *Service) resolveProfile(ctx context.Context, scope api.Scope, id api.ID) (result profileResolution, resultErr error) {
	state, err := lstate.Load(ctx, s.deps.Store, s.deps.Config, scope, id)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, state.Close()) }()
	r := state.Record.Reservation
	if r.Mode != "start" && r.Mode != "adopt" {
		return result, manifest.Invalid("profile remapping requires a new start or adoption reservation")
	}
	selection, err := newLaunchSelection(state)
	if err != nil {
		return result, err
	}
	set, err := s.resolveLaunchState(ctx, state)
	if err != nil {
		return result, err
	}
	profile, err := api.IssuedLaunchProfile(r, state.Request, set)
	if err != nil {
		return result, err
	}
	if profile.Paid && selection.budget.SpendMicros <= 0 {
		return result, refused("selected paid profile has no retained spend authority")
	}
	policy, err := s.launchPolicy(ctx, state.Scope, r)
	if err != nil {
		return result, err
	}
	if policy.Generation == 0 || policy.Generation != r.PolicyGeneration {
		return result, conflict("selected profile policy generation changed")
	}
	if slices.Contains(policy.ProfileExclusions, profile.ProfileID) {
		return result, refused("selected launch profile is excluded by current policy")
	}
	return profileResolution{Reservation: r, Grants: set, Profile: profile}, nil
}
