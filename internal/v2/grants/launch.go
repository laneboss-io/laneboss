package grants

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Resolve is read-only. The planner commits these reserved IDs under its
// current launch-plan effect/CAS; neither a public preview nor this return
// value grants permission to release a worker or agent.
func (s *Service) Resolve(ctx context.Context, scope api.Scope, request api.GrantResolveRequest) (api.GrantSet, error) {
	ctx = verificationContext(ctx)
	first, err := s.resolveReserved(ctx, scope, request.ReservationID)
	if err != nil {
		return api.GrantSet{}, err
	}
	// Reopen all authority after source reads, including the reservation and
	// retained original frame. Never reuse the caller's initial read snapshot.
	current, err := s.resolveReserved(ctx, scope, request.ReservationID)
	if err != nil {
		return api.GrantSet{}, err
	}
	if !reflect.DeepEqual(first, current) {
		return api.GrantSet{}, conflict("reserved launch grants changed during source verification")
	}
	return current, nil
}

type launchSelection struct {
	level     int
	role      string
	profile   api.ID
	requested api.GrantRequest
	budget    api.Budget
	ticket    api.ID
}

func newLaunchSelection(state *lstate.State) (launchSelection, error) {
	r := state.Record.Reservation
	selection := launchSelection{level: r.Level, role: r.Role, ticket: r.Authority.ID}
	if r.Authority.Kind != "ticket" {
		selection.ticket = ""
	}
	switch r.Mode {
	case "start":
		var request api.StartRequest
		if state.Request.Method != "lane.start" {
			return selection, integrity("start reservation retained a different request method")
		}
		if err := api.DecodeObject(state.Request.Params, &request); err != nil {
			return selection, err
		}
		if request.Level != r.Level || request.Role != r.Role || request.Driver != r.Driver || request.RootTicketID != selection.ticket {
			return selection, refused("start request differs from stored reservation pins or authority")
		}
		selection.requested, selection.budget, selection.profile = request.Grants, request.Budget, request.ProfileGrantID
		if request.ExpectedPolicyGeneration != r.PolicyGeneration {
			return selection, conflict("reserved request differs from its target policy generation")
		}
	case "adopt":
		var request api.AdoptRequest
		if state.Request.Method != "lane.adopt" {
			return selection, integrity("adopt reservation retained a different request method")
		}
		if err := api.DecodeObject(state.Request.Params, &request); err != nil {
			return selection, err
		}
		if request.Level != r.Level || request.Role != r.Role || request.Driver != r.Driver || request.RootTicketID != selection.ticket {
			return selection, refused("adopt request differs from stored reservation pins or authority")
		}
		selection.requested, selection.budget, selection.profile = request.Grants, request.Budget, request.ProfileGrantID
		if request.ExpectedPolicyGeneration != r.PolicyGeneration {
			return selection, conflict("reserved request differs from its target policy generation")
		}
	default:
		return selection, manifest.Invalid("new launch resolution needs start or adopt")
	}
	if selection.level < 3 || selection.level > 6 || !manifest.ValidID(api.ID(selection.role)) {
		return selection, manifest.Invalid("reserved launch needs an L3-L6 level and named role")
	}
	if err := manifest.Budget(selection.budget); err != nil {
		return selection, err
	}
	return selection, manifest.Request(selection.requested)
}

func (s *Service) resolveReserved(ctx context.Context, scope api.Scope, id api.ID) (result api.GrantSet, resultErr error) {
	state, err := lstate.Load(ctx, s.deps.Store, s.deps.Config, scope, id)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, state.Close()) }()
	return s.resolveLaunchState(ctx, state)
}

// Both full-set and profile resolution use the same retained frame and
// authority checks. The caller owns the loaded read view until this returns.
func (s *Service) resolveLaunchState(ctx context.Context, state *lstate.State) (result api.GrantSet, resultErr error) {
	r := state.Record.Reservation
	if r.Mode != "start" && r.Mode != "adopt" {
		return s.resolveRetained(ctx, state)
	}
	selection, err := newLaunchSelection(state)
	if err != nil {
		return result, err
	}
	if _, err := s.launchPolicy(ctx, state.Scope, r); err != nil {
		return result, err
	}
	var ceiling api.GrantSet
	bound := within
	if r.RequestedBy.Kind == "lane" {
		if selection.ticket != "" || r.ParentLifeID != r.RequestedBy.LifeID {
			return result, refused("lane reservation cannot select a root ticket or another starter")
		}
		parent, err := s.deps.Store.Lane(ctx, state.Scope, api.LifeRef{LifeID: r.ParentLifeID})
		if err != nil {
			return result, err
		}
		if parent.Cleaned || parent.LifeID != r.ParentLifeID || parent.Level <= selection.level ||
			parent.Level != r.RequestedBy.Level || parent.Role != r.RequestedBy.Role ||
			parent.RootLifeID != r.RootLifeID ||
			!slices.Equal(r.StarterChain, append(append([]api.ID{}, parent.StarterChain...), parent.LifeID)) {
			return result, refused("reserved child differs from its authentic strict-lower starter")
		}
		if err := delegationState(parent.State); err != nil {
			return result, err
		}
		// StarterEventSeq points at the parent's own created/adopted event,
		// not the sequence of the parent's starter edge.
		if err := s.parentCreation(ctx, state.Scope, r, parent); err != nil {
			return result, err
		}
		starter, err := s.deps.Store.Launch(ctx, r.Authority.ID)
		if err != nil {
			return result, err
		}
		if starter.ID != r.Authority.ID || starter.ID != parent.LaunchID || starter.Kind != "agent" || starter.Revoked ||
			starter.Config != r.Config || starter.Actor != r.RequestedBy || starter.Target != (api.LifeRef{LifeID: parent.LifeID, Run: parent.Run}) ||
			starter.GrantSetID != parent.GrantSetID || starter.PolicyGeneration != r.PolicyGeneration {
			return result, refused("reserved starter authority differs from its current authentic launch")
		}
		ceiling, err = s.deps.Store.Grants(ctx, parent.GrantSetID)
		if err != nil {
			return result, err
		}
		if ceiling.ID != parent.GrantSetID || ceiling.LifeID != parent.LifeID {
			return result, integrity("reserved starter grants belong to another life")
		}
		ceiling, err = s.revalidateScope(ctx, state.Scope, ceiling, func(ctx context.Context, grants api.GrantSet) (api.GrantSet, error) {
			return s.currentAfterScope(ctx, state.Scope, grants)
		})
		if err != nil {
			return result, err
		}
	} else if r.RequestedBy.Kind == "human" {
		if r.ParentLifeID != "" || !manifest.ValidID(selection.ticket) {
			return result, refused("human root reservation requires its retained root ticket")
		}
		ticket, err := s.launchTicket(ctx, state.Scope, r)
		if err != nil {
			return result, err
		}
		if ticket.ID != selection.ticket || ticket.PrincipalID != r.RequestedBy.ID || ticket.Config != r.Config ||
			ticket.EndpointGeneration == 0 || ticket.Level != selection.level || ticket.Role != selection.role || !ticket.Redeemed {
			return result, refused("root ticket differs from the reserved principal, role or consumed authority")
		}
		// The protected ticket reader proves this operation's exact consumed
		// reservation. Recheck its admission expiry against the original
		// service-retained input, never against a later claimant's retry time.
		metadata, err := s.deps.Store.ObjectMetadata(ctx, state.Scope, r.OriginalRequest.ID)
		if err != nil {
			return result, err
		}
		reservedAt, err := manifest.Time(metadata.CommittedAt)
		if err != nil || reservedAt.IsZero() || reservedAt.After(s.deps.Clock.Now()) {
			return result, refused("root ticket reservation has no valid service admission time")
		}
		if _, err := manifest.Expiry(ticket.ExpiresAt, reservedAt); err != nil {
			return result, err
		}
		ceiling, err = s.deps.Store.Grants(ctx, ticket.GrantSetID)
		if err != nil {
			return result, err
		}
		if ceiling.ID != ticket.GrantSetID || ceiling.ParentLifeID != "" || ceiling.PolicyGeneration != r.PolicyGeneration {
			return result, refused("root ticket does not select the current root grant template")
		}
		if err := checkedSeal(ceiling, s.deps.Clock.Now()); err != nil {
			return result, err
		}
		bound = rootUseWithin
	} else {
		return result, refused("new launch reservation has no authenticated starter")
	}
	result, err = deriveWith(ceiling, selection.requested, s.deps.Clock.Now(), reservedIssuer(r), bound)
	if err != nil {
		return api.GrantSet{}, err
	}
	if r.ParentLifeID == "" {
		clearRootParents(&result)
	}
	result.ParentLifeID, result.PolicyGeneration = r.ParentLifeID, r.PolicyGeneration
	if err := seal(&result); err != nil {
		return api.GrantSet{}, err
	}
	if err := checkedSeal(result, s.deps.Clock.Now()); err != nil {
		return api.GrantSet{}, err
	}
	if err := s.checkSources(ctx, state.Scope, result, selection.budget.DiskBytes); err != nil {
		return api.GrantSet{}, err
	}
	stored, err := s.deps.Store.Grants(ctx, r.GrantSetID)
	if err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound || state.Record.Phase != "reserved" {
			return api.GrantSet{}, err
		}
	} else {
		if err := checkedSeal(stored, s.deps.Clock.Now()); err != nil {
			return api.GrantSet{}, err
		}
		if !reflect.DeepEqual(stored, result) {
			return api.GrantSet{}, conflict("issued reserved grant set differs from the original launch selection")
		}
	}
	if state.Record.Inputs != nil && !reflect.DeepEqual(state.Record.Inputs.Grants, result) {
		return api.GrantSet{}, conflict("sourced launch grants differ from current reserved authority")
	}
	return result, nil
}

func checkedSeal(grants api.GrantSet, now time.Time) error {
	if err := manifest.Set(grants, now); err != nil {
		return err
	}
	sealed := grants
	if err := seal(&sealed); err != nil || sealed.SHA256 != grants.SHA256 {
		return integrity("reserved launch grant digest differs from its exact contents")
	}
	return nil
}

func reservedIssuer(reservation api.LaunchReservation) func() (api.ID, error) {
	sequence := 0
	return func() (api.ID, error) {
		sequence++
		if sequence == 1 {
			return reservation.GrantSetID, nil
		}
		if sequence == 2 {
			return reservation.Target.LifeID, nil
		}
		// Member IDs are deterministic service derivations of the immutable
		// reservation and input digest, so a retry before commit is identical.
		digest := manifest.Hash([]byte("laneboss.launch-grant.v2\x00" + string(reservation.ID) + "\x00" +
			string(reservation.RequestSHA256) + "\x00" + strconv.Itoa(sequence)))
		return api.ID("g_" + string(digest[:32])), nil
	}
}

func rootUseWithin(expiry, parent, set api.Timestamp, delegate, parentDelegate bool, now time.Time) error {
	// A consumed root ticket authorizes direct use of its named template.
	// It cannot add redelegation that the approved template withheld.
	if delegate && !parentDelegate {
		return refused("root selection widens the ticket's redelegation ceiling")
	}
	return within(expiry, parent, set, delegate, true, now)
}

func clearRootParents(set *api.GrantSet) {
	for i := range set.Data {
		set.Data[i].ParentGrantID = ""
	}
	for i := range set.Secrets {
		set.Secrets[i].ParentGrantID = ""
	}
	for i := range set.Profiles {
		set.Profiles[i].ParentGrantID = ""
	}
	for i := range set.Network {
		set.Network[i].ParentGrantID = ""
	}
	for i := range set.Channels {
		set.Channels[i].ParentGrantID = ""
	}
	for i := range set.Resources {
		set.Resources[i].ParentGrantID = ""
	}
}
