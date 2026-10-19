package secrets

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func (s *Service) acquisitionRoom(ctx context.Context, launch credentialLaunch, grant api.ProfileGrant, profile bstate.Profile) (api.Room, error) {
	if launch.continuation == nil || profile.Usage == nil {
		return s.roomForProfile(ctx, grant, profile)
	}
	if launch.room == nil || launch.room.ProfileID != grant.ProfileID || !launch.room.Available || !future(launch.room.ExpiresAt, s.deps.Clock.Now()) {
		return api.Room{}, wire.Error(api.CodeUnavailable, "credential acquisition lost its freshly measured continuation room")
	}
	return *launch.room, nil
}

// Authenticate a committed room as historical input, without treating that
// receipt as a current provider decision. Availability is remeasured below.
func (s *Service) committedRoom(ctx context.Context, ref api.BlobRef, target api.LifeRef, grant api.ProfileGrant) (api.Room, error) {
	var saved retainedRoom
	backend, err := s.brokerBackend()
	if err != nil {
		return api.Room{}, err
	}
	if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("usage", ref.ID, &saved) }); err != nil {
		return api.Room{}, err
	}
	profile, err := s.loadProfile(ctx, grant)
	if err != nil {
		return api.Room{}, err
	}
	if saved.Schema != "laneboss.retained-room.v1" || saved.Config != s.deps.Config || saved.Grant != grant || !reflect.DeepEqual(saved.Profile, profile) ||
		saved.Room.Evidence != ref || saved.Room.ProfileID != grant.ProfileID || saved.Request.Target != target || saved.Observation.Target != target || profile.Usage == nil {
		return api.Room{}, wire.Error(api.CodeIntegrity, "committed room differs from its protected selected profile or cause")
	}
	lane, err := s.roomLane(ctx, grant)
	if err != nil {
		return api.Room{}, err
	}
	manifestMeta, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ServiceScope, ref.ID)
	if err != nil {
		return api.Room{}, err
	}
	if !reflect.DeepEqual(manifestMeta.ACL.Participants, roomParticipants(lane)) || manifestMeta.ACL.Generation != 1 {
		return api.Room{}, wire.Error(api.CodeIntegrity, "committed room changed its exact supervising participants")
	}
	request, err := s.roomRequest(ctx, lane, grant)
	if err != nil {
		return api.Room{}, err
	}
	if request != saved.Request {
		return api.Room{}, wire.Error(api.CodeConflict, "committed room causing run changed")
	}
	from, err := s.usageProfile(ctx, request)
	if err != nil {
		return api.Room{}, err
	}
	sealed, err := s.protectedObject(ctx, saved.Producer.Lease.Input, request.OperationID)
	if err != nil {
		return api.Room{}, err
	}
	var input UsageInput
	if api.DecodeObject(sealed, &input) != nil || input.Schema != "laneboss.usage-input.v1" || input.Request != request || input.ProfileGeneration != from.Generation || input.Source != from.Source || input.VendorProfile != from.Usage.VendorProfile {
		return api.Room{}, wire.Error(api.CodeConflict, "committed room from-profile enrollment changed")
	}
	value := saved.Observation
	if err := s.usageProducer(ctx, saved.Producer, value.CheckedAt, value.Raw); err != nil {
		return api.Room{}, err
	}
	data, err := s.readRoomObject(ctx, ref, saved.Producer, target.LifeID)
	if err != nil {
		return api.Room{}, err
	}
	var actual roomObservation
	if api.DecodeObject(data, &actual) != nil || !reflect.DeepEqual(value, actual) || value.Schema != "laneboss.room-observation.v1" || value.ProfileID != grant.ProfileID || value.ProfileGrantID != grant.ID || value.WorkerLeaseID != saved.Producer.Lease.ID {
		return api.Room{}, wire.Error(api.CodeIntegrity, "committed room differs from its exact normalized bytes")
	}
	at, err := time.Parse(time.RFC3339Nano, string(value.CheckedAt))
	if err != nil {
		return api.Room{}, err
	}
	raw, err := s.protectedObject(ctx, value.Raw, request.OperationID)
	if err != nil {
		return api.Room{}, err
	}
	meta, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ServiceScope, value.Raw.ID)
	if err != nil {
		return api.Room{}, err
	}
	windows, available, err := parseRoomWindows(raw, profile.Usage.VendorProfile, at)
	if err != nil {
		return api.Room{}, err
	}
	if meta.ACL.Owner != saved.Producer.Record.Actor || meta.ACL.LifeID != target.LifeID || !reflect.DeepEqual(windows, value.Windows) || available != value.Available || saved.Room.Available != available || saved.Room.CheckedAt != value.CheckedAt || saved.Room.ExpiresAt != value.ExpiresAt {
		return api.Room{}, wire.Error(api.CodeIntegrity, "committed room differs from its actual provider rows or producer")
	}
	return saved.Room, nil
}

func (s *Service) continuationRoom(ctx context.Context, intent api.ContinuationIntent, selected api.ProfileGrant) (api.ProfileEligibility, error) {
	empty := api.ProfileEligibility{}
	profile, err := s.loadProfile(ctx, selected)
	if err != nil {
		return empty, err
	}
	if profile.Usage != nil {
		// The intent's two observations may name different fresh jobs. Both must
		// authenticate the same delegated profile and exact causing run.
		prior, err := s.committedRoom(ctx, intent.Eligibility.Evidence, intent.Target, selected)
		if err != nil {
			return empty, err
		}
		chosen, err := s.committedRoom(ctx, intent.Swap.Room.Evidence, intent.Target, selected)
		if err != nil {
			return empty, err
		}
		if !prior.Available || !chosen.Available || chosen != intent.Swap.Room {
			return empty, wire.Error(api.CodeUnavailable, "credential continuation changed its committed room")
		}
	}
	fresh, err := s.Eligibility(ctx, intent.Eligibility.Request)
	if err != nil {
		return empty, err
	}
	if !fresh.Compatible || fresh.ID != intent.Eligibility.ID || fresh.Request != intent.Eligibility.Request {
		return empty, wire.Error(api.CodeForbidden, "credential continuation eligibility changed before acquisition")
	}
	if profile.Usage != nil {
		room, err := s.committedRoom(ctx, fresh.Evidence, intent.Target, selected)
		if err != nil {
			return empty, err
		}
		if !room.Available || !future(room.ExpiresAt, s.deps.Clock.Now()) {
			return empty, wire.Error(api.CodeUnavailable, "credential continuation has no fresh authenticated room")
		}
		return fresh, nil
	}
	if fresh.Evidence != intent.Eligibility.Evidence {
		return empty, wire.Error(api.CodeForbidden, "credential continuation eligibility changed before acquisition")
	}
	room, err := s.Room(ctx, selected)
	if err != nil {
		return empty, err
	}
	if !room.Available || !reflect.DeepEqual(room, intent.Swap.Room) {
		return empty, wire.Error(api.CodeUnavailable, "credential continuation has no unchanged authenticated room")
	}
	return fresh, nil
}
