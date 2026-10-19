package grants

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) grantPolicy(ctx context.Context, scope api.Scope, request api.GrantPolicyRequest) (api.EffectivePolicy, error) {
	reader, ok := s.deps.Store.(api.GrantPolicyReader)
	if !ok || nilInterface(reader) {
		return api.EffectivePolicy{}, api.NotImplemented("lb-v2-service", "protected grant policy selection")
	}
	return reader.GrantPolicy(ctx, scope, request)
}

func (s *Service) launchPolicy(ctx context.Context, scope api.Scope, reservation api.LaunchReservation) (api.EffectivePolicy, error) {
	return s.grantPolicy(ctx, scope, api.GrantPolicyRequest{ReservationID: reservation.ID,
		Target: reservation.Target, GrantSetID: reservation.GrantSetID,
		Context: api.RoleContext{Level: reservation.Level, Role: reservation.Role}, PolicyGeneration: reservation.PolicyGeneration})
}

func (s *Service) launchTicket(ctx context.Context, scope api.Scope, reservation api.LaunchReservation) (api.Ticket, error) {
	reader, ok := s.deps.Store.(api.LaunchTicketReader)
	if !ok || nilInterface(reader) {
		return api.Ticket{}, api.NotImplemented("lb-v2-service", "protected launch ticket selection")
	}
	return reader.LaunchTicket(ctx, scope, api.LaunchTicketRequest{ReservationID: reservation.ID})
}

func (s *Service) lanePolicy(ctx context.Context, scope api.Scope, lane api.Lane) (api.EffectivePolicy, error) {
	return s.grantPolicy(ctx, scope, api.GrantPolicyRequest{Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run},
		GrantSetID: lane.GrantSetID, Context: api.RoleContext{Level: lane.Level, Role: lane.Role}, PolicyGeneration: lane.PolicyGeneration})
}
