package lifecycle

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// Check the current store projection independently at each authority boundary.
// An old authentic run is not a starter for a new child after its replacement.
func (s *Service) currentStarter(ctx context.Context, scope api.Scope, launchID api.ID,
	actor api.Actor, endpoint api.Generation) (api.Lane, error) {
	if actor.Kind != "lane" || !validID(launchID) {
		return api.Lane{}, problem(api.CodeForbidden, "child launch has no authentic starter", "Use the current recorded agent binding.")
	}
	starter, err := s.deps.Store.Launch(ctx, launchID)
	if err != nil {
		return api.Lane{}, failure(err)
	}
	if starter.Kind != "agent" || starter.Actor != actor || starter.Config != scope.Config ||
		starter.ID != launchID || starter.Target.LifeID != actor.LifeID || starter.Revoked ||
		!validTarget(starter.Target) || !validGeneration(starter.EndpointGeneration) ||
		endpoint != 0 && starter.EndpointGeneration != endpoint {
		return api.Lane{}, problem(api.CodeForbidden, "starter binding is stale", "Reauthenticate through the current confined starter endpoint.")
	}
	parent, err := s.deps.Store.Lane(ctx, scope, starter.Target)
	if err != nil {
		return api.Lane{}, failure(err)
	}
	if parent.LifeID != actor.LifeID || parent.Level != actor.Level || parent.Role != actor.Role ||
		parent.Run != starter.Target.Run || parent.LaunchID != starter.ID || parent.Cleaned ||
		starter.ParentLifeID != parent.ParentLifeID || starter.RootLifeID != parent.RootLifeID ||
		starter.StarterEventSeq != parent.StarterEventSeq || !reflect.DeepEqual(starter.StarterChain, parent.StarterChain) ||
		!validID(parent.RootLifeID) || !validAncestry(parent) {
		return api.Lane{}, problem(api.CodeForbidden, "starter role or run does not match service state", "Use the authentic current starter and retained grants.")
	}
	return parent, nil
}

func childReservation(parent api.Lane, r api.LaunchReservation) bool {
	return r.Level < parent.Level && r.ParentLifeID == parent.LifeID && r.RootLifeID == parent.RootLifeID &&
		reflect.DeepEqual(r.StarterChain, append(append([]api.ID{}, parent.StarterChain...), parent.LifeID))
}

func (execution *planExecution) starter(ctx context.Context) error {
	r := execution.record.Reservation
	if r.Target.Run != 1 || r.Authority.Kind != "starter" {
		return nil
	}
	parent, err := execution.service.currentStarter(ctx, execution.scope, r.Authority.ID, r.RequestedBy, 0)
	if err != nil {
		return err
	}
	if !childReservation(parent, r) {
		return integrity("child reservation exceeds its current starter level or ancestry")
	}
	return nil
}
