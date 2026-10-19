package store

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

// Relation is the private D7 routing projection. It contains no task, session,
// workspace, prompt or capture, and never widens Lane's public raw-history ACL.
func (s *Service) Relation(ctx context.Context, scope api.Scope, id api.ID) (api.RelationFacts, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.RelationFacts{}, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return api.RelationFacts{}, err
	}
	db, err := s.reader(scope)
	if err != nil {
		return api.RelationFacts{}, err
	}
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", id, &lane); err != nil {
		return api.RelationFacts{}, err
	}
	if scope.Actor.Kind == "lane" {
		var from api.Lane
		if err := storedProjection(ctx, db, "lane", scope.Actor.LifeID, &from); err != nil {
			return api.RelationFacts{}, err
		}
		if !laneControls(from, lane) && !laneControls(lane, from) && !mailRelated(from, lane) {
			return api.RelationFacts{}, fault(api.CodeNotFound, "relation is outside the authentic starter topology")
		}
	} else if scope.Actor.Kind != "human" && !internalScope(scope) {
		return api.RelationFacts{}, fault(api.CodeForbidden, "relation requires the authenticated messaging service")
	}
	return api.RelationFacts{LifeID: lane.LifeID, ParentLifeID: lane.ParentLifeID, RootLifeID: lane.RootLifeID,
		StarterChain: append([]api.ID{}, lane.StarterChain...), Level: lane.Level, Role: lane.Role, State: lane.State,
		Generation: lane.Generation, GrantSetID: lane.GrantSetID, PolicyGeneration: lane.PolicyGeneration, Revoked: lane.Cleaned}, nil
}
