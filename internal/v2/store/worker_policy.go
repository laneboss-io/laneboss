package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) WorkerPolicyGeneration(ctx context.Context, connection api.ConnectionContext, actor api.ID) (api.Generation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return 0, err
	}
	if connection == nil || connection.Peer() == nil || connection.Binding().Class != api.EndpointWorker || connection.Binding().Config != s.deps.Config {
		return 0, fault(api.CodeUnauthenticated, "worker policy requires its native installed connection")
	}
	if err := connection.Peer().Alive(ctx); err != nil {
		return 0, err
	}
	facts, err := connection.Peer().Facts(ctx)
	if err != nil {
		return 0, err
	}
	principal, err := s.dataPrincipal(ctx, s.db, connection.Binding(), facts, api.WorkerInputRead)
	if err != nil {
		return 0, err
	}
	if actor != principal.Record.Actor.ID {
		return 0, fault(api.CodeForbidden, "worker policy names another authenticated principal")
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, s.db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return 0, err
	}
	if policy.Generation == 0 || policy.Generation < principal.Record.PolicyGeneration {
		return 0, fault(api.CodeUnauthenticated, "worker policy is absent or predates its native job")
	}
	return policy.Generation, nil
}
