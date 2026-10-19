package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// CurrentApprovedPolicy deliberately ignores historical PolicyGeneration and
// ReadView selectors. It reads the protected head under the writer's lock.
func (s *Service) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentApprovedPolicy(ctx, scope)
}

func (s *Service) currentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	var current api.EffectivePolicy
	if err := s.available(); err != nil {
		return current, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return current, err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" {
		return current, fault(api.CodeForbidden, "current approved policy requires the service coordinator")
	}
	if err := s.orgGenerationReady(ctx, s.db); err != nil {
		return current, err
	}
	if err := storedProjection(ctx, s.db, "policy", api.ID(s.deps.Config), &current); err != nil {
		return current, err
	}
	if current.Generation == 0 || current.Generation > 1<<53-1 || !wire.ValidDigest(string(current.SHA256)) {
		return api.EffectivePolicy{}, fault(api.CodeIntegrity, "current approved policy head is malformed")
	}
	return current, nil
}

// transactInternal already holds mu. Calling the exported read would try to
// acquire the same lock again, so the API receives this private locked source.
type lockedPolicySource struct{ store *Service }

func (p lockedPolicySource) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	return p.store.currentApprovedPolicy(ctx, scope)
}

func (s *Service) bindCurrentLaunchPolicy(ctx context.Context, input api.Transaction) (api.Transaction, error) {
	if input.Internal == nil || input.Internal.Kind != api.InternalHelperPrepare && input.Internal.Kind != api.InternalHelperOpen {
		return input, nil
	}
	// Worker-only transactions retain their leased-job authority and do not
	// acquire an agent launch-policy fence.
	needed := len(input.Writes.LaunchPlans) != 0 || len(input.Writes.Lanes) != 0
	for _, binding := range input.Writes.IdentityBindings {
		needed = needed || binding.Record.Kind != "worker"
	}
	for _, event := range input.Events {
		needed = needed || event.Kind == "lane.started" || event.Kind == "lane.resumed" || event.Kind == "lane.turn"
	}
	if !needed {
		return input, nil
	}
	return api.BindCurrentLaunchPolicy(ctx, lockedPolicySource{s}, input)
}
