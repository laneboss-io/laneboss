package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

var _ api.HumanPolicySource = (*Service)(nil)

// HumanPolicyGeneration is not an RPC or a content read. Identity uses it only
// after native peer binding and unique enrollment resolution, before a read
// session can exist. Public Policy and object reads retain readScope unchanged.
func (s *Service) HumanPolicyGeneration(ctx context.Context, connection api.ConnectionContext, principal api.ID) (api.Generation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return 0, err
	}
	if connection == nil || connection.Peer() == nil || !wire.ValidID(string(principal)) {
		return 0, fault(api.CodeUnauthenticated, "human policy generation requires its verified native connection")
	}
	binding := connection.Binding()
	if err := api.ValidateBinding(binding, s.deps.Config, binding.ServiceVersion); err != nil {
		return 0, err
	}
	if binding.Class != api.EndpointHuman {
		return 0, fault(api.CodeForbidden, "human policy generation requires the installed human endpoint")
	}
	scope := api.Scope{Config: s.deps.Config, Connection: connection,
		Actor: api.Actor{Kind: "human", ID: principal}, EndpointGeneration: binding.EndpointGeneration}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return 0, err
	}
	var enrollment api.HumanEnrollment
	if err := storedProjection(ctx, s.db, "enrollment", principal, &enrollment); err != nil {
		return 0, err
	}
	if enrollment.Config != s.deps.Config || enrollment.PrincipalID != principal || enrollment.Generation == 0 {
		return 0, fault(api.CodeUnauthenticated, "human policy generation differs from the retained enrollment")
	}
	if err := api.ValidateHumanEnrollments(s.deps.Config, []api.HumanEnrollment{enrollment}); err != nil {
		return 0, err
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, s.db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return 0, err
	}
	if policy.Generation == 0 || policy.Generation > 1<<53-1 || !wire.ValidDigest(string(policy.SHA256)) {
		return 0, fault(api.CodeIntegrity, "protected current human policy is malformed")
	}
	if err := connection.Peer().Alive(ctx); err != nil {
		return 0, err
	}
	return policy.Generation, nil
}
