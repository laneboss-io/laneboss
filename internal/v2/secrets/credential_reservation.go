package secrets

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// ReserveCredentials retains only native metadata before the helper's
// independent identity check. No descriptor or opening permit is exported.
func (s *Service) ReserveCredentials(ctx context.Context, peer api.VerifiedPeer, request api.CredentialProjectionRequest) (api.CredentialProjectionRecord, error) {
	if wire.Nil(peer) {
		return api.CredentialProjectionRecord{}, wire.Error(api.CodeUnauthenticated, "credential reservation requires its native helper peer")
	}
	if err := peer.Alive(ctx); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if facts.HostUID != 0 || facts.HostPID <= 1 || request.Handoff.Config != s.deps.Config {
		return api.CredentialProjectionRecord{}, wire.Error(api.CodeForbidden, "credential reservation requires its installed root helper")
	}
	return s.deps.Store.ReserveCredentialProjection(ctx, s.deps.ServiceScope, request)
}
