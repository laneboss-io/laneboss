package admin

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

type CredentialPeerVerification struct {
	Role string
	Peer api.PeerFacts
}

// VerifyCredentialNativePeer is metadata-only. The authenticated helper
// measures the actual retained native owner, never a caller's process label.
func (s *Service) VerifyCredentialNativePeer(ctx context.Context, role string, peer api.PeerFacts) error {
	var result api.Empty
	return s.call(ctx, "credential_peer_verify", CredentialPeerVerification{role, peer}, &result)
}
