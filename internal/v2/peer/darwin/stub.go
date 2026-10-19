// Package darwin verifies native socket peers; owned by lb-v2-darwin.
package darwin

import (
	"context"
	"net"

	"laneboss.io/laneboss/internal/v2/api"
)

type Verifier struct{ registry api.ContainmentRegistry }

var _ api.PeerVerifier = (*Verifier)(nil)

func New(registry api.ContainmentRegistry) (*Verifier, error) {
	// TODO(lb-v2-darwin): require native lifetime-bound peer support.
	return nil, api.NotImplemented("lb-v2-darwin", "peer.darwin.New")
}

func (v *Verifier) Verify(ctx context.Context, connection net.Conn, binding api.InstalledBinding) (api.VerifiedPeer, error) {
	// TODO(lb-v2-darwin): reject descriptor passing, UID drift and PID reuse.
	return nil, api.NotImplemented("lb-v2-darwin", "peer.darwin.Verify")
}
