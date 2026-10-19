//go:build !linux

package linux

import (
	"context"
	"net"

	"laneboss.io/laneboss/internal/v2/api"
)

type Verifier struct{}

func New(api.ContainmentRegistry) (*Verifier, error) {
	return nil, peerError(api.CodeUnsupported, "Linux peer verification requires Linux")
}

func (*Verifier) Verify(context.Context, net.Conn, api.InstalledBinding) (api.VerifiedPeer, error) {
	return nil, peerError(api.CodeUnsupported, "Linux peer verification requires Linux")
}

func (*Verifier) Close() error { return nil }
