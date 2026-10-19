package api

import (
	"context"
	"net"
)

// PeerFacts are host-kernel observations, never request fields.
type PeerFacts struct {
	HostUID           uint32
	HostGID           uint32
	HostPID           int
	ProcessGeneration string
	ContainmentID     ID
}

type VerifiedPeer interface {
	Facts(context.Context) (PeerFacts, error)
	Alive(context.Context) error
	Close() error
}

type PeerVerifier interface {
	// Resolve kernel facts and registered containment using the transport's
	// protected endpoint binding, before identity looks up launch authority.
	Verify(context.Context, net.Conn, InstalledBinding) (VerifiedPeer, error)
}
