//go:build linux

package admin

import (
	"context"
	"errors"
	"net"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// This fixed administrator channel cannot acquire human read authority or
// replace its original peer. The listener owns its socket and reply lifetime.
type enrollmentConnection struct {
	id      api.ID
	socket  *net.UnixConn
	binding api.InstalledBinding
	peer    api.VerifiedPeer
}

var _ api.ConnectionContext = (*enrollmentConnection)(nil)

func newEnrollmentConnection(ctx context.Context, socket *net.UnixConn, human api.InstalledBinding, endpoint api.AdminEnrollmentEndpoint) (*enrollmentConnection, error) {
	peer, err := wire.NewAdministratorPeer(ctx, socket)
	if err != nil {
		return nil, err
	}
	id, err := wire.NewID()
	if err != nil {
		return nil, errors.Join(err, peer.Close())
	}
	human.Socket = endpoint.Socket
	return &enrollmentConnection{id: id, socket: socket, binding: human, peer: peer}, nil
}

func (c *enrollmentConnection) ID() api.ID                    { return c.id }
func (c *enrollmentConnection) Conn() net.Conn                { return c.socket }
func (c *enrollmentConnection) Binding() api.InstalledBinding { return c.binding }
func (c *enrollmentConnection) Peer() api.VerifiedPeer        { return c.peer }
func (c *enrollmentConnection) BindPeer(api.VerifiedPeer) error {
	return failure(api.CodeConflict, "administrator connection already has its pinned peer")
}
func (c *enrollmentConnection) BindReadAuthority(api.ReadAuthority) error {
	return failure(api.CodeForbidden, "administrator channel cannot bind human read authority")
}
func (c *enrollmentConnection) ReadAuthority(context.Context) (api.ReadAuthority, error) {
	return api.ReadAuthority{}, failure(api.CodeForbidden, "administrator channel has no human read authority")
}
func (c *enrollmentConnection) Close() error {
	return errors.Join(c.peer.Close(), c.socket.Close())
}
func (c *enrollmentConnection) verify(ctx context.Context, endpoint api.AdminEnrollmentEndpoint, frame api.FrameContext) error {
	return wire.VerifyAdministrator(ctx, endpoint, c, frame)
}
