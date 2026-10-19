package wire

import (
	"context"
	"io"
	"net"

	"laneboss.io/laneboss/internal/v2/api"
)

// SocketPeer is transport evidence from the kernel, never request metadata.
type SocketPeer struct {
	UID, GID uint32
	PID      int
}

func ReadPeerBytes(connection *net.UnixConn, expected SocketPeer, data []byte) (int, error) {
	reader := credentialReader{connection: connection, expected: expected}
	return reader.Read(data)
}

type receivedFrame struct {
	data       []byte
	connection net.Conn
	writer     SocketPeer
}

func (f *receivedFrame) Bytes() []byte { return append([]byte(nil), f.data...) }
func (f *receivedFrame) Verify(ctx context.Context, c api.ConnectionContext) error {
	if c == nil || c.Conn() != f.connection || c.Peer() == nil {
		return Invalid("frame lacks its authenticated connection")
	}
	peer := c.Peer()
	if err := peer.Alive(ctx); err != nil {
		return err
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return err
	}
	if facts.HostUID != f.writer.UID || facts.HostGID != f.writer.GID || facts.HostPID != f.writer.PID || facts.ProcessGeneration == "" {
		return &api.Error{Code: api.CodeUnauthenticated, Message: "frame writer differs from pinned connector", Instead: "Open a new authenticated connection from the current process."}
	}
	return nil
}

// ReadPinnedFrame uses a credential-aware reader for every header/payload byte.
// EnableCredentials must be called on the listener before any client connects.
func ReadPinnedFrame(connection *net.UnixConn, expected SocketPeer) (api.FrameContext, error) {
	r := credentialReader{connection: connection, expected: expected}
	data, err := ReadFrame(io.Reader(&r))
	if err != nil {
		return nil, err
	}
	return &receivedFrame{data: data, connection: connection, writer: expected}, nil
}
