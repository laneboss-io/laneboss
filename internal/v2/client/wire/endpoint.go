package wire

import (
	"context"
	"net"
	"os"
	"sync"
)

// Endpoint owns the duplicate of a projected socket inode for the client's
// entire lifetime. Dial and Close serialize so a closed/reused descriptor can
// never redirect a connection. Ordinary protected host bindings use their path.
type Endpoint struct {
	mu     sync.Mutex
	file   *os.File
	path   string
	check  func() error
	closed bool
}

// A service outside a lane's private PID namespace has no visible PID there.
// Only an owned projected socket pin enables that server-side credential form;
// service-side connector verification still requires a visible native PID.
func (e *Endpoint) PeerCredentials(connection *net.UnixConn) (SocketPeer, error) {
	return serverCredentials(connection, e.file != nil)
}

func (e *Endpoint) DialContext(ctx context.Context, dialer *net.Dialer) (net.Conn, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, net.ErrClosed
	}
	if e.check != nil {
		if err := e.check(); err != nil {
			return nil, err
		}
	}
	return dialer.DialContext(ctx, "unix", e.path)
}

func (e *Endpoint) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	if e.file != nil {
		return e.file.Close()
	}
	return nil
}
