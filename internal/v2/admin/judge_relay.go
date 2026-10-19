package admin

import (
	"net"
	"os"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
)

// This one-connection relay transports bytes for the protected provider URL.
// It interprets no HTTP, model request, response or credential and authorizes
// no second exchange. The fixed judge adapter remains in its native worker.
type judgeRelay struct {
	listener *net.UnixListener
	path     string
	done     chan struct{}
	mu       sync.Mutex
	peer     net.Conn
	provider net.Conn
	err      error
}

func (r *judgeRelay) close() error {
	r.listener.Close()
	r.mu.Lock()
	if r.peer != nil {
		r.peer.Close()
	}
	if r.provider != nil {
		r.provider.Close()
	}
	r.mu.Unlock()
	<-r.done
	if err := os.Remove(r.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return r.err
}

func (m *leaseManager) closeJudgeRelay(id api.ID) error {
	r := m.judgeRelays[id]
	if r == nil {
		return nil
	}
	err := r.close()
	delete(m.judgeRelays, id)
	return err
}
