package service

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type connectionContext struct {
	mu               sync.Mutex
	id               api.ID
	conn             net.Conn
	binding          api.InstalledBinding
	clock            api.Clock
	peer             api.VerifiedPeer
	facts            api.PeerFacts
	authority        *api.ReadAuthority
	staging          api.ID
	stagingPrincipal api.ID
	stagingFrame     api.FrameContext
	closed           bool
	cancel           context.CancelFunc
	finished         chan struct{}
}

var _ api.ConnectionContext = (*connectionContext)(nil)

func newConnection(conn net.Conn, binding api.InstalledBinding, clock api.Clock) (*connectionContext, error) {
	if conn == nil || clock == nil {
		return nil, wire.Invalid("connection requires socket and clock")
	}
	id, err := wire.NewID()
	if err != nil {
		return nil, err
	}
	return &connectionContext{id: id, conn: conn, binding: binding, clock: clock}, nil
}
func (c *connectionContext) ID() api.ID     { return c.id }
func (c *connectionContext) Conn() net.Conn { return c.conn }
func (c *connectionContext) Binding() api.InstalledBinding {
	b := c.binding
	if b.Target != nil {
		target := *b.Target
		b.Target = &target
	}
	return b
}
func (c *connectionContext) BindPeer(peer api.VerifiedPeer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.peer != nil || peer == nil {
		return serviceError(api.CodeConflict, "connection peer is already bound or closed")
	}
	facts, err := peer.Facts(context.Background())
	if err != nil {
		return err
	}
	if err := peer.Alive(context.Background()); err != nil {
		return err
	}
	if facts.HostPID <= 0 || facts.ProcessGeneration == "" {
		return serviceError(api.CodeUnauthenticated, "peer lacks a pinned process lifetime")
	}
	c.peer, c.facts = peer, facts
	return nil
}
func (c *connectionContext) Peer() api.VerifiedPeer { c.mu.Lock(); defer c.mu.Unlock(); return c.peer }

func (c *connectionContext) HumanStaging(ctx context.Context) (api.HumanStaging, error) {
	c.mu.Lock()
	bound := api.HumanStaging{Frame: c.stagingFrame, CredentialID: c.staging, PrincipalID: c.stagingPrincipal}
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return api.HumanStaging{}, serviceError(api.CodeUnauthenticated, "human staging connection is closed")
	}
	if bound.Frame == nil || !wire.ValidID(string(bound.PrincipalID)) {
		return api.HumanStaging{}, serviceError(api.CodeNotFound, "connection has no human staging selector")
	}
	if err := bound.Frame.Verify(ctx, c); err != nil {
		return api.HumanStaging{}, err
	}
	return bound, nil
}
func (c *connectionContext) BindReadAuthority(a api.ReadAuthority) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.peer == nil || c.binding.Class != api.EndpointHuman || a.Config != c.binding.Config ||
		a.EndpointGeneration != c.binding.EndpointGeneration || !wire.ValidID(string(a.SessionID)) ||
		!wire.ValidID(string(a.PrincipalID)) || !wire.ValidID(string(a.CredentialID)) || a.ConnectionID != c.id || a.Generation == 0 {
		return serviceError(api.CodeUnauthenticated, "read authority does not belong to this live human connection")
	}
	if c.authority != nil {
		return serviceError(api.CodeForbidden, "read authority binds once per connection")
	}
	now := c.clock.Now()
	idle, e1 := time.Parse(time.RFC3339Nano, string(a.IdleExpiresAt))
	absolute, e2 := time.Parse(time.RFC3339Nano, string(a.ExpiresAt))
	if e1 != nil || e2 != nil || !idle.After(now) || !absolute.After(now) || idle.After(absolute) ||
		idle.After(now.Add(5*time.Minute)) || absolute.After(now.Add(30*time.Minute)) {
		return serviceError(api.CodeUnauthenticated, "read authority expiry is invalid")
	}
	copy := a
	c.authority = &copy
	return nil
}
func (c *connectionContext) ReadAuthority(ctx context.Context) (api.ReadAuthority, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.peer == nil || c.authority == nil {
		return api.ReadAuthority{}, serviceError(api.CodeUnauthenticated, "connection has no current read authority (read by "+readAuthorityCallers()+")")
	}
	if err := c.peer.Alive(ctx); err != nil {
		return api.ReadAuthority{}, err
	}
	facts, err := c.peer.Facts(ctx)
	if err != nil {
		return api.ReadAuthority{}, err
	}
	if facts != c.facts {
		return api.ReadAuthority{}, serviceError(api.CodeUnauthenticated, "pinned peer lifetime changed")
	}
	a := *c.authority
	idle, e1 := time.Parse(time.RFC3339Nano, string(a.IdleExpiresAt))
	absolute, e2 := time.Parse(time.RFC3339Nano, string(a.ExpiresAt))
	if e1 != nil || e2 != nil || !idle.After(c.clock.Now()) || !absolute.After(c.clock.Now()) {
		c.authority = nil
		return api.ReadAuthority{}, serviceError(api.CodeUnauthenticated, "connection read authority expired")
	}
	return a, nil
}

func (c *connectionContext) RefreshReadAuthority(ctx context.Context, update api.ReadAuthorityUpdate) (resultErr error) {
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, c.Close())
		}
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.peer == nil || c.authority == nil {
		return serviceError(api.CodeUnauthenticated, "read authority refresh requires its live connection")
	}
	if err := c.peer.Alive(ctx); err != nil {
		return err
	}
	facts, err := c.peer.Facts(ctx)
	if err != nil {
		return err
	}
	if facts != c.facts {
		return serviceError(api.CodeUnauthenticated, "read authority peer lifetime changed")
	}
	if err := api.ValidateReadAuthorityUpdate(*c.authority, update); err != nil {
		return err
	}
	deadline, err := time.Parse(time.RFC3339Nano, string(update.After.IdleExpiresAt))
	if err != nil || !deadline.After(c.clock.Now()) || deadline.After(c.clock.Now().Add(5*time.Minute)) {
		return serviceError(api.CodeForbidden, "read authority refresh has an uncommitted idle deadline")
	}
	after := update.After
	c.authority = &after
	return nil
}
func (c *connectionContext) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.authority = nil
	c.staging = ""
	c.stagingPrincipal = ""
	c.stagingFrame = nil
	peer := c.peer
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	err := c.conn.Close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	if peer != nil {
		err = errors.Join(err, peer.Close())
	}
	return err
}

// readAuthorityCallers names the three callers above ReadAuthority, so the refusal says which read
// asked for a session the connection never bound (item 1 diagnosis, box 77: lane.check).
func readAuthorityCallers() string {
	var names []string
	for skip := 2; skip <= 4; skip++ {
		_, file, line, ok := runtime.Caller(skip)
		if !ok {
			break
		}
		names = append(names, filepath.Base(filepath.Dir(file))+"/"+filepath.Base(file)+":"+strconv.Itoa(line))
	}
	return strings.Join(names, " < ")
}
