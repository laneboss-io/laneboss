package identityd

import (
	"fmt"
	"net"
)

type process struct {
	Peer
	Parent int
}

type peerLifetime interface {
	check() error
	mutationAllowed() error
	close() error
	mode() string
}

type socketIdentity struct {
	Peer
	lifetime peerLifetime
}

func (p *socketIdentity) check() error {
	if unpinnedPeer() {
		return nil
	}
	return p.lifetime.check()
}

// socketPeer reads credentials before reading any bytes supplied by the caller.
func socketPeer(conn *net.UnixConn) (*socketIdentity, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer Peer
	var lifetime peerLifetime
	var credentialError error
	if err = raw.Control(func(fd uintptr) {
		peer, lifetime, credentialError = peerCredentials(int(fd))
	}); err != nil {
		if lifetime != nil {
			lifetime.close()
		}
		return nil, err
	}
	if credentialError != nil {
		return nil, credentialError
	}
	identity := &socketIdentity{Peer: peer, lifetime: lifetime}
	if err := identity.check(); err != nil {
		lifetime.close()
		return nil, err
	}
	current, err := nativeProcess(peer.PID)
	if err != nil || current.UID != peer.UID || current.GID != peer.GID {
		lifetime.close()
		return nil, refuse("the peer's kernel process identity cannot be read\nInstead: reconnect from the live session that will issue these commands.")
	}
	identity.Start = current.Start
	if err := identity.check(); err != nil {
		lifetime.close()
		return nil, err
	}
	return identity, nil
}

func samePeer(a, b Peer) bool {
	return a.PID > 1 && a.PID == b.PID && a.UID == b.UID && a.GID == b.GID && sameStart(a.Start, b.Start)
}

// ancestry is read by the service from the kernel, with no ps executable,
// portable-mode environment switch, terminal label or caller-writable file.
func ancestry(peer Peer) ([]process, error) {
	line := []process{}
	seen := map[int]bool{}
	for pid := peer.PID; pid > 1; {
		if seen[pid] || len(line) >= 128 {
			return nil, refuse("the peer's process ancestry is invalid\nInstead: reconnect from a live recorded session.")
		}
		seen[pid] = true
		current, err := nativeProcess(pid)
		if err != nil {
			return nil, refuse("the peer's process ancestry cannot be read\nInstead: reconnect from a live recorded session.")
		}
		if len(line) == 0 && !samePeer(peer, current.Peer) {
			return nil, refuse("the peer's process start time or credentials changed\nInstead: reconnect from the live session that will issue these commands.")
		}
		if current.UID != peer.UID {
			break
		}
		line = append(line, current)
		pid = current.Parent
	}
	// Re-read each edge so an exit, reparent or PID reuse during the walk does
	// not authenticate a snapshot assembled from different process lifetimes.
	for _, old := range line {
		current, err := nativeProcess(old.PID)
		if err != nil || !samePeer(old.Peer, current.Peer) || old.Parent != current.Parent {
			return nil, refuse("the peer's process ancestry changed\nInstead: reconnect from a live recorded session.")
		}
	}
	return line, nil
}

func inAncestry(anchor Peer, line []process) bool {
	for _, current := range line {
		if samePeer(anchor, current.Peer) {
			return true
		}
	}
	return false
}

func processFor(ref ProcessRef) (process, error) {
	current, err := nativeProcess(ref.PID)
	if err != nil || ref.PID <= 1 || !sameStart(ref.Start, current.Start) {
		return process{}, refuse("the recorded process start time disagrees with the kernel\nInstead: record the live process with its kernel start time.")
	}
	return current, nil
}

func processUnavailable() error { return fmt.Errorf("kernel process identity is unavailable") }
