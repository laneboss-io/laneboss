package linux

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

type objectKey struct{ device, inode uint64 }

// Verifier's bindings come only from the trusted helper/composition root.
// There is deliberately no RPC that registers a caller-supplied cgroup.
type Verifier struct {
	mu       sync.RWMutex
	registry api.ContainmentRegistry
	closed   bool
}

// New probes the actual SO_PEERPIDFD primitive. It never substitutes pidfd_open
// on a sampled numerical PID for a socket-bound process lifetime.
func New(registry api.ContainmentRegistry) (*Verifier, error) {
	if registry == nil || (reflect.ValueOf(registry).Kind() == reflect.Pointer && reflect.ValueOf(registry).IsNil()) {
		return nil, peerError(api.CodePrerequisite, "trusted containment registry is required")
	}
	fds, err := unix.Socketpair(unix.AF_UNIX,
		unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, peerError(api.CodePrerequisite, "Unix peer probe failed")
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	fd, err := unix.GetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	if err != nil {
		return nil, peerError(api.CodeUnsupported,
			"Linux SO_PEERPIDFD is required; no PID-only fallback exists")
	}
	defer unix.Close(fd)
	unix.CloseOnExec(fd)
	if err := liveFD(fd); err != nil {
		return nil, err
	}
	return &Verifier{registry: registry}, nil
}

// Close invalidates peer handles. The helper registry owns containment pins,
// revocation and allocation tombstones until its separate measured cleanup.
func (v *Verifier) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	return nil
}

func (v *Verifier) Verify(ctx context.Context, connection net.Conn, binding api.InstalledBinding) (api.VerifiedPeer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, ok := connection.(syscall.Conn)
	if !ok || conn == nil || (reflect.ValueOf(conn).Kind() == reflect.Pointer && reflect.ValueOf(conn).IsNil()) {
		return nil, peerError(api.CodeUnauthenticated, "a Unix stream peer is required")
	}
	if err := api.ValidateBinding(binding, binding.Config, binding.ServiceVersion); err != nil {
		return nil, err
	}
	if binding.Backend != "linux-bwrap-landlock" {
		return nil, peerError(api.CodeUnsupported, "Linux peer requires the installed Linux backend")
	}
	peer, err := socketPeer(conn)
	if err != nil {
		return nil, err
	}
	peer.verifier = v
	peer.binding = binding
	facts, err := peer.Facts(ctx)
	if err != nil {
		closeErr := peer.Close()
		return nil, errors.Join(err, closeErr)
	}
	peer.initial = facts
	return peer, nil
}

type nativePeer struct {
	mu       sync.Mutex
	fd       int
	pid      int
	uid      uint32
	gid      uint32
	initial  api.PeerFacts
	closed   bool
	verifier *Verifier
	binding  api.InstalledBinding
}

var _ api.VerifiedPeer = (*nativePeer)(nil)

func socketPeer(connection syscall.Conn) (*nativePeer, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, peerError(api.CodeUnauthenticated, "socket is unavailable")
	}
	peer := &nativePeer{fd: -1}
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		var socketType int
		socketType, controlErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		if controlErr != nil || socketType != unix.SOCK_STREAM {
			controlErr = unix.EPROTOTYPE
			return
		}
		address, addressErr := unix.Getsockname(int(fd))
		if _, ok := address.(*unix.SockaddrUnix); addressErr != nil || !ok {
			controlErr = unix.EAFNOSUPPORT
			return
		}
		peer.fd, controlErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET,
			unix.SO_PEERPIDFD)
		if controlErr != nil {
			return
		}
		unix.CloseOnExec(peer.fd)
		var credential *unix.Ucred
		credential, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET,
			unix.SO_PEERCRED)
		if controlErr == nil {
			peer.pid, peer.uid, peer.gid = int(credential.Pid), credential.Uid, credential.Gid
		}
	})
	if err != nil || controlErr != nil || peer.pid <= 1 {
		if peer.fd >= 0 {
			closeErr := unix.Close(peer.fd)
			if closeErr != nil {
				return nil, peerError(api.CodeIntegrity, "peer handle could not close")
			}
		}
		return nil, peerError(api.CodeUnauthenticated,
			"socket lifetime credentials are unavailable")
	}
	if err := liveFD(peer.fd); err != nil {
		return nil, errors.Join(err, peer.Close())
	}
	return peer, nil
}

func liveFD(fd int) error {
	return liveFDWithCalls(fd, unix.PidfdSendSignal, unix.Poll)
}

func liveFDWithCalls(fd int, signal func(int, unix.Signal, *unix.Siginfo, int) error, poll func([]unix.PollFd, int) (int, error)) error {
	// EPERM is normal between service/lane UIDs. The pidfd's exit notification
	// remains authoritative; signal zero is never used as the only live check.
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		err = signal(fd, 0, nil, 0)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil && !errors.Is(err, unix.EPERM) {
		return peerError(api.CodeUnauthenticated, "connecting process liveness refused (signal_zero="+peerLifetimeErrno(err)+")")
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	var n int
	for attempt := 0; attempt < 4; attempt++ {
		fds[0].Revents = 0
		n, err = poll(fds, 0)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		return peerError(api.CodeUnauthenticated, "connecting process liveness refused (poll="+peerLifetimeErrno(err)+")")
	}
	if n != 0 || fds[0].Revents != 0 {
		reason := "event_count"
		switch {
		case fds[0].Revents&unix.POLLIN != 0:
			reason = "readable"
		case fds[0].Revents&unix.POLLNVAL != 0:
			reason = "invalid"
		case fds[0].Revents&unix.POLLHUP != 0:
			reason = "hangup"
		case fds[0].Revents != 0:
			reason = "unexpected_event"
		}
		return peerError(api.CodeUnauthenticated, "connecting process has ended (poll="+reason+")")
	}
	return nil
}

func peerLifetimeErrno(err error) string {
	for _, item := range []struct {
		value unix.Errno
		name  string
	}{{unix.EINTR, "EINTR"}, {unix.ESRCH, "ESRCH"}, {unix.EBADF, "EBADF"}, {unix.EINVAL, "EINVAL"},
		{unix.EACCES, "EACCES"}, {unix.EPERM, "EPERM"}, {unix.ENOSYS, "ENOSYS"}} {
		if errors.Is(err, item.value) {
			return item.name
		}
	}
	return "other"
}

func (p *nativePeer) Facts(ctx context.Context) (api.PeerFacts, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var empty api.PeerFacts
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if p.closed {
		return empty, peerError(api.CodeUnauthenticated, "peer handle is closed")
	}
	if p.verifier == nil {
		return empty, peerError(api.CodeContainmentUnknown, "no trusted containment binding")
	}
	p.verifier.mu.RLock()
	closed := p.verifier.closed
	p.verifier.mu.RUnlock()
	if closed {
		return empty, peerError(api.CodeUnauthenticated, "peer verifier is closed")
	}
	if err := liveFD(p.fd); err != nil {
		return empty, err
	}
	observed, err := readProcess(p.pid, p.uid, p.gid)
	if err != nil {
		return empty, err
	}
	if err := liveFD(p.fd); err != nil {
		return empty, err
	}
	facts := api.PeerFacts{HostUID: p.uid, HostGID: p.gid, HostPID: p.pid,
		ProcessGeneration: observed.generation}
	if p.binding.Class != api.EndpointHuman {
		id, err := p.verifier.resolve(ctx, observed.group, facts, p.binding)
		if err != nil {
			return empty, err
		}
		facts.ContainmentID = id
	}
	if p.initial.ProcessGeneration != "" && facts != p.initial {
		return empty, peerError(api.CodeUnauthenticated, "peer generation or containment changed")
	}
	return facts, nil
}

func (p *nativePeer) Alive(ctx context.Context) error {
	_, err := p.Facts(ctx)
	return err
}

func (p *nativePeer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return unix.Close(p.fd)
}

func (v *Verifier) resolve(ctx context.Context, relative string, facts api.PeerFacts, binding api.InstalledBinding) (api.ID, error) {
	fd, key, err := openGroup(relative)
	if err != nil {
		return "", err
	}
	if err := unix.Close(fd); err != nil {
		return "", peerError(api.CodeIntegrity, "cgroup handle could not close")
	}
	v.mu.RLock()
	closed, registry := v.closed, v.registry
	v.mu.RUnlock()
	if closed || registry == nil {
		return "", peerError(api.CodeContainmentUnknown, "peer cgroup has no live service binding")
	}
	// No verifier lock is held across the helper/registry call. Resolution has
	// only kernel facts and the endpoint binding, never an identity callback.
	resolved, err := registry.ResolveContainment(ctx, facts, binding)
	if err != nil {
		return "", err
	}
	boot, _, _ := strings.Cut(facts.ProcessGeneration, ":")
	if resolved.Revoked || resolved.Directory == nil || resolved.Config != binding.Config ||
		resolved.Backend != binding.Backend || resolved.Generation == 0 || resolved.BootID != boot ||
		binding.Target == nil || resolved.Target != *binding.Target ||
		!validID(resolved.Lease.ID) || !validID(resolved.Lease.ContainmentID) ||
		resolved.Lease.UID != facts.HostUID || resolved.Lease.GID != facts.HostGID ||
		resolved.Lease.EndpointGeneration != binding.EndpointGeneration {
		return "", peerError(api.CodeContainmentUnknown, "peer containment lease is stale or mismatched")
	}
	var stat unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(int(resolved.Directory.Fd()), &stat) != nil ||
		unix.Fstatfs(int(resolved.Directory.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR || key != (objectKey{device: uint64(stat.Dev), inode: stat.Ino}) {
		return "", peerError(api.CodeContainmentUnknown, "peer cgroup differs from the protected registry directory")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return "", peerError(api.CodeContainmentUnknown, "peer verifier closed during resolution")
	}
	return resolved.Lease.ContainmentID, nil
}

func openGroup(relative string) (int, objectKey, error) {
	var empty objectKey
	if relative == "" || strings.ContainsRune(relative, '\x00') ||
		strings.HasPrefix(relative, "/") || relative == ".." ||
		strings.HasPrefix(relative, "../") || filepath.Clean(relative) != relative {
		return -1, empty, peerError(api.CodeContainmentUnknown, "invalid host cgroup path")
	}
	root, err := unix.Open("/sys/fs/cgroup",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, empty, peerError(api.CodePrerequisite, "host cgroup v2 is unavailable")
	}
	defer unix.Close(root)
	fd, err := fdpath.Open(root, relative, &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return -1, empty, peerError(api.CodeContainmentUnknown, "cannot pin peer cgroup")
	}
	var stat unix.Stat_t
	var fs unix.Statfs_t
	statErr, fsErr := unix.Fstat(fd, &stat), unix.Fstatfs(fd, &fs)
	if statErr != nil || fsErr != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		closeErr := unix.Close(fd)
		if closeErr != nil {
			return -1, empty, peerError(api.CodeIntegrity, "cgroup handle could not close")
		}
		return -1, empty, peerError(api.CodePrerequisite, "cgroup v2 is required")
	}
	return fd, objectKey{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func validID(id api.ID) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if c != '-' && c != '_' && !(c >= 'a' && c <= 'z') &&
			!(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

type processFacts struct{ generation, group string }

func readProcess(pid int, uid, gid uint32) (processFacts, error) {
	var empty processFacts
	base := "/proc/" + strconv.Itoa(pid) + "/"
	first, err := os.ReadFile(base + "stat")
	if err != nil {
		return empty, peerError(api.CodeUnauthenticated, "peer process is unavailable")
	}
	ticks, err := processTicks(pid, first)
	if err != nil {
		return empty, err
	}
	status, err := os.ReadFile(base + "status")
	if err != nil || checkIDs(status, uid, gid) != nil {
		return empty, peerError(api.CodeUnauthenticated, "peer UID or GID changed")
	}
	data, err := os.ReadFile(base + "cgroup")
	if err != nil {
		return empty, peerError(api.CodeContainmentUnknown, "peer containment is unavailable")
	}
	group, err := unifiedGroup(data)
	if err != nil {
		return empty, err
	}
	last, err := os.ReadFile(base + "stat")
	if err != nil {
		return empty, peerError(api.CodeUnauthenticated, "peer process has ended")
	}
	lastTicks, err := processTicks(pid, last)
	if err != nil || ticks != lastTicks {
		return empty, peerError(api.CodeUnauthenticated, "peer process generation changed")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(strings.TrimSpace(string(boot))) != 36 {
		return empty, peerError(api.CodePrerequisite, "host boot generation is unavailable")
	}
	return processFacts{generation: strings.TrimSpace(string(boot)) + ":" + ticks,
		group: group}, nil
}
