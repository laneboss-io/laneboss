//go:build linux

package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
)

// VerifyAdministrator checks the live fixed helper unit and protected installed
// artifact. The privileged daemon checks mapped executables at its entry.
// A supplied UID, source label or service actor is never evidence.
func VerifyAdministrator(ctx context.Context, endpoint api.AdminEnrollmentEndpoint, connection api.ConnectionContext, frame api.FrameContext) error {
	if err := ctx.Err(); err != nil {
		return api.AdminEnrollmentFailure("deadline", err)
	}
	if err := api.ValidateAdminEnrollmentEndpoint(endpoint); err != nil {
		return api.AdminEnrollmentFailure("admin_enrollment", err)
	}
	if connection == nil || frame == nil || connection.Peer() == nil {
		return api.AdminEnrollmentFailure("connection", Invalid("administrator enrollment requires its native private channel"))
	}
	socket, ok := connection.Conn().(*net.UnixConn)
	if !ok || socket.LocalAddr().String() != endpoint.Socket {
		return api.AdminEnrollmentFailure("socket", Invalid("administrator channel differs from the protected endpoint"))
	}
	peer, err := PeerCredentials(socket)
	if err != nil {
		return api.AdminEnrollmentFailure("peer_credentials", err)
	}
	if peer.UID != 0 || peer.PID <= 0 {
		return api.AdminEnrollmentFailure("peer_uid", Invalid("administrator channel requires the installed root helper"))
	}
	if err := frame.Verify(ctx, connection); err != nil {
		return api.AdminEnrollmentFailure("frame", err)
	}
	statPath := fmt.Sprintf("/proc/%d/stat", peer.PID)
	before, err := os.ReadFile(statPath)
	if err != nil {
		return api.AdminEnrollmentFailure("peer_lifetime", err)
	}
	if err := administratorUnit(endpoint, connection.Binding(), peer); err != nil {
		return err
	}
	after, err := os.ReadFile(statPath)
	if err != nil {
		return api.AdminEnrollmentFailure("peer_lifetime", err)
	}
	start := func(data []byte) string {
		at := strings.LastIndexByte(string(data), ')')
		if at < 0 {
			return ""
		}
		fields := strings.Fields(string(data[at+1:]))
		if len(fields) < 20 {
			return ""
		}
		return fields[19]
	}
	if start(before) == "" || start(before) != start(after) {
		return api.AdminEnrollmentFailure("peer_lifetime", Invalid("administrator helper kernel lifetime changed"))
	}
	facts, err := connection.Peer().Facts(ctx)
	if err != nil {
		return api.AdminEnrollmentFailure("peer_lifetime", err)
	}
	if facts.ProcessGeneration != start(after) {
		return api.AdminEnrollmentFailure("peer_lifetime", Invalid("administrator connection belongs to an earlier helper lifetime"))
	}
	b := connection.Binding()
	if b.Config != endpoint.Config || b.InstallationGeneration != endpoint.InstallationGeneration || b.ServiceUID != endpoint.ServiceUID || b.Socket != endpoint.Socket {
		return api.AdminEnrollmentFailure("generation", Invalid("administrator channel installation generation changed"))
	}
	return nil
}

// The root daemon verifies its own mapped artifact before opening its protected
// socket. Enrollment is forwarded by that daemon, not by the external root CLI.
// The service can read these kernel/installed facts without ptrace authority.
func administratorUnit(endpoint api.AdminEnrollmentEndpoint, binding api.InstalledBinding, peer SocketPeer) error {
	if endpoint.Helper.Version != release.Version || binding.ServiceVersion != release.Version || binding.ArtifactSHA256 != endpoint.Helper.SHA256 {
		return api.AdminEnrollmentFailure("helper_artifact", Invalid("administrator helper release differs from the installed service"))
	}
	runtime := filepath.Join("/run/laneboss-v2", endpoint.Config)
	directory, err := administratorDirectory(runtime)
	if err != nil {
		return api.AdminEnrollmentFailure("helper_socket", err)
	}
	var socket unix.Stat_t
	if err := unix.Lstat(filepath.Join(runtime, "helper.sock"), &socket); err != nil {
		return api.AdminEnrollmentFailure("helper_socket", err)
	}
	if directory.Gid != binding.ServiceGID || directory.Mode&07777 != 0750 ||
		socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Uid != 0 || socket.Gid != binding.ServiceGID || socket.Mode&07777 != 0660 || socket.Nlink != 1 {
		return api.AdminEnrollmentFailure("helper_socket", Invalid("administrator helper socket or protected directory differs"))
	}
	membership := "/system.slice/laneboss-helper@" + endpoint.Config + ".service/control"
	control := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(membership, "/"))
	if _, err := administratorDirectory(control); err != nil {
		return api.AdminEnrollmentFailure("helper_unit", err)
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(control, &filesystem); err != nil {
		return api.AdminEnrollmentFailure("helper_unit", err)
	}
	if filesystem.Type != unix.CGROUP2_SUPER_MAGIC {
		return api.AdminEnrollmentFailure("helper_unit", Invalid("administrator helper needs its real cgroup-v2 control unit"))
	}
	actual, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", peer.PID))
	if err != nil {
		return api.AdminEnrollmentFailure("helper_unit", err)
	}
	processPath := filepath.Join(control, "cgroup.procs")
	var processFile unix.Stat_t
	if err := unix.Lstat(processPath, &processFile); err != nil {
		return api.AdminEnrollmentFailure("helper_unit", err)
	}
	if processFile.Uid != 0 || processFile.Mode&unix.S_IFMT != unix.S_IFREG || processFile.Mode&0022 != 0 {
		return api.AdminEnrollmentFailure("helper_unit", Invalid("administrator control process inventory is writable or untrusted"))
	}
	members, err := os.ReadFile(processPath)
	if err != nil {
		return api.AdminEnrollmentFailure("helper_unit", err)
	}
	if err := administratorMembership(actual, members, membership, peer.PID); err != nil {
		return api.AdminEnrollmentFailure("helper_unit", err)
	}
	return administratorArtifact(filepath.Join("/usr/lib/laneboss-v2", release.Version, "laneboss"), endpoint.Helper.SHA256)
}

func administratorMembership(actual, members []byte, expected string, pid int) error {
	unified := 0
	for _, line := range strings.Split(strings.TrimSpace(string(actual)), "\n") {
		if strings.HasPrefix(line, "0::") {
			unified++
			if line != "0::"+expected {
				return Invalid("administrator connector is outside its fixed helper control unit")
			}
		}
	}
	processes := strings.Fields(string(members))
	if unified != 1 || pid <= 0 || len(processes) != 1 || processes[0] != strconv.Itoa(pid) {
		return Invalid("administrator connector is not the sole installed helper controller")
	}
	return nil
}

func administratorDirectory(path string) (unix.Stat_t, error) {
	var info unix.Stat_t
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return info, Invalid("administrator path is not canonical")
	}
	current := "/"
	for _, part := range append([]string{""}, strings.Split(strings.TrimPrefix(path, "/"), "/")...) {
		current = filepath.Join(current, part)
		if err := unix.Lstat(current, &info); err != nil {
			return info, err
		}
		if info.Uid != 0 || info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Mode&0022 != 0 {
			return info, Invalid("administrator directory is linked, untrusted or shared writable")
		}
	}
	return info, nil
}

func administratorArtifact(path string, expected api.Digest) (resultErr error) {
	refuse := func(err error) error { return api.AdminEnrollmentFailure("helper_artifact", err) }
	if _, err := administratorDirectory(filepath.Dir(path)); err != nil {
		return refuse(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return refuse(err)
	}
	file := os.NewFile(uintptr(fd), "installed-administrator-artifact")
	defer func() {
		if err := file.Close(); err != nil && resultErr == nil {
			resultErr = refuse(err)
		}
	}()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return refuse(err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Mode&07022 != 0 || before.Mode&0111 == 0 || before.Nlink != 1 || before.Size < 1 || before.Size > 1<<30 {
		return refuse(Invalid("installed administrator artifact metadata differs"))
	}
	h := sha256.New()
	count, err := io.Copy(h, io.LimitReader(file, 1<<30+1))
	if err != nil {
		return refuse(err)
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return refuse(err)
	}
	if count != before.Size || api.Digest(hex.EncodeToString(h.Sum(nil))) != expected ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mode != after.Mode ||
		before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return refuse(Invalid("installed administrator artifact bytes or identity changed"))
	}
	return nil
}

type administratorPeer struct {
	mu     sync.Mutex
	facts  api.PeerFacts
	closed bool
}

func NewAdministratorPeer(ctx context.Context, connection *net.UnixConn) (api.VerifiedPeer, error) {
	peer, err := PeerCredentials(connection)
	if err != nil {
		return nil, api.AdminEnrollmentFailure("peer_credentials", err)
	}
	if peer.UID != 0 {
		return nil, api.AdminEnrollmentFailure("peer_uid", Invalid("administrator enrollment requires a native root connector"))
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", peer.PID))
	if err != nil {
		return nil, api.AdminEnrollmentFailure("peer_lifetime", err)
	}
	at := strings.LastIndexByte(string(data), ')')
	if at < 0 {
		return nil, api.AdminEnrollmentFailure("peer_lifetime", Invalid("administrator process lifetime unavailable"))
	}
	fields := strings.Fields(string(data[at+1:]))
	if len(fields) < 20 {
		return nil, api.AdminEnrollmentFailure("peer_lifetime", Invalid("administrator process lifetime truncated"))
	}
	if err := ctx.Err(); err != nil {
		return nil, api.AdminEnrollmentFailure("deadline", err)
	}
	return &administratorPeer{facts: api.PeerFacts{HostUID: peer.UID, HostGID: peer.GID, HostPID: peer.PID, ProcessGeneration: fields[19]}}, nil
}
func (p *administratorPeer) Facts(ctx context.Context) (api.PeerFacts, error) {
	if err := p.Alive(ctx); err != nil {
		return api.PeerFacts{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.facts, nil
}
func (p *administratorPeer) Alive(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.closed {
		return Invalid("administrator peer was closed")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.facts.HostPID))
	if err != nil {
		return err
	}
	at := strings.LastIndexByte(string(data), ')')
	if at < 0 {
		return Invalid("administrator lifetime unavailable")
	}
	fields := strings.Fields(string(data[at+1:]))
	if len(fields) < 20 || fields[19] != p.facts.ProcessGeneration {
		return Invalid("administrator helper process was replaced")
	}
	return nil
}
func (p *administratorPeer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}
