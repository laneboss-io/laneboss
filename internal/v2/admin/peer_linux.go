//go:build linux

package admin

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type pinnedPeer struct {
	credentials unix.Ucred
	pidfd       int
}

// A bounded fresh observation tolerates signal interruption, never a native
// exit, invalid descriptor or exhausted observation. No caller can set a bound.
func pollHelperLifetime(fds []unix.PollFd, poll func([]unix.PollFd, int) (int, error)) (count int, resultErr error) {
	for attempt := 0; attempt < 32; attempt++ {
		for index := range fds {
			fds[index].Revents = 0
		}
		count, resultErr = poll(fds, 0)
		if !errors.Is(resultErr, unix.EINTR) {
			break
		}
	}
	return count, resultErr
}

func socketControl(connection *net.UnixConn, action func(int) error) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return failure(api.CodeUnauthenticated, "cannot pin helper socket")
	}
	var actionErr error
	if err := raw.Control(func(fd uintptr) { actionErr = action(int(fd)) }); err != nil {
		return err
	}
	return actionErr
}

func pinPeer(connection *net.UnixConn, uid, gid uint32) (*pinnedPeer, error) {
	peer := &pinnedPeer{pidfd: -1}
	err := socketControl(connection, func(fd int) error {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
			return err
		}
		credentials, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return err
		}
		if credentials.Uid != uid || credentials.Gid != gid || credentials.Pid <= 1 {
			return failure(api.CodeForbidden, "helper endpoint refuses a noninstalled peer identity")
		}
		peer.credentials = *credentials
		peer.pidfd, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PEERPIDFD)
		if err != nil {
			return failure(api.CodePrerequisite, "SO_PEERPIDFD is required; no PID-only helper mode exists")
		}
		unix.CloseOnExec(peer.pidfd)
		return nil
	})
	if err != nil {
		if peer.pidfd >= 0 {
			unix.Close(peer.pidfd)
		}
		var typed *api.Error
		if errors.As(err, &typed) {
			return nil, typed
		}
		return nil, failure(api.CodeUnauthenticated, "cannot authenticate native helper peer")
	}
	if err := peer.alive(); err != nil {
		unix.Close(peer.pidfd)
		return nil, err
	}
	return peer, nil
}

func (p *pinnedPeer) alive() (resultErr error) {
	defer helperCheck(&resultErr, "caller_lifetime")
	var err error
	for attempt := 0; attempt < 32; attempt++ {
		err = unix.PidfdSendSignal(p.pidfd, 0, nil, 0)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil && !errors.Is(err, unix.EPERM) {
		return failure(api.CodeUnauthenticated, "helper peer lifetime ended")
	}
	fds := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
	count, err := pollHelperLifetime(fds, unix.Poll)
	if err != nil || count != 0 || fds[0].Revents != 0 {
		return failure(api.CodeUnauthenticated, "helper peer lifetime is no longer live")
	}
	return nil
}

func (p *pinnedPeer) verifyService(b installation) (resultErr error) {
	check := "caller_containment"
	defer func() { helperCheck(&resultErr, check) }()
	if err := p.alive(); err != nil {
		return err
	}
	membership, err := cgroupMembership(int(p.credentials.Pid))
	if err != nil {
		return err
	}
	if membership != "/system.slice/laneboss-service@"+b.Config+".service" {
		return failure(api.CodeForbidden, "helper caller is outside the installed service containment")
	}
	check = "caller_privileges"
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", p.credentials.Pid))
	if err != nil {
		return failure(api.CodeUnauthenticated, "cannot recheck helper peer credentials")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "Uid", "Gid":
			fields := strings.Fields(value)
			if len(fields) != 4 {
				return failure(api.CodeUnauthenticated, "helper peer credential shape changed")
			}
			expected := b.Service.UID
			if key == "Gid" {
				expected = b.Service.GID
			}
			for _, field := range fields {
				id, err := strconv.ParseUint(field, 10, 32)
				if err != nil || uint32(id) != expected {
					return failure(api.CodeForbidden, "helper peer credentials drifted")
				}
			}
			seen[key] = true
		case "Groups":
			for _, field := range strings.Fields(value) {
				id, err := strconv.ParseUint(field, 10, 32)
				if err != nil || uint32(id) != b.Service.GID {
					return failure(api.CodeForbidden, "helper peer has supplementary groups")
				}
			}
			seen[key] = true
		case "CapEff", "CapPrm", "CapAmb":
			number, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			if err != nil || number != 0 {
				return failure(api.CodeForbidden, "service peer must be unprivileged")
			}
			seen[key] = true
		}
	}
	for _, field := range []string{"Uid", "Gid", "Groups", "CapEff", "CapPrm", "CapAmb"} {
		if !seen[field] {
			return failure(api.CodeUnauthenticated, "helper peer privilege observation is incomplete")
		}
	}
	check = "caller_executable"
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", p.credentials.Pid))
	if err != nil {
		return failure(api.CodeUnauthenticated, "cannot pin helper peer executable")
	}
	defer f.Close()
	if err := sameInstalledExecutable(f, b); err != nil {
		return err
	}
	return p.alive()
}

func sameInstalledExecutable(f *os.File, b installation) error {
	actual, err := f.Stat()
	if err != nil {
		return failure(api.CodeIntegrity, "cannot stat the executing helper artifact")
	}
	installed, err := os.Stat(b.binaryPath())
	if err != nil {
		return failure(api.CodeIntegrity, "cannot stat fixed installed helper executable")
	}
	if err := verifyFileIdentity(actual, installed); err != nil {
		return err
	}
	return verifyExecutableFile(f, b.Artifact)
}

func verifyFileIdentity(actual, installed os.FileInfo) error {
	if actual == nil || installed == nil || !os.SameFile(actual, installed) {
		return failure(api.CodeIntegrity, "executing artifact is not the fixed installed executable")
	}
	return nil
}

// Native errors can contain paths and other private details. Only the closed
// transport categories cross the helper boundary, never Error() or Unwrap().
func helperReceiveError(err error, started bool) *api.Error {
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.As(err, &timeout) && timeout.Timeout() {
		return failure(api.CodeDeadline, "helper frame receive timeout")
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || started && errors.Is(err, io.EOF) {
		return failure(api.CodeInvalid, "helper frame malformed")
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, unix.ECONNRESET) ||
		errors.Is(err, unix.EPIPE) || errors.Is(err, unix.ENOTCONN) {
		return failure(api.CodeUnavailable, "helper frame peer closed")
	}
	return failure(api.CodeUnavailable, "helper frame receive unavailable")
}

// Every read uses recvmsg. SO_PEERCRED alone would let another process write
// through an inherited/passed connected socket. Per-message SCM_CREDENTIALS
// must match the lifetime-pinned connector; all SCM_RIGHTS are closed/refused.
func readUnixFrame(connection *net.UnixConn, peer *pinnedPeer) ([]byte, error) {
	started := false
	readExact := func(target []byte) error {
		for len(target) > 0 {
			oob := make([]byte, 4096)
			n, oobn, flags, _, err := connection.ReadMsgUnix(target, oob)
			if err != nil {
				return helperReceiveError(err, started)
			}
			if n == 0 {
				return helperReceiveError(io.EOF, started)
			}
			messages, parseErr := unix.ParseSocketControlMessage(oob[:oobn])
			valid, rights, unknown := false, false, false
			for _, message := range messages {
				if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS {
					rights = true
					descriptors, err := unix.ParseUnixRights(&message)
					if err != nil {
						unknown = true
					}
					for _, descriptor := range descriptors {
						unix.Close(descriptor)
					}
				} else if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_CREDENTIALS {
					credentials, err := unix.ParseUnixCredentials(&message)
					if err != nil || valid || *credentials != peer.credentials {
						unknown = true
					} else {
						valid = true
					}
				} else {
					unknown = true
				}
			}
			if parseErr != nil || rights || unknown || !valid || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
				return failure(api.CodeForbidden, "helper descriptor passing or message-identity mismatch refused")
			}
			if n < 0 || n > len(target) {
				return failure(api.CodeInvalid, "helper frame malformed")
			}
			if err := peer.alive(); err != nil {
				return err
			}
			target = target[n:]
			started = true
		}
		return nil
	}
	var header [4]byte
	if err := readExact(header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > api.MaxFrameBytes {
		return nil, failure(api.CodeInvalid, "helper frame malformed length")
	}
	data := make([]byte, int(size))
	if err := readExact(data); err != nil {
		return nil, err
	}
	return data, nil
}
