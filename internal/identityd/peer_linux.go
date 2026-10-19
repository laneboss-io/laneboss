package identityd

import (
	"errors"

	"golang.org/x/sys/unix"
)

type linuxLifetime struct{ fd int }

func (p *linuxLifetime) check() error {
	// Signal zero sends no signal. Different service/caller UIDs normally yield
	// EPERM, so additionally poll the same pidfd's kernel exit notification.
	err := unix.PidfdSendSignal(p.fd, 0, nil, 0)
	if err != nil && !errors.Is(err, unix.EPERM) {
		return refuse("the connecting process's kernel lifetime ended\nInstead: reconnect from the live session that will issue these commands.")
	}
	fds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err != nil || n != 0 || fds[0].Revents != 0 {
		return refuse("the connecting process's kernel lifetime ended\nInstead: reconnect from the live session that will issue these commands.")
	}
	return nil
}

func (p *linuxLifetime) mutationAllowed() error { return p.check() }

func (p *linuxLifetime) close() error { return unix.Close(p.fd) }

func (*linuxLifetime) mode() string { return "pidfd" }

func peerCredentials(fd int) (Peer, peerLifetime, error) {
	// This reference belongs to the process associated with the socket, not
	// whatever process happens to have the numerical PID at accept time.
	pidfd, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	if err != nil {
		return Peer{}, nil, refuse("the kernel cannot bind the Unix peer's process lifetime\nInstead: use Linux 6.5 or later with SO_PEERPIDFD; no PID-only mutation mode is available.")
	}
	unix.CloseOnExec(pidfd)
	lifetime := &linuxLifetime{fd: pidfd}
	credential, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		lifetime.close()
		return Peer{}, nil, err
	}
	if credential.Pid <= 1 {
		lifetime.close()
		return Peer{}, nil, processUnavailable()
	}
	return Peer{PID: int(credential.Pid), UID: credential.Uid, GID: credential.Gid}, lifetime, nil
}
