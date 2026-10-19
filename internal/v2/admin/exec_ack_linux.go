//go:build linux

package admin

import (
	"errors"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// A socket inherited by bwrap can remain open in its outer monitor. Create the
// exec proof inside the confined bootstrap instead: only this process owns the
// close-on-exec end. The original socket still authenticates credential input.
func attestGateReadiness(payload gatePayload) (int, error) {
	if !payload.CredentialRequired {
		if err := unix.Send(5, []byte(payload.Token), 0); err != nil {
			return -1, failure(api.CodeContainmentUnknown, "cannot attest closed gate readiness")
		}
		return -1, nil
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, failure(api.CodePrerequisite, "cannot create bootstrap-only exec proof")
	}
	n, sendErr := unix.SendmsgN(5, []byte(payload.Token), unix.UnixRights(pair[1]), nil, unix.MSG_NOSIGNAL)
	closeErr := unix.Close(pair[1])
	if sendErr != nil || closeErr != nil || n != len(payload.Token) {
		return -1, errors.Join(failure(api.CodeContainmentUnknown, "cannot transfer bootstrap-only exec proof"), unix.Close(pair[0]))
	}
	return pair[0], nil
}

// This runs only when the prepared bootstrap returns instead of execing. A
// refusal byte must precede close: worker and bootstrap may share an executable,
// so the independent executable check alone cannot classify an error return.
func refuseExecProof(fd int) {
	defer unix.Close(fd)
	if err := unix.Send(fd, []byte{1}, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err == nil {
		return
	}
	// Never turn a failed refusal write into success-shaped EOF. Keep this end
	// open until the bounded helper proof attempt has closed its peer. This is
	// the already confined lane process; helper lease/cgroup limits still apply.
	var data [1]byte
	for {
		n, _, err := unix.Recvfrom(fd, data[:], 0)
		if err == nil && n == 0 || errors.Is(err, unix.ECONNRESET) || errors.Is(err, unix.ENOTCONN) {
			return
		}
	}
}

func receiveNativeReadiness(ready *net.UnixConn, data, controls []byte) (n, oobn, flags int, resultErr error) {
	raw, err := ready.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var readErr error
	err = raw.Read(func(fd uintptr) bool {
		n, oobn, flags, _, readErr = unix.Recvmsg(int(fd), data, controls, unix.MSG_CMSG_CLOEXEC)
		return !errors.Is(readErr, unix.EAGAIN) && !errors.Is(readErr, unix.EWOULDBLOCK)
	})
	if err == nil && readErr == nil && n == 0 {
		readErr = io.EOF
	}
	return n, oobn, flags, errors.Join(err, readErr)
}

func closeReadinessRights(controls []byte) error {
	messages, err := unix.ParseSocketControlMessage(controls)
	if err != nil {
		return failure(api.CodeIntegrity, "readiness ancillary data cannot be collected")
	}
	var result error
	for _, message := range messages {
		if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS {
			fds, err := unix.ParseUnixRights(&message)
			result = errors.Join(result, err)
			for _, fd := range fds {
				result = errors.Join(result, unix.Close(fd))
			}
		}
	}
	return result
}

func nativeReadinessPeer(controls []byte, needAck bool) (_ *unix.Ucred, result *net.UnixConn, resultErr error) {
	defer func() { resultErr = errors.Join(resultErr, closeReadinessRights(controls)) }()
	messages, err := unix.ParseSocketControlMessage(controls)
	if err != nil {
		return nil, nil, failure(api.CodeIntegrity, "readiness has no unique kernel credential")
	}
	var peer *unix.Ucred
	var rights []int
	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET {
			return nil, nil, failure(api.CodeIntegrity, "readiness has foreign ancillary data")
		}
		switch message.Header.Type {
		case unix.SCM_CREDENTIALS:
			if peer != nil {
				return nil, nil, failure(api.CodeIntegrity, "readiness has no unique kernel credential")
			}
			peer, err = unix.ParseUnixCredentials(&message)
		case unix.SCM_RIGHTS:
			var fds []int
			fds, err = unix.ParseUnixRights(&message)
			rights = append(rights, fds...)
		default:
			return nil, nil, failure(api.CodeIntegrity, "readiness has foreign ancillary data")
		}
		if err != nil {
			return nil, nil, failure(api.CodeIntegrity, "readiness has malformed ancillary data")
		}
	}
	if peer == nil || needAck && len(rights) != 1 || !needAck && len(rights) != 0 {
		return nil, nil, failure(api.CodeIntegrity, "readiness has no exact bootstrap exec proof")
	}
	if !needAck {
		return peer, nil, nil
	}
	fd := rights[0]
	kind, kindErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	domain, domainErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	creator, peerErr := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if kindErr != nil || domainErr != nil || peerErr != nil || flagErr != nil || kind != unix.SOCK_SEQPACKET ||
		domain != unix.AF_UNIX {
		return nil, nil, failure(api.CodeIntegrity, "readiness exec proof has a foreign native creator")
	}
	if *creator != *peer || flags&unix.FD_CLOEXEC == 0 {
		allowAndLog("exec_proof_creator")
	}
	// Give the os.File wrapper its own FD; its finalizer must never own the
	// ancillary FD that the common deferred collector will close.
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(duplicate), "received-exec-proof")
	connection, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		if connection != nil {
			closeErr = errors.Join(closeErr, connection.Close())
		}
		return nil, nil, errors.Join(err, closeErr)
	}
	result = connection.(*net.UnixConn)
	return peer, result, nil
}
