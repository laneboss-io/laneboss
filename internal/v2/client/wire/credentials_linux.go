//go:build linux

package wire

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func EnableCredentials(socket syscall.Conn) error {
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	return EnableRawCredentials(raw)
}
func EnableRawCredentials(raw syscall.RawConn) error {
	var optionErr error
	err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) })
	return errors.Join(err, optionErr)
}
func PeerCredentials(connection *net.UnixConn) (SocketPeer, error) {
	return serverCredentials(connection, false)
}

func serverCredentials(connection *net.UnixConn, projected bool) (SocketPeer, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return SocketPeer{}, err
	}
	var peer *unix.Ucred
	var optionErr error
	err = raw.Control(func(fd uintptr) { peer, optionErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err = errors.Join(err, optionErr); err != nil {
		return SocketPeer{}, err
	}
	if peer == nil || peer.Pid < 0 || peer.Pid == 0 && !projected {
		return SocketPeer{}, Invalid("socket connector credentials unavailable")
	}
	return SocketPeer{UID: peer.Uid, GID: peer.Gid, PID: int(peer.Pid)}, nil
}

type credentialReader struct {
	connection *net.UnixConn
	expected   SocketPeer
}

func (r *credentialReader) Read(data []byte) (int, error) {
	control := make([]byte, 65536)
	n, count, flags, _, err := r.connection.ReadMsgUnix(data, control)
	if err != nil {
		return n, err
	}
	messages, parseErr := unix.ParseSocketControlMessage(control[:count])
	credentials, extra := 0, false
	var writer SocketPeer
	var cleanupErr error
	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET {
			extra = true
			continue
		}
		switch message.Header.Type {
		case unix.SCM_RIGHTS:
			extra = true
			descriptors, err := unix.ParseUnixRights(&message)
			cleanupErr = errors.Join(cleanupErr, err)
			for _, descriptor := range descriptors {
				cleanupErr = errors.Join(cleanupErr, unix.Close(descriptor))
			}
		case unix.SCM_CREDENTIALS:
			credentials++
			peer, err := unix.ParseUnixCredentials(&message)
			if err != nil {
				extra = true
				continue
			}
			writer = SocketPeer{UID: peer.Uid, GID: peer.Gid, PID: int(peer.Pid)}
		default:
			extra = true
		}
	}
	if cleanupErr != nil {
		return 0, cleanupErr
	}
	if parseErr != nil || extra || credentials != 1 || writer != r.expected || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		return 0, Invalid("missing, mixed, extra or truncated socket writer credentials")
	}
	return n, nil
}
