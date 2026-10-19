//go:build linux

package secrets

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// SendProjection runs on the installed outside worker's private unixpacket
// connection. The owner supplies the genuinely verified peer; kernel checks
// below additionally pin this socket and each recvmsg writer. This is not a
// public RPC handler or a service-UID adapter. Success requires the actual
// helper acknowledgement and durable store read-back.
func (s *Service) SendProjection(ctx context.Context, conn *net.UnixConn, peer api.VerifiedPeer, request api.CredentialProjectionRequest) (api.CredentialProjectionRecord, error) {
	var empty api.CredentialProjectionRecord
	if conn == nil || wire.Nil(peer) {
		return empty, wire.Error(api.CodePrerequisite, "credential transfer requires its installed native channel")
	}
	if err := projectionSocket(ctx, conn, peer); err != nil {
		return empty, err
	}
	deadline := time.Now().Add(30 * time.Second)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return empty, wire.Error(api.CodeUnavailable, "credential native channel could not be bounded")
	}
	var result api.CredentialProjectionRecord
	var err error
	_, err = s.transferCredentials(ctx, peer, request, func(j bstate.Journal, f *projectionFlight) error {
		fail := func(err error) error { conn.Close(); return err }
		if err := sendProjectionPacket(conn, f.transfer, f.transfer.Files); err != nil {
			return fail(err)
		}
		data, err := receiveProjectionPacket(ctx, conn, peer)
		if err != nil {
			return fail(err)
		}
		var receipt api.CredentialProjectionReceipt
		if err := api.DecodeObject(data, &receipt); err != nil {
			return fail(err)
		}
		result, err = s.acknowledgeTransfer(ctx, j, f, receipt)
		if err != nil {
			return fail(err)
		}
		if err := sendProjectionPacket(conn, result, nil); err != nil {
			return fail(err)
		}
		return nil
	})
	if err != nil {
		return empty, err
	}
	return result, nil
}

func projectionSocket(ctx context.Context, conn *net.UnixConn, peer api.VerifiedPeer) error {
	if err := peer.Alive(ctx); err != nil {
		return err
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return wire.Error(api.CodeUnauthenticated, "credential native connection is unavailable")
	}
	var checked error
	if err := raw.Control(func(fd uintptr) {
		kind, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil || kind != unix.SOCK_SEQPACKET {
			checked = wire.Error(api.CodeForbidden, "credential channel must preserve private native message boundaries")
			return
		}
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil || cred.Uid != 0 || int(cred.Pid) != facts.HostPID || cred.Uid != facts.HostUID || cred.Gid != facts.HostGID {
			checked = wire.Error(api.CodeUnauthenticated, "credential native peer differs from its kernel socket identity")
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
			checked = wire.Error(api.CodePrerequisite, "credential channel cannot verify each native writer")
		}
	}); err != nil {
		return wire.Error(api.CodeUnavailable, "credential native channel inspection failed")
	}
	return checked
}

func sendProjectionPacket(conn *net.UnixConn, metadata any, files []*os.File) error {
	data, err := json.Marshal(metadata)
	if err != nil || len(data) == 0 || len(data) > api.MaxFrameBytes || len(files) > 64 {
		return wire.Error(api.CodeInvalid, "credential native metadata exceeds its bound")
	}
	rights := []byte(nil)
	if len(files) != 0 {
		fds := make([]int, len(files))
		for i, file := range files {
			if file == nil {
				return wire.Error(api.CodeIntegrity, "credential native export lost a descriptor")
			}
			fds[i] = int(file.Fd())
		}
		rights = unix.UnixRights(fds...)
	}
	n, oob, err := conn.WriteMsgUnix(data, rights, nil)
	if err != nil || n != len(data) || oob != len(rights) {
		return wire.Error(api.CodeUnavailable, "credential native descriptor transfer was incomplete")
	}
	return nil
}

func receiveProjectionPacket(ctx context.Context, conn *net.UnixConn, peer api.VerifiedPeer) ([]byte, error) {
	data, files, err := receiveProjectionFrame(ctx, conn, peer, 0)
	if len(files) != 0 {
		closeProjectionFiles(files)
		return nil, wire.Error(api.CodeUnauthenticated, "credential acknowledgement carried unexpected descriptors")
	}
	return data, err
}

// ReceiveRefresh owns all received duplicates immediately. AcceptCredentialRefresh
// closes the accepted file on success and refusal; malformed controls close all.
func (s *Service) ReceiveRefresh(ctx context.Context, conn *net.UnixConn, peer api.VerifiedPeer) (api.CredentialSourceVersion, error) {
	var empty api.CredentialSourceVersion
	if conn == nil || wire.Nil(peer) {
		return empty, wire.Error(api.CodePrerequisite, "credential refresh requires its installed native channel")
	}
	if err := projectionSocket(ctx, conn, peer); err != nil {
		return empty, err
	}
	deadline := time.Now().Add(30 * time.Second)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return empty, wire.Error(api.CodeUnavailable, "credential refresh channel could not be bounded")
	}
	data, files, err := receiveProjectionFrame(ctx, conn, peer, 1)
	if err != nil {
		return empty, err
	}
	var refresh api.CredentialRefresh
	if err := api.DecodeObject(data, &refresh); err != nil {
		closeProjectionFiles(files)
		return empty, err
	}
	refresh.File = files[0]
	source, err := s.AcceptCredentialRefresh(ctx, peer, refresh)
	if err != nil {
		return empty, err
	}
	if err := sendProjectionPacket(conn, source, nil); err != nil {
		return empty, err
	}
	return source, nil
}

// GuardProjection keeps the broker lock alive across the helper's one-use gate
// opening and native exec acknowledgement. The caller owns the helper lease
// lock and actual exec; this exchange never puts values into any environment.
func (s *Service) GuardProjection(ctx context.Context, conn *net.UnixConn, peer api.VerifiedPeer, request api.CredentialGateRequest) error {
	if conn == nil || wire.Nil(peer) {
		return wire.Error(api.CodePrerequisite, "credential gate requires its live private channel")
	}
	if err := projectionSocket(ctx, conn, peer); err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return wire.Error(api.CodeUnavailable, "credential gate channel could not be bounded")
	}
	guard, err := s.lockCredentialProjection(ctx, request, peer)
	if err != nil {
		return err
	}
	defer guard.Close()
	if err := guard.Check(ctx); err != nil {
		return err
	}
	if err := sendProjectionPacket(conn, guard.Projection(), nil); err != nil {
		return guard.Fence(err)
	}
	data, err := receiveProjectionPacket(ctx, conn, peer)
	if err != nil {
		return guard.Fence(err)
	}
	var acknowledgement struct {
		Opened bool `json:"opened"`
	}
	if err := api.DecodeObject(data, &acknowledgement); err != nil {
		return guard.Fence(err)
	}
	if !acknowledgement.Opened {
		return guard.Fence(wire.Error(api.CodeForbidden, "credential gate exec acknowledgement was refused"))
	}
	return guard.Check(ctx)
}

func receiveProjectionFrame(ctx context.Context, conn *net.UnixConn, peer api.VerifiedPeer, expected int) ([]byte, []*os.File, error) {
	data, control := make([]byte, api.MaxFrameBytes+1), make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(64*4))
	var n, oob, flags int
	var received error
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, nil, wire.Error(api.CodeUnavailable, "credential native receiver is unavailable")
	}
	err = raw.Read(func(fd uintptr) bool {
		n, oob, flags, _, received = unix.Recvmsg(int(fd), data, control, unix.MSG_CMSG_CLOEXEC)
		return received != unix.EAGAIN && received != unix.EWOULDBLOCK
	})
	if err != nil || received != nil {
		return nil, nil, wire.Error(api.CodeUnavailable, "credential native acknowledgement was incomplete")
	}
	messages, err := unix.ParseSocketControlMessage(control[:oob])
	if err != nil {
		return nil, nil, wire.Error(api.CodeUnauthenticated, "credential native control message was malformed")
	}
	files := []*os.File{}
	accepted := false
	defer func() {
		if !accepted {
			closeProjectionFiles(files)
		}
	}()
	// Take ownership of every kernel-delivered right before any peer lookup
	// can fail. MSG_CMSG_CLOEXEC already set close-on-exec atomically.
	for _, message := range messages {
		if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS {
			fds, err := unix.ParseUnixRights(&message)
			if err != nil {
				return nil, nil, wire.Error(api.CodeUnauthenticated, "credential native rights were malformed")
			}
			for _, fd := range fds {
				files = append(files, os.NewFile(uintptr(fd), "credential-received"))
			}
		}
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return nil, nil, err
	}
	writers, invalid := 0, false
	for _, message := range messages {
		if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_CREDENTIALS {
			cred, err := unix.ParseUnixCredentials(&message)
			if err != nil || cred.Uid != 0 || int(cred.Pid) != facts.HostPID || cred.Uid != facts.HostUID || cred.Gid != facts.HostGID {
				invalid = true
			}
			writers++
		} else if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS {
			// Ownership was recorded before the peer check above.
		} else {
			invalid = true
		}
	}
	if invalid || writers != 1 || len(files) != expected || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n == 0 || n > api.MaxFrameBytes {
		return nil, nil, wire.Error(api.CodeUnauthenticated, "credential acknowledgement changed its writer controls or bounded shape")
	}
	if err := peer.Alive(ctx); err != nil {
		return nil, nil, err
	}
	accepted = true
	return data[:n], files, nil
}
