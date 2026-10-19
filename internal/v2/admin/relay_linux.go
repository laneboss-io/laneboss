//go:build linux

package admin

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Enable message credentials before connect, including for a fast refusal.
func helperDialer() net.Dialer {
	return net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		if err := raw.Control(func(fd uintptr) {
			optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
		}); err != nil || optionErr != nil {
			return failure(api.CodeUnavailable, "cannot enable helper message credentials")
		}
		return nil
	}}
}

// This selects which fixed identity to pin; it grants no authority itself.
func helperRootCaller(connection *net.UnixConn) (bool, error) {
	root := false
	err := socketControl(connection, func(fd int) error {
		credentials, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return failure(api.CodeUnauthenticated, "cannot observe helper caller identity")
		}
		root = credentials.Uid == 0
		return nil
	})
	return root, err
}

func readHelperFrame(ctx context.Context, connection *net.UnixConn, peer *pinnedPeer) ([]byte, error) {
	data, err := readUnixFrame(connection, peer)
	if canceled := contextError(ctx); canceled != nil {
		return nil, canceled
	}
	return data, err
}

func bindHelperCall(ctx context.Context, connection net.Conn) (func(), error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, failure(api.CodeInvalid, "helper transport requires a bounded caller")
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, failure(api.CodeUnavailable, "cannot bound helper call transport")
	}
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	return func() { stop() }, nil
}
