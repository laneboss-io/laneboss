//go:build linux

package service

import (
	"context"
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Set permissions and credentials before listen. No connector may queue a
// frame in the interval between binding the pathname and protecting its mode.
func listenInstalled(ctx context.Context, binding api.InstalledBinding) (listener net.Listener, resultErr error) {
	return listenMode(ctx, binding, 0660)
}

func listenAdministrator(ctx context.Context, binding api.InstalledBinding) (net.Listener, error) {
	return listenMode(ctx, binding, 0600)
}

func listenMode(ctx context.Context, binding api.InstalledBinding, mode os.FileMode) (listener net.Listener, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var owned os.FileInfo
	defer func() {
		if fd >= 0 {
			resultErr = errors.Join(resultErr, unix.Close(fd))
		}
		if resultErr != nil && owned != nil {
			if current, err := os.Lstat(binding.Socket); err == nil && os.SameFile(owned, current) {
				resultErr = errors.Join(resultErr, os.Remove(binding.Socket))
			}
		}
	}()
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: binding.Socket}); err != nil {
		return nil, err // Existing paths are never removed, including stale ones.
	}
	owned, err = os.Lstat(binding.Socket)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(binding.Socket, mode); err != nil {
		return nil, err
	}
	if err := os.Chown(binding.Socket, int(binding.ServiceUID), int(binding.ServiceGID)); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}
	if err := unix.Listen(fd, 128); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "installed-service-listener")
	fd = -1 // Ownership is now held by file; FileListener duplicates it.
	listener, err = net.FileListener(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		if listener != nil {
			closeErr = errors.Join(closeErr, listener.Close())
		}
		return nil, errors.Join(err, closeErr)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	return listener, nil
}
