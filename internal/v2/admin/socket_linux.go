//go:build linux

package admin

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Called only after the installed root directory and process flock are held.
func recoverHelperSocket(ctx context.Context, binding installation) error {
	return recoverSocketAt(ctx, binding.socketPath(), 0, binding.Service.GID)
}

func recoverSocketAt(ctx context.Context, path string, uid, gid uint32) error {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return failure(api.CodeIntegrity, "cannot observe existing helper socket")
	}
	info, ok := before.Sys().(*unix.Stat_t)
	if !ok {
		// os.FileInfo uses syscall.Stat_t; observe through native lstat below.
		info = &unix.Stat_t{}
		if err := unix.Lstat(path, info); err != nil {
			return failure(api.CodeIntegrity, "cannot pin helper socket metadata")
		}
	}
	if before.Mode()&os.ModeSocket == 0 || info.Uid != uid || info.Gid != gid || before.Mode().Perm() != 0660 {
		return failure(api.CodeIntegrity, "existing helper endpoint is not its protected socket")
	}
	bounded, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(bounded, "unix", path)
	if err == nil {
		if err := connection.Close(); err != nil {
			return failure(api.CodeIntegrity, "cannot close live socket observation")
		}
		return failure(api.CodeConflict, "an existing helper endpoint is still live")
	}
	if !errors.Is(err, unix.ECONNREFUSED) {
		return failure(api.CodeConflict, "helper socket liveness is unknown")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return failure(api.CodeIntegrity, "helper socket changed during recovery")
	}
	if err := os.Remove(path); err != nil {
		return failure(api.CodeIntegrity, "cannot collect proven dead helper socket")
	}
	return nil
}
