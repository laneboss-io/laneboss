package codex

import (
	"io"
	"os"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

// Native root-peer/source ownership and writable-alias/seal proof belong to the
// broker's authenticated private channel. Recheck the received object's actual
// shape and flags here, and read from offset zero without reopening any name.
func readRefreshDescriptor(file *os.File) ([]byte, error) {
	if file == nil {
		return nil, problem(api.CodeIntegrity, "Codex refresh descriptor is absent")
	}
	before, err := file.Stat()
	if err != nil {
		return nil, problem(api.CodeIntegrity, "Codex refresh descriptor cannot be inspected")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	flags, _, flagErr := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_GETFL, 0)
	fdFlags, _, fdErr := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_GETFD, 0)
	if !ok || !before.Mode().IsRegular() || stat.Nlink != 0 || before.Mode().Perm() != 0600 ||
		before.Size() <= 0 || before.Size() > maxAuthBytes || flagErr != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY ||
		fdErr != 0 || fdFlags&syscall.FD_CLOEXEC == 0 {
		return nil, problem(api.CodeIntegrity, "Codex refresh descriptor is not private anonymous read-only material")
	}
	data, readErr := io.ReadAll(io.NewSectionReader(file, 0, maxAuthBytes+1))
	after, statErr := file.Stat()
	if readErr != nil || statErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		before.ModTime() != after.ModTime() || int64(len(data)) != before.Size() {
		return nil, problem(api.CodeIntegrity, "Codex refresh descriptor changed during its read")
	}
	return data, nil
}
