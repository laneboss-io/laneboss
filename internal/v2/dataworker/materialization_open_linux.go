//go:build linux

package dataworker

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/fdpath"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Use the same restricted-openat2 fallback as the helper. NO_XDEV includes
// same-device bind mounts; NONBLOCK prevents a raced FIFO from hanging open.
func openJobPath(root *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
	if err := manifest.Relative(name); err != nil {
		return nil, err
	}
	parent, err := root.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fd, openErr := fdpath.Open(int(parent.Fd()), name, &unix.OpenHow{
		Flags: uint64(flags | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC), Mode: uint64(mode.Perm()),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	closeErr := parent.Close()
	if openErr != nil || closeErr != nil {
		if fd >= 0 {
			closeErr = errors.Join(closeErr, unix.Close(fd))
		}
		return nil, errors.Join(openErr, closeErr)
	}
	return os.NewFile(uintptr(fd), "materialization-entry"), nil
}
