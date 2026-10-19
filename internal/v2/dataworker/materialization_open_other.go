//go:build !linux

package dataworker

import (
	"errors"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Darwin keeps the descriptor-relative, nonfollowing portable walk. Its native
// worker bridge remains unavailable until that platform's proof is supplied.
func openJobPath(root *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
	if err := manifest.Relative(name); err != nil {
		return nil, err
	}
	current, err := root.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	baseInfo, err := current.Stat()
	if err != nil {
		return nil, errors.Join(err, current.Close())
	}
	baseFacts, ok := baseInfo.Sys().(*syscall.Stat_t)
	if !ok || !baseInfo.IsDir() {
		return nil, errors.Join(manifest.Invalid("job root has no directory identity"), current.Close())
	}
	if name == "." {
		return current, nil
	}
	parts := strings.Split(name, "/")
	for i, component := range parts {
		openFlags := os.O_RDONLY | unix.O_DIRECTORY
		if i == len(parts)-1 {
			openFlags = flags
		}
		fd, openErr := unix.Openat(int(current.Fd()), component, openFlags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, uint32(mode.Perm()))
		closeErr := current.Close()
		if openErr != nil {
			return nil, errors.Join(openErr, closeErr)
		}
		current = os.NewFile(uintptr(fd), component)
		if closeErr != nil {
			return nil, errors.Join(closeErr, current.Close())
		}
		info, err := current.Stat()
		if err != nil {
			return nil, errors.Join(err, current.Close())
		}
		facts, ok := info.Sys().(*syscall.Stat_t)
		if !ok || facts.Dev != baseFacts.Dev {
			return nil, errors.Join(lstate.Error(api.CodeIntegrity, "job path crosses its held root device"), current.Close())
		}
	}
	return current, nil
}
