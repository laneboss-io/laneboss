//go:build linux

package admin

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

type nativeMountOpenat2 = fdpath.Openat2

type nativeMountWalkError struct{ cause error }

func (*nativeMountWalkError) Error() string   { return "native mount component walk failed" }
func (e *nativeMountWalkError) Unwrap() error { return e.cause }

const nativeMountParentFlags = unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_DIRECTORY
const nativeMountLeafFlags = unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW

func openNativeMountSource(source string, openat2 nativeMountOpenat2) (int, error) {
	// Source paths are derived from protected installation/storage metadata.
	// Reject normalization rather than cleaning away a forbidden component.
	if !filepath.IsAbs(source) || source == "/" {
		return -1, &nativeMountWalkError{cause: unix.EINVAL}
	}
	relative := strings.TrimPrefix(source, "/")
	if _, err := nativeMountComponents(relative); err != nil {
		return -1, &nativeMountWalkError{cause: err}
	}
	fd, err := fdpath.OpenWith(unix.AT_FDCWD, source, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}, openat2)
	if err != nil {
		var walked *fdpath.WalkError
		if errors.As(err, &walked) {
			return -1, &nativeMountWalkError{cause: err}
		}
		return -1, err
	}
	return fd, nil
}

func nativeMountComponents(relative string) ([]string, error) {
	return fdpath.Components(relative)
}

// The caller owns trustedRoot. Own a duplicate for the entire walk, opening
// exactly one validated component relative to its held parent at every step.
func walkNativeMountAt(trustedRoot int, relative string) (int, error) {
	if _, err := nativeMountComponents(relative); err != nil {
		return -1, err
	}
	return fdpath.Walk(trustedRoot, relative, &unix.OpenHow{Flags: nativeMountLeafFlags, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
}
