//go:build linux

// Package fdpath pins paths without following any link, including when an
// inherited syscall filter refuses openat2. Every fallback component is opened
// relative to its held parent; it never retries an absolute pathname with open.
package fdpath

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type Openat2 func(int, string, *unix.OpenHow) (int, error)

type WalkError struct{ Cause error }

func (*WalkError) Error() string   { return "descriptor component walk failed" }
func (e *WalkError) Unwrap() error { return e.Cause }

const parentFlags = unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_DIRECTORY

func Components(relative string) ([]string, error) {
	if relative == "" || filepath.IsAbs(relative) || strings.ContainsRune(relative, 0) {
		return nil, unix.EINVAL
	}
	parts := strings.Split(relative, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, unix.EINVAL
		}
	}
	return parts, nil
}

func Open(root int, name string, how *unix.OpenHow) (int, error) {
	return OpenWith(root, name, how, unix.Openat2)
}

func OpenWith(root int, name string, how *unix.OpenHow, openat2 Openat2) (int, error) {
	if how == nil || openat2 == nil || how.Resolve&^uint64(unix.RESOLVE_BENEATH|unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS|unix.RESOLVE_NO_XDEV) != 0 ||
		how.Resolve&unix.RESOLVE_NO_SYMLINKS == 0 || how.Flags&unix.O_NOFOLLOW == 0 || how.Flags&unix.O_CLOEXEC == 0 {
		return -1, unix.EINVAL
	}
	relative := name
	absolute := filepath.IsAbs(name)
	if absolute {
		if root != unix.AT_FDCWD || how.Resolve&unix.RESOLVE_BENEATH != 0 || name == "/." {
			return -1, unix.EINVAL
		}
		relative = strings.TrimPrefix(name, "/")
	}
	if relative != "." {
		if _, err := Components(relative); err != nil {
			return -1, err
		}
	}
	if !absolute && root == unix.AT_FDCWD {
		return -1, unix.EINVAL
	}
	fd, err := openat2(root, name, how)
	if err == nil || !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EPERM) {
		return fd, err
	}
	if absolute {
		root, err = unix.Open("/", parentFlags, 0)
		if err != nil {
			return -1, err
		}
	}
	fd, err = Walk(root, relative, how)
	if absolute {
		if closeErr := unix.Close(root); closeErr != nil {
			err = errors.Join(err, closeErr)
			if fd >= 0 {
				err = errors.Join(err, unix.Close(fd))
				fd = -1
			}
		}
	}
	if err != nil {
		return -1, &WalkError{Cause: err}
	}
	return fd, nil
}

// Walk owns a duplicate, not the caller's root. The sole permitted dot is the
// complete name ".", used to reopen an already pinned directory with new flags.
func Walk(root int, relative string, how *unix.OpenHow) (int, error) {
	if how == nil {
		return -1, unix.EINVAL
	}
	parts := []string{"."}
	if relative != "." {
		var err error
		parts, err = Components(relative)
		if err != nil {
			return -1, err
		}
	}
	parent, err := unix.FcntlInt(uintptr(root), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return -1, err
	}
	var mount uint64
	if how.Resolve&unix.RESOLVE_NO_XDEV != 0 {
		mount, err = mountID(parent)
		if err != nil {
			return -1, errors.Join(err, unix.Close(parent))
		}
	}
	for index, component := range parts {
		flags, mode := parentFlags, uint32(0)
		if index == len(parts)-1 {
			flags, mode = int(how.Flags)|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(how.Mode)
		}
		next, openErr := unix.Openat(parent, component, flags, mode)
		closeErr := unix.Close(parent)
		if openErr != nil || closeErr != nil {
			if next >= 0 {
				closeErr = errors.Join(closeErr, unix.Close(next))
			}
			return -1, errors.Join(openErr, closeErr)
		}
		var info unix.Stat_t
		err = unix.Fstat(next, &info)
		if err == nil && info.Mode&unix.S_IFMT == unix.S_IFLNK {
			err = unix.ELOOP // O_PATH|O_NOFOLLOW can return the link inode.
		}
		if err == nil && how.Resolve&unix.RESOLVE_NO_XDEV != 0 {
			var actual uint64
			actual, err = mountID(next)
			if err == nil && actual != mount {
				err = unix.EXDEV // Includes bind mounts on the same device.
			}
		}
		if err != nil {
			return -1, errors.Join(err, unix.Close(next))
		}
		parent = next
	}
	return parent, nil
}

func mountID(fd int) (uint64, error) {
	var info unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &info); err != nil {
		return 0, err
	}
	if info.Mask&unix.STATX_MNT_ID == 0 {
		return 0, unix.EOPNOTSUPP
	}
	return info.Mnt_id, nil
}
