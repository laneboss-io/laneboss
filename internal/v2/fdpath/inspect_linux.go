//go:build linux

package fdpath

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Inspect returns a single child inode, including a symlink inode, without
// following it. Export validation needs that distinction before resolving an
// ordinary contained data link. The kernel never resolves a link in this walk.
func Inspect(parent int, name string) (int, error) {
	parts, err := Components(name)
	if err != nil || len(parts) != 1 {
		return -1, unix.EINVAL
	}
	mount, err := mountID(parent)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Openat(parent, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	actual, err := mountID(fd)
	if err == nil && actual != mount {
		err = unix.EXDEV
	}
	if err != nil {
		return -1, errors.Join(err, unix.Close(fd))
	}
	return fd, nil
}

// ResolveBeneath validates contained data links using held directory/link
// descriptors. Readlinkat on the link FD cannot race a replacement pathname.
// Absolute targets, root escapes, magic links and mount crossings are refused.
func ResolveBeneath(root int, relative string) (result int, resultErr error) {
	if relative == "" || filepath.IsAbs(relative) || strings.ContainsRune(relative, 0) || len(relative) > 4096 {
		return -1, unix.EINVAL
	}
	first, err := unix.FcntlInt(uintptr(root), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return -1, err
	}
	stack := []int{first}
	defer func() {
		for _, fd := range stack {
			resultErr = errors.Join(resultErr, unix.Close(fd))
		}
		if resultErr != nil && result >= 0 {
			resultErr = errors.Join(resultErr, unix.Close(result))
			result = -1
		}
	}()
	pending, links := strings.Split(relative, "/"), 0
	for len(pending) != 0 {
		name := pending[0]
		pending = pending[1:]
		if name == "" || name == "." {
			continue
		}
		if name == ".." {
			if len(stack) == 1 {
				return -1, unix.EXDEV
			}
			fd := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if err := unix.Close(fd); err != nil {
				return -1, err
			}
			continue
		}
		fd, err := Inspect(stack[len(stack)-1], name)
		if err != nil {
			return -1, err
		}
		var info unix.Stat_t
		if err := unix.Fstat(fd, &info); err != nil {
			return -1, errors.Join(err, unix.Close(fd))
		}
		if info.Mode&unix.S_IFMT == unix.S_IFLNK {
			links++
			if links > 40 {
				return -1, errors.Join(unix.ELOOP, unix.Close(fd))
			}
			buffer := make([]byte, 4096)
			n, readErr := unix.Readlinkat(fd, "", buffer)
			closeErr := unix.Close(fd)
			if readErr != nil || closeErr != nil {
				return -1, errors.Join(readErr, closeErr)
			}
			if n == 0 || n == len(buffer) || buffer[0] == '/' {
				return -1, unix.EXDEV
			}
			pending = append(strings.Split(string(buffer[:n]), "/"), pending...)
			continue
		}
		if len(pending) == 0 {
			return fd, nil
		}
		if info.Mode&unix.S_IFMT != unix.S_IFDIR {
			return -1, errors.Join(unix.ENOTDIR, unix.Close(fd))
		}
		stack = append(stack, fd)
	}
	return unix.FcntlInt(uintptr(stack[len(stack)-1]), unix.F_DUPFD_CLOEXEC, 3)
}
