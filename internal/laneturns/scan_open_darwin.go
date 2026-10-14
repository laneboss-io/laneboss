//go:build darwin

package laneturns

import (
	"bytes"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Darwin's standard syscall package does not export openat. This uses the
// module's already pinned x/sys dependency for the descriptor-relative call.
func openScanChild(directory int, name string, flags int) (int, error) {
	for {
		fd, err := unix.Openat(directory, name, flags, 0)
		if err != syscall.EINTR {
			return fd, err
		}
	}
}

func openedFilePath(file *os.File) (string, error) {
	var path [1024]byte // Darwin's MAXPATHLEN used by F_GETPATH.
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_GETPATH, uintptr(unsafe.Pointer(&path[0])))
	runtime.KeepAlive(file)
	if errno != 0 {
		return "", errno
	}
	end := bytes.IndexByte(path[:], 0)
	if end <= 0 {
		return "", refused("the opened record's kernel path is incomplete")
	}
	return string(path[:end]), nil
}
