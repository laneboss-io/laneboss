//go:build linux

package laneturns

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func openScanChild(directory int, name string, flags int) (int, error) {
	for {
		fd, err := syscall.Openat(directory, name, flags, 0)
		if err != syscall.EINTR {
			return fd, err
		}
	}
}

func openedFilePath(file *os.File) (string, error) {
	path, err := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(file.Fd()), 10))
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(path, " (deleted)") {
		return "", refused("the opened record was removed before its location could be verified")
	}
	return path, nil
}
