//go:build linux

package dataworker

import (
	"os"
	"strconv"
)

func testExecutablePath(file *os.File) string { return "/proc/self/fd/" + strconv.Itoa(int(file.Fd())) }
