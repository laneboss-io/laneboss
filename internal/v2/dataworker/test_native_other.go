//go:build !linux

package dataworker

import "os"

func testExecutablePath(file *os.File) string { return file.Name() }
