//go:build !linux && !darwin

package laneturns

import "os"

func openScanChild(directory int, name string, flags int) (int, error) {
	return -1, refused("this platform cannot open a session record relative to a confined directory")
}

func openedFilePath(file *os.File) (string, error) {
	return "", refused("this platform cannot verify an opened session record's location")
}
