//go:build !linux && !darwin

package laneturns

import "os"

func terminalMode(file *os.File) (func(), bool, bool) { return func() {}, false, false }
