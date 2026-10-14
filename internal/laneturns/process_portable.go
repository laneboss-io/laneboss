//go:build !linux

package laneturns

import (
	"os"
	"path/filepath"
	"syscall"
)

func nativeSignal(identity object, signal syscall.Signal) (bool, bool, error) {
	return false, false, nil
}
func becomeSubreaper() bool                                               { return false }
func reapOrphans(table map[int]processEntry, runner int, excluded ...int) {}
func makeFIFO(root *os.Root, name string) error {
	return syscall.Mkfifo(filepath.Join(root.Name(), name), 0600)
}
