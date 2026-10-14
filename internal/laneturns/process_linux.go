//go:build linux

package laneturns

import (
	"os"
	"syscall"
)

func nativeSignal(identity object, signal syscall.Signal) (bool, bool, error) {
	// pidfd_open and pidfd_send_signal use these syscall numbers on Linux's
	// supported amd64 and arm64 toolchains. ENOSYS falls back to check-then-signal.
	fd, _, errno := syscall.Syscall(434, uintptr(integer(identity["pid"])), 0, 0)
	if errno == syscall.ESRCH {
		return true, false, nil
	}
	if errno != 0 {
		return false, false, nil
	}
	defer syscall.Close(int(fd))
	entry, err := procEntry(integer(identity["pid"]))
	if err != nil {
		return true, false, err
	}
	yes, err := entryMatches(entry, identity)
	if err != nil || !yes {
		return true, false, err
	}
	_, _, errno = syscall.Syscall6(424, fd, uintptr(signal), 0, 0, 0, 0)
	if errno == syscall.ESRCH {
		return true, false, nil
	}
	if errno != 0 {
		return true, false, refused("the recorded process could not be signalled through its process descriptor")
	}
	return true, true, nil
}
func becomeSubreaper() bool {
	if !nativeProcesses() {
		return false
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 36, 1, 0, 0, 0, 0)
	return errno == 0
}
func reapOrphans(table map[int]processEntry, runner int, excluded ...int) {
	for pid, entry := range table {
		blocked := false
		for _, skip := range excluded {
			if pid == skip {
				blocked = true
			}
		}
		if blocked {
			continue
		}
		if pid != runner && entry.ppid == syscall.Getpid() && len(entry.state) > 0 && entry.state[0] == 'Z' {
			var status syscall.WaitStatus
			syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		}
	}
}
func makeFIFO(root *os.Root, name string) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return syscall.Mknodat(int(f.Fd()), name, syscall.S_IFIFO|0600, 0)
}
