//go:build linux

package lane

import (
	"os"
	"syscall"
)

func nativeSignal(id object, sig syscall.Signal) (bool, bool, error) {
	fd, _, errno := syscall.RawSyscall(434, uintptr(integer(id["pid"])), 0, 0)
	if errno == syscall.ESRCH {
		return false, true, nil
	}
	if errno != 0 {
		return false, false, nil
	}
	defer syscall.Close(int(fd))
	p, err := linuxInfo(integer(id["pid"]))
	if err != nil {
		return false, true, err
	}
	yes, err := processMatches(p, id)
	if err != nil || !yes {
		return false, true, err
	}
	_, _, errno = syscall.RawSyscall6(424, fd, uintptr(sig), 0, 0, 0, 0)
	return errno == 0, true, nil
}
func becomeSubreaper() bool {
	if !nativeProcesses() {
		return false
	}
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, 36, 1, 0, 0, 0, 0)
	return errno == 0
}
func fifoAt(f *os.File, directory, name string) error {
	return syscall.Mknodat(int(f.Fd()), name, syscall.S_IFIFO|0600, 0)
}
func openChildAt(f *os.File, name string, flags int, mode uint32) (int, error) {
	return syscall.Openat(int(f.Fd()), name, flags, mode)
}
