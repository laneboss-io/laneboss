//go:build darwin

package lane

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func nativeSignal(id object, sig syscall.Signal) (bool, bool, error) { return false, false, nil }
func becomeSubreaper() bool                                          { return false }
func fifoAt(f *os.File, directory, name string) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(553, uintptr(f.Fd()), uintptr(unsafe.Pointer(p)), 0600)
	runtime.KeepAlive(p)
	if errno != 0 {
		return errno
	}
	return nil
}
func openChildAt(f *os.File, name string, flags int, mode uint32) (int, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	fd, _, errno := syscall.Syscall6(463, uintptr(f.Fd()), uintptr(unsafe.Pointer(p)), uintptr(flags), uintptr(mode), 0, 0)
	runtime.KeepAlive(p)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}
