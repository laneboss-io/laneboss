//go:build darwin

package laneturns

import (
	"os"
	"syscall"
	"unsafe"
)

func terminalMode(file *os.File) (func(), bool, bool) {
	var original syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), syscall.TIOCGETA, uintptr(unsafe.Pointer(&original)))
	if errno != 0 {
		return func() {}, false, false
	}
	mode := original
	mode.Lflag &^= syscall.ICANON | syscall.ECHO | syscall.ISIG | syscall.IEXTEN
	mode.Iflag &^= syscall.ICRNL | syscall.IXON
	mode.Cc[syscall.VMIN] = 1
	mode.Cc[syscall.VTIME] = 0
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), syscall.TIOCSETA, uintptr(unsafe.Pointer(&mode)))
	if errno != 0 {
		return func() {}, false, false
	}
	return func() {
		syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), syscall.TIOCSETA, uintptr(unsafe.Pointer(&original)))
	}, true, original.Lflag&syscall.ECHO != 0
}
