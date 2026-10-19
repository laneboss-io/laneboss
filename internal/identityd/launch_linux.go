package identityd

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func requireNoSubreaper() error {
	var enabled int32
	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&enabled)), 0, 0, 0); err != nil {
		return refuse("the launcher's child-subreaper setting cannot be checked")
	}
	if enabled != 0 {
		return refuse("the lane launcher may not be a child subreaper\nInstead: use a dedicated launcher without PR_SET_CHILD_SUBREAPER.")
	}
	return nil
}

func replaceStdio() error {
	for _, pair := range [][2]int{{6, 0}, {4, 1}, {5, 2}} {
		if err := unix.Dup2(pair[0], pair[1]); err != nil {
			return err
		}
	}
	for fd := 3; fd <= 6; fd++ {
		if err := unix.Close(fd); err != nil {
			return err
		}
	}
	return nil
}
