//go:build linux

// Package subreaper preserves detached descendants under their recorded supervisor.
package subreaper

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Enable runs in the supervising process before any runner is started. Kernel
// adoption does not depend on whether callers read /proc or the portable ps table.
func Enable() (bool, error) {
	disabled, err := disabled()
	if err != nil {
		return false, err
	}
	if disabled {
		return false, nil
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return false, fmt.Errorf("cannot preserve detached lane ancestry: %w", err)
	}
	return true, nil
}
