//go:build linux

package client

import (
	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Go forwards an arbitrary non-CLOEXEC descriptor even when it is absent from
// ExtraFiles. Mark the parent's inherited table, without closing its handles;
// Start then clears CLOEXEC only on the two explicit child mappings. This is
// intentionally process-wide, so callers must declare every child capability.
func inheritedCloseOnExec() error {
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-client", Message: "cannot isolate inherited child descriptors", Instead: "Retain the lane and repair the required close-range primitive before starting a child."}
	}
	return nil
}
