//go:build linux

package lanesandbox

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/unix"
)

// This probe changes no process permissions. A kernel without usable Landlock
// never refuses a lane start. A kernel with Landlock still cannot be presented
// as enforcing an exact deny-only policy merely because it supports rulesets.
func nativeRunner(_ *exec.Cmd, paths []string, _ []writeAllowance) (bool, string, string) {
	abi, _, failure := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if failure != 0 || abi == 0 {
		return false, "", "Linux Landlock is unavailable; runner continues without a Laneboss-files sandbox"
	}
	return false, "", fmt.Sprintf("Linux Landlock ABI %d is available, but exact deny-only protection of %d paths is not implemented; runner continues without a Laneboss-files sandbox", abi, len(paths))
}
