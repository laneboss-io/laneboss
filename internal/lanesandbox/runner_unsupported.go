//go:build !darwin && !linux

package lanesandbox

import "os/exec"

func nativeRunner(_ *exec.Cmd, _ []string, _ []writeAllowance) (bool, string, string) {
	return false, "", "runner sandbox enforcement is unavailable on this platform; runner continues without a Laneboss-files sandbox"
}
