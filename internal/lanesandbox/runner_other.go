//go:build !darwin

package lanesandbox

import "os/exec"

func ReplacesRunner(map[string]any) bool { return false }
func CheckClaudeSettings([]string) error { return nil }

func nativeAllowedWrites(_ *exec.Cmd, _ Configuration, _ []string) ([]writeAllowance, error) {
	return nil, nil
}
