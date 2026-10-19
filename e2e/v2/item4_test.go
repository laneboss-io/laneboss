//go:build linux

package e2e_test

import (
	"os/exec"
	"testing"
)

// Python case-oracle and native descriptor checks execute on the authorized
// Linux queue alongside Go regressions, never on the development Mac.
func TestItem4PythonOracles(t *testing.T) {
	for _, directory := range []string{".", "cases/policy", "cases/guidance", "cases/integrate"} {
		t.Run(directory, func(t *testing.T) {
			command := exec.Command("python3", "-m", "unittest", "discover", "-s", directory, "-p", "test_*.py")
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("Python oracle or descriptor regression failed: %s", output)
			}
		})
	}
}
