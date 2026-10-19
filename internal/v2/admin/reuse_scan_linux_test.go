//go:build linux

package admin

import (
	"os/exec"
	"testing"
)

func TestReuseHarnessControls(t *testing.T) {
	for _, name := range []string{"api_key_canary_test.py", "reuse_gate_test.py"} {
		t.Run(name, func(t *testing.T) {
			command := exec.Command("python3", "-I", "-B", name)
			command.Dir = "../../../scripts/v2-serve"
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("fake-key harness scanner controls failed: %v\n%s", err, output)
			}
			// unittest emits counts/verdicts only; no captured plant is retained.
			t.Log(string(output))
		})
	}
}
