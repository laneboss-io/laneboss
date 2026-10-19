//go:build linux && laneboss_root_canary

package main

import (
	"os/exec"
	"testing"
)

// The queue runs Python controls on Linux; no project interpreter runs on Mac.
func TestCanarySpendHarness(t *testing.T) {
	command := exec.Command("python3", "-I", "-B", "../spend_canary_test.py")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("canary spend controls failed: %v\n%s", err, output)
	}
	t.Logf("canary spend controls:\n%s", output)
}
