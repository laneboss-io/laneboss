package messagingcase

import (
	"os"
	"os/exec"
	"testing"
)

func TestItem3PythonDescriptorHandoff(t *testing.T) {
	if _, err := os.Stat("test_lane_fds.py"); err != nil {
		t.Fatal("inside actor has no descriptor handoff regression", err)
	}
	command := exec.Command("python3", "-I", "test_lane_fds.py")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fixed Python lane descriptor handoff failed: %v\n%s", err, output)
	}
}

func TestItem3HarnessEntryControls(t *testing.T) {
	command := exec.Command("python3", "-I", "test_item3_harness.py")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("public event selection or owner wait failed: %v\n%s", err, output)
	}
}
