//go:build linux

package grants_test

import (
	"os/exec"
	"testing"
)

func TestRelayLiveSequence(t *testing.T) {
	command := exec.Command("python3", "-B", "relay_live_test.py", "-v")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("installed readiness/RPC/exit ordering: %v\n%s", err, raw)
	}
}

func TestGrantsLifecycle(t *testing.T) {
	command := exec.Command("python3", "-B", "lifecycle_test.py", "-v")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("installed lifecycle before grants preparation: %v\n%s", err, raw)
	}
}
