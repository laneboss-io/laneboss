//go:build linux && laneboss_root_canary && laneboss_gate_integration

package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestLadderObserverNative(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("observer peer canary requires the authorized root Linux box")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, "python3", "native/observer_canary.py").CombinedOutput()
	if err != nil {
		t.Fatalf("native observer boundary failed: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}
