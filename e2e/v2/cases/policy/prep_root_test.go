//go:build linux && !laneboss_root_canary

package policycase

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func prepProbe(t *testing.T, args ...string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("profile controls require the unprivileged box phase")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", append([]string{"-I", "-B", "prep_probe.py"}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("policy preparation controls: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func TestPrepProfiles(t *testing.T) {
	prepProbe(t)
	prepProbe(t, "--units")
}
