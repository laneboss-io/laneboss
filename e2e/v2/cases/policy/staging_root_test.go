//go:build linux && laneboss_root_canary

package policycase

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Keep the protected-path regression in the authorized Linux root phase.
func TestPolicyProtectedStaging(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("policy staging controls require the authorized root Linux box")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	path := filepath.Join("..", "..", "..", "..", "scripts", "v2-serve", "policy_staging_test.py")
	command := exec.CommandContext(ctx, "python3", "-I", "-B", path, "-v")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("policy staging regression: %v\n%s", err, output)
	}
	t.Log(string(output))
}
