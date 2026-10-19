//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Exercise production enrollment and retain every resolved entry in test output.
func TestLoaderClosure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "runtime_elf_test.py", "closure")
	command.Dir = "../../../scripts/v2-admin"
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	output, err := command.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		t.Log(line)
	}
	if err != nil {
		t.Fatal("native program closure", err)
	}
}
