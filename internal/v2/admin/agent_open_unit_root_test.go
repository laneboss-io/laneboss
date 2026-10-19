//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// RunAgentOpenUnit uses the shipped helper template, including its capability,
// namespace, filesystem and resource properties, for the owner open canary.
func RunAgentOpenUnit(t *testing.T) {
	t.Helper()
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	id, err := randomID("agent-open-")
	if err != nil {
		t.Fatal(err)
	}
	config := string(id[:23])
	directory, err := os.MkdirTemp("/run", "lb-v2-agent-open-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	binary := filepath.Join(directory, "canary")
	workerCanaryWrite(t, binary, self, 0555)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	args := []string{"--quiet", "--wait", "--pipe", "--collect", "--unit=laneboss-helper@" + config + ".service"}
	args = append(args, workerCanaryProperties(t, config)...)
	args = append(args, "--property=RuntimeMaxSec=80s", "--property=WorkingDirectory="+directory,
		binary, "-test.run=^TestAgentOwnerNativeCanary$", "-test.v", "--", config, "agent-open-root")
	command := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...)
	command.Env = []string{}
	command.WaitDelay = 3 * time.Second
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: TestAgentOwnerNativeCanary ")) {
		t.Fatalf("delegated agent open canary failed: %v\n%s", err, output)
	}
	t.Log(string(output))
}
