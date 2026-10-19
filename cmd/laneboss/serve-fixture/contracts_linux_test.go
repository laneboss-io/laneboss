//go:build linux && laneboss_e2e_authenticator

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestFixtureContracts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agent", "handoff"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, "python3", "-B", filepath.Join(root, "scripts", "v2-serve", "agent_evidence_test.py"))
			var log string
			if name == "handoff" {
				out := filepath.Join(t.TempDir(), "handoff")
				command = exec.CommandContext(ctx, "python3", "-B", "unit.py", "--out", out, "--pattern", "test_serve_handoff.py")
				command.Dir = filepath.Join(root, "e2e", "v2")
				log = filepath.Join(out, "unittest.log")
			}
			output, err := command.CombinedOutput()
			if err != nil {
				if log != "" {
					retained, readErr := os.ReadFile(log)
					if readErr != nil {
						t.Fatal(err, readErr)
					}
					output = append(output, retained...)
				}
				t.Fatalf("fixture contract check failed: %v\n%s", err, output)
			}
			t.Log(string(output))
		})
	}
}
