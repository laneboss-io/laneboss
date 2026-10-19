//go:build linux

package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The installer uses a separate Python decoder. Exercise that real decoder
// against actual Go-assembled, hashed publication JSON on the Linux box.
func TestInstallerEnrollment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "scripts/v2-admin/egress_test.py")
	command.Dir = filepath.Join("..", "..", "..")
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal("installer did not accept the assembled enrollment or reject its negative controls", err)
	}
}
