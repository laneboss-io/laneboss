package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestStopWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-B", "scripts/v2-serve/stopwait_test.py")
	command.Dir = filepath.Join("..", "..", "..")
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal("suite Stop did not wait for the committed natural exit", err)
	}
}
