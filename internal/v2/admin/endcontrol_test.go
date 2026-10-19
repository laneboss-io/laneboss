//go:build linux

package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func runEndControl(t *testing.T, file, before, after, target, diagnostic, tags string) {
	t.Helper()
	path, err := filepath.Abs(file)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Count(raw, []byte(before)) != 1 {
		t.Fatal("end control anchor is missing or ambiguous", err)
	}
	directory := t.TempDir()
	mutant := filepath.Join(directory, file)
	if err := os.WriteFile(mutant, bytes.Replace(raw, []byte(before), []byte(after), 1), 0600); err != nil {
		t.Fatal(err)
	}
	mapping, err := json.Marshal(map[string]any{"Replace": map[string]string{path: mutant}})
	if err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(directory, "overlay.json")
	if err := os.WriteFile(overlay, mapping, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"test", "-count=1", "-overlay", overlay, "-run", "^" + target + "$", "-v"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	command := exec.Command("go", append(args, ".")...)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(output, []byte(diagnostic)) ||
		!bytes.Contains(output, []byte("--- FAIL: "+target)) {
		t.Fatalf("end control missed its deciding assertion: %v\n%s", err, output)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, raw) {
		t.Fatal("end control changed the candidate", err)
	}
	t.Log("RED:", target, diagnostic)
}

func TestEndControls(t *testing.T) {
	t.Run("publication", func(t *testing.T) {
		runEndControl(t, "lease.go", "m.commitExitForRelease(ctx, &record, request.Observation)", "error(nil)",
			"TestEndCommitBoundary", "exit commit did not precede credential cleanup and removal", "")
	})
	t.Run("stop-order", func(t *testing.T) {
		runEndControl(t, "gate.go", "reason := stopWithdrawalReason(record)", "reason := \"release\"",
			"TestStopChoiceBeforeFence", "pre-exit Stop became a release at its native fence", "")
	})
	t.Run("native-refusals", func(t *testing.T) {
		runEndControl(t, "lease.go", "m.commitExitForRelease(ctx, &record, request.Observation)", "error(nil)",
			"TestEndCommitRefusals", "normal release bypassed native refusal", "")
	})
}
