//go:build linux

package linux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPinnedBwrapBehavior(t *testing.T) {
	directory, spec, _ := kernelFixture(t)
	spec.Argv = []string{helperPath}
	plan, _, err := prepareSandbox(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	probe, err := newBwrapProbe(plan)
	if err != nil {
		t.Fatal(err)
	}
	args, _ := buildArgs(probe.plan)
	observed, probeErr := probe.run(ctx, args)
	saveJSON(t, directory, "bwrap-behavior.json", observed)
	closeErr := probe.close()
	if err := errors.Join(probeErr, closeErr); err != nil {
		t.Fatal("pinned binary behavior failed:", err)
	}
	binary, err := os.ReadFile(bwrapPath)
	if err != nil {
		t.Fatal(err)
	}
	saveBytes(t, directory, "bwrap.bin", binary)
	hash := sha256.Sum256(binary)
	saveJSON(t, directory, "bwrap-binary.json", map[string]any{
		"sha256": hex.EncodeToString(hash[:]), "bytes": len(binary)})
	if observed.ReadOnlyWriteErrno == 0 || observed.SeccompErrno == 0 || observed.WriteErrno != 0 {
		t.Fatal("probe did not observe the actual operations")
	}
}

func changedProbeArgs(t *testing.T, args []string, mutation string) []string {
	t.Helper()
	result := append([]string{}, args...)
	for index, arg := range result {
		if index+2 < len(result) && result[index+2] == probeReadOnly && arg == "--ro-bind" {
			if mutation == "missing-ro-bind" {
				result[index] = "--lb-no-ro-bind"
				return result
			}
			if mutation == "writable-ro" {
				result[index] = "--bind"
				return result
			}
		}
		if index+2 < len(result) && result[index+2] == "/work/main" && arg == "--bind" && mutation == "missing-bind" {
			result[index] = "--lb-no-bind"
			return result
		}
		if arg == "--seccomp" && mutation == "missing-filter" {
			return append(result[:index], result[index+2:]...)
		}
	}
	t.Fatal("probe mutation did not change an argument")
	return nil
}

func TestBwrapProbeRejectsBadOptions(t *testing.T) {
	directory, spec, _ := kernelFixture(t)
	spec.Argv = []string{helperPath}
	plan, _, err := prepareSandbox(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	for _, cell := range []struct{ mutation, check string }{
		{"missing-bind", "bwrap_options"}, {"missing-ro-bind", "bwrap_options"},
		{"writable-ro", "bwrap_fd_mounts"}, {"missing-filter", "bwrap_seccomp"},
	} {
		t.Run(cell.mutation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			probe, err := newBwrapProbe(plan)
			if err != nil {
				t.Fatal(err)
			}
			args, _ := buildArgs(probe.plan)
			observed, probeErr := probe.run(ctx, changedProbeArgs(t, args, cell.mutation))
			saveJSON(t, directory, cell.mutation+".json", observed)
			closeErr := probe.close()
			if closeErr != nil {
				t.Fatal("probe collection failed:", closeErr)
			}
			var refused *PrerequisiteError
			if !errors.As(probeErr, &refused) || refused.Check != cell.check {
				t.Fatalf("missing/misbehaving option was not refused at %s: %v", cell.check, probeErr)
			}
		})
	}
}

func TestBwrapFailureStopsRunner(t *testing.T) {
	directory, spec, seed := kernelFixture(t)
	marker := filepath.Join(spec.Worktree, "runner-proof")
	// An ordinary shell is the proposed runner. The actual missing-option
	// probe must fail before this source-independent marker command executes.
	spec.Argv = []string{"/bin/sh", "-c", `/bin/cat > /work/main/runner-proof`}
	spec.Stdin = bytes.NewReader(seed)
	plan, payload, err := prepareSandbox(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	probeCalled := false
	failedProbe := func(ctx context.Context, plan launchPlan) error {
		probeCalled = true
		probe, err := newBwrapProbe(plan)
		if err != nil {
			return err
		}
		args, _ := buildArgs(probe.plan)
		observed, probeErr := probe.run(ctx, changedProbeArgs(t, args, "missing-bind"))
		saveJSON(t, directory, "stopped-probe.json", observed)
		return errors.Join(probeErr, probe.close())
	}
	cmd, _, err := startSandboxWithProbe(ctx, plan, payload, spec, failedProbe)
	if cmd != nil {
		waitErr := cmd.Wait()
		saveJSON(t, directory, "unexpected-exit.json", map[string]int{"exit": exitNumber(waitErr)})
		t.Fatal("runner started after failed option probe")
	}
	if !probeCalled {
		t.Fatalf("missing-option probe was not called; earlier startup prerequisite: %v", err)
	}
	var refused *PrerequisiteError
	if !errors.As(err, &refused) || refused.Check != "bwrap_options" {
		t.Fatalf("missing-option cause was not preserved; actual probe error: %v", err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused runner created its marker")
	}
}
