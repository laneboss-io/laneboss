//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func keyJournalScan(data, canary []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("journal empty")
	}
	if bytes.Contains(data, canary) {
		return errors.New("key material found")
	}
	return nil
}

func TestAPIKeyHarnessScanners(t *testing.T) {
	command := exec.Command("python3", "-I", "-B", "api_key_canary_test.py")
	command.Dir = "../../../scripts/v2-serve"
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("API key harness scanner controls failed: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func TestAPIKeyScannerControls(t *testing.T) {
	workerLaunchCanary(t, false, func(t *testing.T, ctx context.Context, m *leaseManager, _ dataReg, _ api.BlobRef, _ api.Executable) {
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			t.Fatal(err)
		}
		canary := []byte("sk-ant-" + hex.EncodeToString(entropy[:]))
		clear(entropy[:])
		defer clear(canary)
		keyScannerControls(t, ctx, m, canary)
	})
}

func keyScannerControls(t *testing.T, ctx context.Context, m *leaseManager, canary []byte) {
	t.Helper()
	scratch, err := os.MkdirTemp(m.binding.runtimePath(), "key-control-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(scratch, "planted")
	workerCanaryWrite(t, path, canary, 0600)
	if err := keyDiskScanResult(t, canary, "negative-control", true, scratch); err == nil || !strings.Contains(err.Error(), "key found in persistent file bytes") {
		t.Fatal("key file scanner failed its planted-material control")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(scratch); err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	stdin, finish, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	defer finish.Close()
	child := exec.CommandContext(ctx, m.binding.binaryPath(), "key-env-control")
	child.Env = []string{"ANTHROPIC_API_KEY=" + string(canary)}
	child.Stdin, child.Stdout, child.Stderr = stdin, write, write
	if err := child.Start(); err != nil {
		t.Fatal("key environment control child did not start", err)
	}
	t.Cleanup(func() {
		if child.ProcessState == nil {
			if err := child.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
			if err := child.Wait(); err != nil {
				t.Error("key control child required forced collection")
			}
		}
	})
	if err := read.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [8]byte
	if _, err := io.ReadFull(read, ready[:]); err != nil || string(ready[:]) != "control\n" {
		t.Fatal("key environment control readiness failed")
	}
	if _, _, err := keyProcessScan(child.Process.Pid, canary, 0); err == nil || err.Error() != "key reached an earlier process environment" {
		t.Fatal("key process scanner failed its planted-environment control")
	}
	if err := finish.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal("key control child did not exit cleanly", err)
	}
	// The deliberately dirty journal has its own unit/tag. It is never
	// confused with the product units or copied into retained evidence.
	tag := "lb-key-control-" + m.binding.Config
	logger := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--unit="+tag+".service", "/usr/bin/logger", "--tag="+tag)
	logger.Env, logger.Stdin = []string{}, bytes.NewReader(canary)
	if output, err := logger.CombinedOutput(); err != nil || bytes.Contains(output, canary) {
		t.Fatal("key journal control logger failed")
	}
	sync := exec.CommandContext(ctx, "/usr/bin/journalctl", "--sync")
	sync.Env = []string{}
	if err := sync.Run(); err != nil {
		t.Fatal("key journal control synchronization failed", err)
	}
	query := exec.CommandContext(ctx, "/usr/bin/journalctl", "--quiet", "--no-pager", "--output=cat", "SYSLOG_IDENTIFIER="+tag)
	query.Env = []string{}
	output, err := query.Output()
	defer clear(output)
	if err != nil || len(bytes.TrimSpace(output)) == 0 {
		t.Fatal("key journal control query was empty or failed")
	}
	if err := keyJournalScan(output, canary); err == nil || err.Error() != "key material found" {
		t.Fatal("key journal scanner failed its planted-line control")
	}
	if err := keyJournalScan(nil, canary); err == nil || err.Error() != "journal empty" {
		t.Fatal("key journal scanner accepted empty output")
	}
	t.Log("key scanner controls: planted scratch file FAIL; actual child environ FAIL; logger journal FAIL and nonempty; no value retained")
}
