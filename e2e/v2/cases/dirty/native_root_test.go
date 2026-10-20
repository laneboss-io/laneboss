//go:build linux && laneboss_root_canary

package dirtycase

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Capture compiler/linker diagnostics as well as the native test's output.
// Queue summaries otherwise omit build stderr for this large native package.
func TestDirtyNative(t *testing.T) {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "internal/v2/admin/arch_fs_linux.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	anchor := []byte("unix.Fchmod(int(file.Fd()), entry.Mode&0555)")
	if bytes.Count(raw, anchor) != 1 {
		t.Fatal("native freeze control moved")
	}
	directory := t.TempDir()
	changed := filepath.Join(directory, "freeze.go")
	if err := os.WriteFile(changed, bytes.Replace(raw, anchor,
		[]byte("unix.Fchmod(int(file.Fd()), entry.Mode)"), 1), 0600); err != nil {
		t.Fatal(err)
	}
	mapping, err := json.Marshal(map[string]any{"Replace": map[string]string{path: changed}})
	if err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(directory, "overlay.json")
	if err := os.WriteFile(overlay, mapping, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	mutant := exec.CommandContext(ctx, "go", "test", "-p", "1", "-count=1", "-timeout", "60s",
		"-tags", "laneboss_root_canary", "-overlay", overlay,
		"-run", "^TestDirtyFreeze$", "-v", "./internal/v2/admin")
	mutant.WaitDelay = 5 * time.Second
	mutant.Dir = root
	output, err := mutant.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("archive writable access was restored")) ||
		bytes.Contains(output, []byte("build failed")) {
		t.Fatalf("native freeze control missed its deciding assertion: %v\n%s", err, output)
	}
	t.Log("RED native freeze: restored write permission is rejected")
	command := exec.CommandContext(ctx, "go", "test", "-p", "1", "-count=1", "-timeout", "60s", "-tags", "laneboss_root_canary",
		"-run", "^TestDirtyFreeze$", "-v", "./internal/v2/admin")
	command.WaitDelay = 5 * time.Second
	command.Dir = root
	output, err = command.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		t.Log(line)
	}
	if err != nil {
		t.Fatal("native dirty freeze canary failed", err)
	}
}
