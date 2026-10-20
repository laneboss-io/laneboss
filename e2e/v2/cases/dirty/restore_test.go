//go:build linux

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

func TestDirtyRestore(t *testing.T) {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "internal/v2/archive/restore.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, row := range []struct{ name, before, after, want string }{
		{"scope", "restoreParent(target, option.Roots)", "restoreParent(target, []string{filepath.Dir(target)})", "outside target did not fail the real command"},
		{"modes", "file.Chmod(os.FileMode(entry.Mode & 0777))", "file.Chmod(0400)", "dirty restore changed pre-stop names, bytes, modes or branch head"},
		{"archive", "return tree.Git.Head, nil", "tree.Entries[0].Mode ^= 0100; return tree.Git.Head, nil", "dirty restore wrote into the retained archive or frozen worktree"},
	} {
		if bytes.Count(raw, []byte(row.before)) != 1 {
			t.Fatal("restore control anchor moved", row.name)
		}
		dir := t.TempDir()
		changed := filepath.Join(dir, "restore.go")
		if err := os.WriteFile(changed, bytes.Replace(raw, []byte(row.before), []byte(row.after), 1), 0600); err != nil {
			t.Fatal(err)
		}
		mapping, err := json.Marshal(map[string]any{"Replace": map[string]string{path: changed}})
		if err != nil {
			t.Fatal(err)
		}
		overlay := filepath.Join(dir, "overlay.json")
		if err := os.WriteFile(overlay, mapping, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, "go", "test", "-count=1", "-timeout", "90s", "-overlay", overlay,
			"-run", "^TestDirtyRestoreCommand$", "-v", "./internal/v2/cli")
		command.Dir = root
		data, err := command.CombinedOutput()
		if err == nil || !bytes.Contains(data, []byte(row.want)) || bytes.Contains(data, []byte("build failed")) {
			t.Fatalf("restore %s control missed its deciding failure: %v\n%s", row.name, err, data)
		}
		t.Log("RED " + row.name + ": " + row.want)
	}
	command := exec.CommandContext(ctx, "go", "test", "-count=1", "-timeout", "90s",
		"-run", "^TestDirtyRestoreCommand$", "-v", "./internal/v2/cli")
	command.Dir = root
	data, err := command.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		t.Log(line)
	}
	if err != nil {
		t.Fatal("real restore command did not pass", err)
	}
}
