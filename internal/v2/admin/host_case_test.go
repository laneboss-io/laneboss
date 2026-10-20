//go:build linux

package admin

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Serialize the actual helper types so a component fixture cannot rename a
// journal field and accidentally validate a shape the helper never writes.
func TestDirtyHostOrder(t *testing.T) {
	journal := leaseRecord{Phase: "active", Storage: &launchStorageRecord{Ready: true,
		Workspace: &workspaceJournal{Phase: "published"}}}
	raw, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "host.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "e2e/v2/cases/dirty", "test_order.py")
	command := exec.Command("python3", "-I", "-B", script, path)
	output, err := command.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		t.Log(line)
	}
	if err != nil {
		t.Fatal("dirty host order or native journal read failed", err)
	}
}
