package main

import (
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestDashboardEntryCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidate.txt")
	raw := []byte(t.Name())
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := checkWorkspace(path, hash(raw))
	if err != nil || result["sha256"] != hash(raw) || result["bytes"] != len(raw) {
		t.Fatal("fixture check did not read actual candidate bytes", err)
	}
	if err := os.WriteFile(path, append(raw, '!'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkWorkspace(path, hash(raw)); err == nil {
		t.Fatal("fixture check accepted changed candidate bytes")
	}
}

func TestDashboardEntryCheckPlan(t *testing.T) {
	candidate := api.BlobRef{ID: "actual-candidate", Class: "manifest", SHA256: hash([]byte(t.Name())), Bytes: int64(len(t.Name()))}
	executable := api.Executable{ID: "actual-executable", SHA256: hash([]byte("executable")), Version: "1.0.0"}
	budget := api.Budget{WallMS: 12345, Processes: 5}
	expected := hash([]byte("actual candidate file"))
	plan := workspaceCheckPlan(candidate, executable, "actual-child-grants", budget, expected)
	if plan.Input != candidate || plan.Executable != executable || plan.GrantSetID != "actual-child-grants" || plan.Budget != budget ||
		len(plan.Argv) != 4 || plan.Argv[3] != string(expected) {
		t.Fatal("fixture check plan lost candidate, executable, grants or expected bytes")
	}
}
