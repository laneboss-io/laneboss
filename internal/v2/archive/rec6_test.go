package archive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRestoreBareLayout(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "owner"}[allow], func(t *testing.T) {
			tree, blobs, _, _ := restoreFixture(t)
			var content *api.BlobRef
			for _, entry := range tree.Entries {
				if entry.Path == "workspace/edited" {
					content = entry.Content
				}
			}
			for _, name := range []string{"module", "module/objects", "module/refs", "module/hooks"} {
				tree.Entries = append(tree.Entries, api.ObjectEntry{Path: "workspace/" + name, Kind: "directory", Mode: 0700})
			}
			for _, name := range []string{"module/HEAD", "module/config", "module/hooks/pre-commit"} {
				tree.Entries = append(tree.Entries, api.ObjectEntry{Path: "workspace/" + name, Kind: "file", Mode: 0600, Content: content})
			}
			root := rec2Root(t)
			target := filepath.Join(root, "restored")
			var report api.RestoreReceipt
			_, err := Restore(context.Background(), target, tree, blobs.read, 8<<20, RestoreOptions{Roots: []string{root}, AllowNestedGit: allow, Report: &report})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"module", "module/objects", "module/refs", "module/hooks", "module/HEAD", "module/config", "module/hooks/pre-commit"} {
				if !slices.Contains(report.SkippedPaths, name) {
					t.Errorf("bare layout path not reported: %s", name)
				}
				if _, err := os.Lstat(filepath.Join(target, name)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("bare layout path restored: %s", name)
				}
			}
		})
	}
}

func TestRestoreReflogs(t *testing.T) {
	rec5Check(t, []string{"logs/HEAD", "logs/refs/heads/main"}, nil, nil, nil)
}

func TestRestoreGitTarget(t *testing.T) {
	for _, name := range []string{".git", ".GIT", ".git.", "git~1", ".g\u200cit"} {
		t.Run(name, func(t *testing.T) {
			tree, blobs, _, _ := restoreFixture(t)
			root := rec2Root(t)
			target := filepath.Join(root, name)
			_, err := Restore(context.Background(), target, tree, blobs.read, 8<<20, RestoreOptions{Roots: []string{root}})
			if err == nil || !strings.Contains(err.Error(), "restore_target_git") {
				t.Fatal("Git target lacks its named refusal:", err)
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("Git target was created")
			}
		})
	}
}

func TestRestoreEmptyTarget(t *testing.T) {
	tree, blobs, _, _ := restoreFixture(t)
	root := rec2Root(t)
	target := filepath.Join(root, "empty")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), target, tree, blobs.read, 8<<20, RestoreOptions{Roots: []string{root}}); err != nil {
		t.Fatal("empty target refused:", err)
	}
}
