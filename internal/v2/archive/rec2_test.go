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

func rec2Root(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "authorized")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRestoreRootFence(t *testing.T) {
	for _, kind := range []string{"inside", "outside", "traversal", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			tree, blobs, _, _ := restoreFixture(t)
			root, outside := rec2Root(t), rec2Root(t)
			target := filepath.Join(root, "restored")
			switch kind {
			case "outside":
				target = filepath.Join(outside, "restored")
			case "traversal":
				target = root + "/../escape"
			case "symlink":
				if err := os.Symlink(outside, filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(root, "alias/restored")
			}
			_, err := Restore(context.Background(), target, tree, blobs.read, 8<<20, RestoreOptions{Roots: []string{root}})
			if kind == "inside" {
				if err != nil {
					t.Fatal("authorized root control refused", err)
				}
				return
			}
			var typed *api.Error
			if _, err := os.Lstat(filepath.Join(outside, "restored")); !os.IsNotExist(err) {
				t.Fatal("outside canary was created")
			}
			if !errors.As(err, &typed) || !strings.Contains(typed.Message, "restore_target_scope") {
				t.Fatal("target escaped its authorized root:", err)
			}
		})
	}
}

func TestRestoreSpecialModes(t *testing.T) {
	tree, blobs, _, _ := restoreFixture(t)
	for i := range tree.Entries {
		if tree.Entries[i].Path == "workspace/executable" {
			tree.Entries[i].Mode = 04755
		}
		if tree.Entries[i].Path == "workspace/new name" {
			tree.Entries[i].Mode = 02640
		}
		if tree.Entries[i].Path == "workspace/empty" {
			tree.Entries[i].Mode = 01710
		}
	}
	root := rec2Root(t)
	target := filepath.Join(root, "restored")
	var report api.RestoreReceipt
	_, err := Restore(context.Background(), target, tree, blobs.read, 8<<20, RestoreOptions{Roots: []string{root}, Report: &report})
	if err != nil {
		t.Fatal("archived special bits cannot be safely restored:", err)
	}
	for name, mode := range map[string]os.FileMode{"executable": 0755, "edited": 0600, "new name": 0640, "empty": 0710} {
		info, err := os.Lstat(filepath.Join(target, name))
		if err != nil || info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			t.Fatal("restored mode differs from archived rwx bits", name, err)
		}
	}
	if !slices.Equal(report.ClearedModes, []string{"empty", "executable", "new name"}) {
		t.Fatal("cleared special bits were not reported", report.ClearedModes)
	}
}

func TestRestoreGitFence(t *testing.T) {
	for _, name := range []string{".git", ".GIT", ".git.", "git~1", ".g\u200cit", ".git ", "GIT~1.", ".git::$DATA", ".git\ufeff"} {
		for _, allow := range []bool{false, true} {
			t.Run(name+"-"+map[bool]string{false: "deny", true: "owner"}[allow], func(t *testing.T) {
				tree, blobs, _, _ := restoreFixture(t)
				base := "workspace/module/" + name
				tree.Entries = append(tree.Entries, api.ObjectEntry{Path: "workspace/module", Kind: "directory", Mode: 0700},
					api.ObjectEntry{Path: base, Kind: "directory", Mode: 0700},
					api.ObjectEntry{Path: base + "/hooks", Kind: "directory", Mode: 0700})
				var content *api.BlobRef
				for _, entry := range tree.Entries {
					if entry.Path == "workspace/edited" {
						content = entry.Content
					}
				}
				for _, leaf := range []string{"config", "hooks/pre-commit", "HEAD"} {
					tree.Entries = append(tree.Entries, api.ObjectEntry{Path: base + "/" + leaf, Kind: "file", Mode: 0600, Content: content})
				}
				root := rec2Root(t)
				target := filepath.Join(root, "restored")
				var report api.RestoreReceipt
				_, err := Restore(context.Background(), target, tree, blobs.read, 8<<20, RestoreOptions{Roots: []string{root}, AllowNestedGit: allow, Report: &report})
				if !allow {
					var typed *api.Error
					if !errors.As(err, &typed) || !strings.Contains(typed.Message, "restore_git_unsafe") || !strings.Contains(typed.Message, "module/"+name) {
						t.Fatal("Git planting lacks its named path refusal", err)
					}
					return
				}
				if err != nil {
					t.Fatal("owner cannot restore safe nested Git data", err)
				}
				for _, leaf := range []string{"config", "hooks", "hooks/pre-commit"} {
					name := "module/" + name + "/" + leaf
					if !slices.Contains(report.SkippedPaths, name) {
						t.Fatal("unsafe Git metadata was not reported", name)
					}
					if _, err := os.Lstat(filepath.Join(target, name)); !os.IsNotExist(err) {
						t.Fatal("unsafe Git metadata was restored", name)
					}
				}
				if _, err := os.Lstat(filepath.Join(target, "module", name, "HEAD")); err != nil {
					t.Fatal("owner flag dropped safe nested Git data", err)
				}
			})
		}
	}
}

func TestRestoreUnsafeLinks(t *testing.T) {
	for _, kind := range []string{"modules", "outside", "chain"} {
		for _, allow := range []bool{false, true} {
			t.Run(kind+"-"+map[bool]string{false: "deny", true: "owner"}[allow], func(t *testing.T) {
				tree, blobs, _, _ := restoreFixture(t)
				entry := api.ObjectEntry{Path: "workspace/unsafe", Kind: "symlink", Mode: 0777, LinkTarget: "../escape"}
				if kind == "modules" {
					entry.Path, entry.LinkTarget = "workspace/.gitmodules", "edited"
				}
				if kind == "chain" {
					tree.Entries = append(tree.Entries, api.ObjectEntry{Path: "workspace/alias", Kind: "symlink", Mode: 0777, LinkTarget: "../escape"})
					entry.LinkTarget = "alias/child"
				}
				tree.Entries = append(tree.Entries, entry)
				root := rec2Root(t)
				target := filepath.Join(root, "restored")
				_, err := Restore(context.Background(), target, tree, blobs.read, 8<<20, RestoreOptions{Roots: []string{root}, AllowNestedGit: allow})
				var typed *api.Error
				if !errors.As(err, &typed) || !strings.Contains(typed.Message, "restore_git_unsafe") || !strings.Contains(typed.Message, strings.TrimPrefix(entry.Path, "workspace/")) {
					t.Fatal("unsafe link lacks its named path refusal", err)
				}
				if _, err := os.Lstat(target); !os.IsNotExist(err) {
					t.Fatal("unsafe link input created a destination")
				}
			})
		}
	}
}
