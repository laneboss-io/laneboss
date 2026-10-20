package archive

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func TestRestoreGitAllowlist(t *testing.T) {
	tree, blobs, _, _ := restoreFixture(t)
	nested := t.TempDir()
	restoreGit(t, nested, nil, "init", "--template=")
	restoreGit(t, nested, nil, "symbolic-ref", "HEAD", "refs/heads/main")
	want := []byte("retained nested repository content\n")
	if err := os.WriteFile(filepath.Join(nested, "kept.txt"), want, 0600); err != nil {
		t.Fatal(err)
	}
	restoreGit(t, nested, nil, "add", "kept.txt")
	restoreGit(t, nested, nil, "commit", "-m", "nested fixture")
	head := strings.TrimSpace(string(restoreGit(t, nested, nil, "rev-parse", "HEAD")))
	restoreGit(t, nested, nil, "pack-refs", "--all")
	restoreGit(t, nested, nil, "update-ref", "refs/heads/kept", head)
	gitRoot := filepath.Join(nested, ".git")
	blocked := []string{
		"COMMIT_EDITMSG", "config", "config.worktree", "description", "index",
		"commondir", "gitdir", "info", "info/alternates",
		"objects/info/alternates", "modules", "modules/x", "modules/x/config",
		"hooks", "hooks/pre-commit", "new-control", "new-control/leaf",
		"objects/info",
	}
	for _, name := range []string{
		"commondir", "gitdir", "info/alternates", "objects/info/alternates",
		"modules/x/config", "config.worktree", "description", "hooks/pre-commit", "new-control/leaf",
	} {
		file := filepath.Join(gitRoot, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("inert redirect canary\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	tree.Entries = append(tree.Entries, api.ObjectEntry{Path: "workspace/module", Kind: "directory", Mode: 0700})
	err := filepath.WalkDir(gitRoot, func(name string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(gitRoot, name)
		if err != nil {
			return err
		}
		logical := "workspace/module/.git"
		if rel != "." {
			logical += "/" + filepath.ToSlash(rel)
		}
		entry := api.ObjectEntry{Path: logical, Mode: 0700, Kind: "directory"}
		if !item.IsDir() {
			body, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			id := api.ID("nested-" + strconv.Itoa(len(blobs)))
			blobs[id] = body
			entry.Kind, entry.Mode = "file", 0600
			entry.Content = &api.BlobRef{ID: id, Class: "artifact", Bytes: int64(len(body)), SHA256: manifest.Hash(body)}
		}
		tree.Entries = append(tree.Entries, entry)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "owner"}[allow], func(t *testing.T) {
			root := rec2Root(t)
			target := filepath.Join(root, "restored")
			var report api.RestoreReceipt
			_, err := Restore(context.Background(), target, tree, blobs.read, 8<<20,
				RestoreOptions{Roots: []string{root}, AllowNestedGit: allow, Report: &report})
			if !allow {
				var typed *api.Error
				if !errors.As(err, &typed) || !strings.Contains(typed.Message, "restore_git_unsafe") || !strings.Contains(typed.Message, "module/.git/HEAD") {
					t.Fatal("default nested Git refusal changed:", err)
				}
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("default refusal created a target:", err)
				}
				return
			}
			if err != nil {
				t.Fatal("owner could not restore the nested repository:", err)
			}
			var expected []string
			for _, name := range blocked {
				rel := "module/.git/" + name
				expected = append(expected, rel)
				if !slices.Contains(report.SkippedPaths, rel) {
					t.Errorf("Git metadata was not reported: %s", name)
				}
				if _, err := os.Lstat(filepath.Join(target, filepath.FromSlash(rel))); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("Git metadata was restored: %s: %v", name, err)
				}
			}
			sort.Strings(expected)
			if !slices.Equal(report.SkippedPaths, expected) {
				t.Error("skipped paths differ from the complete omitted inventory")
			}
			if t.Failed() {
				return
			}
			module := filepath.Join(target, "module")
			for _, name := range []string{"HEAD", "packed-refs", "refs/heads/kept", "logs/HEAD", "logs/refs/heads/main"} {
				before, err := os.ReadFile(filepath.Join(gitRoot, filepath.FromSlash(name)))
				if err != nil {
					t.Fatal(err)
				}
				after, err := os.ReadFile(filepath.Join(module, ".git", filepath.FromSlash(name)))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("allowed nested Git data changed:", name, err)
				}
			}
			if got := strings.TrimSpace(string(restoreGit(t, module, nil, "rev-parse", "HEAD"))); got != head {
				t.Fatal("nested repository lost its recorded head")
			}
			if got := restoreGit(t, module, nil, "show", "HEAD:kept.txt"); !bytes.Equal(got, want) {
				t.Fatal("nested repository lost its actual Git objects")
			}
		})
	}
}

func TestRestoreGitPaths(t *testing.T) {
	for _, admin := range []string{".git", ".GIT", ".git.", "git~1", ".g\u200cit"} {
		t.Run(admin, func(t *testing.T) {
			base := "workspace/module/" + admin
			tree := api.ObjectManifest{Entries: []api.ObjectEntry{{Path: base, Kind: "directory"}}}
			blocked := []string{
				"commondir", "gitdir", "info/alternates", "objects/info/alternates",
				"Objects/Info/ALTERNATES.", "objects/info/altern~1", "modules/x/config", "future-control",
				"modules/x/.git", "modules/x/.git/HEAD", "HEAD/child", "packed-refs/child",
				"objects/saved/config", "objects/aa/bb",
			}
			kept := []string{"HEAD", "packed-refs", "objects/ab/" + strings.Repeat("c", 38), "refs/heads/main", "logs/main", "logs/HEAD", "logs/refs/heads/main"}
			for _, name := range append(append([]string{}, blocked...), kept...) {
				kind := "file"
				if name == "modules/x/.git" {
					kind = "directory"
				}
				tree.Entries = append(tree.Entries, api.ObjectEntry{Path: base + "/" + name, Kind: kind})
			}
			skipped, err := RestorePolicy(tree, true)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range blocked {
				if !skipped[base+"/"+name] {
					t.Errorf("Git allowlist restored %s", name)
				}
			}
			for _, name := range kept {
				if skipped[base+"/"+name] {
					t.Errorf("Git allowlist omitted %s", name)
				}
			}
		})
	}
}
