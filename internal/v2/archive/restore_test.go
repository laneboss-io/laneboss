package archive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func restoreGit(t *testing.T, dir string, input []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@invalid", "GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@invalid"}
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture git %s: %v: %s", args[0], err, output)
	}
	return output
}

type restoreEntry struct {
	Mode fs.FileMode
	Data string
}

func restoreTree(t *testing.T, root string) map[string]restoreEntry {
	t.Helper()
	result := map[string]restoreEntry{}
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		if rel == ".git" {
			return fs.SkipDir
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		item := restoreEntry{Mode: info.Mode()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			item.Data = string(data)
		} else if info.Mode()&os.ModeSymlink != 0 {
			item.Data, err = os.Readlink(name)
			if err != nil {
				return err
			}
		}
		result[filepath.ToSlash(rel)] = item
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func restoreFixture(t *testing.T) (api.ObjectManifest, byteStore, map[string]restoreEntry, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "lane")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	restoreGit(t, root, nil, "init", "--template=")
	for _, name := range []string{"edited", "deleted"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("committed\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	restoreGit(t, root, nil, "add", ".")
	restoreGit(t, root, nil, "commit", "-m", "fixture")
	head := strings.TrimSpace(string(restoreGit(t, root, nil, "rev-parse", "HEAD")))
	pack := restoreGit(t, root, []byte(head+"\n"), "pack-objects", "--stdout", "--revs", "--threads=1", "--window=0")
	if err := os.Remove(filepath.Join(root, "deleted")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "edited"), []byte("unsaved\x00bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "empty"), 0710); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "new name"), []byte("untracked\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "executable"), []byte("execute\n"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("edited", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	want := restoreTree(t, root)
	store := byteStore{}
	put := func(id string, data []byte) *api.BlobRef {
		store[api.ID(id)] = append([]byte{}, data...)
		return &api.BlobRef{ID: api.ID(id), Class: "artifact", Bytes: int64(len(data)), SHA256: manifest.Hash(data)}
	}
	tree := api.ObjectManifest{Schema: "laneboss.objects.v2", Git: &api.ArchiveGit{Head: head, Branch: "lane/example"},
		Entries: []api.ObjectEntry{{Path: "git", Kind: "directory", Mode: 0700}, {Path: "git/pack", Kind: "file", Mode: 0400, Content: put("git-pack", pack)}}}
	for name, item := range want {
		path := "workspace"
		if name != "." {
			path += "/" + name
		}
		entry := api.ObjectEntry{Path: path, Mode: uint32(item.Mode.Perm())}
		switch {
		case item.Mode.IsDir():
			entry.Kind = "directory"
		case item.Mode&os.ModeSymlink != 0:
			entry.Kind, entry.LinkTarget = "symlink", item.Data
		default:
			entry.Kind, entry.Content = "file", put("file-"+strings.ReplaceAll(name, " ", "-"), []byte(item.Data))
		}
		tree.Entries = append(tree.Entries, entry)
	}
	// Discard the source before restore. Only frozen object bytes remain.
	if err := os.Rename(root, root+"-stopped"); err != nil {
		t.Fatal(err)
	}
	return tree, store, want, head
}

func TestRestoreRoundTrip(t *testing.T) {
	tree, store, want, head := restoreFixture(t)
	before, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	var archived bytes.Buffer
	if err := Write(context.Background(), &archived, tree, store.read, 8<<20); err != nil {
		t.Fatal(err)
	}
	assembly := assemblyFixture(t, archived.Bytes(), store)
	kept := map[api.ID][]byte{}
	for id, data := range store {
		kept[id] = append([]byte{}, data...)
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "restored")
	got, err := Restore(context.Background(), target, tree, store.read, 8<<20, RestoreOptions{Roots: []string{parent}})
	if err != nil {
		t.Fatal("archive restore unavailable:", err)
	}
	if got != head || !reflect.DeepEqual(restoreTree(t, target), want) {
		t.Fatal("restored names, bytes, modes or branch head differ from the dirty tree")
	}
	actual := strings.TrimSpace(string(restoreGit(t, target, nil, "rev-parse", "HEAD")))
	if actual != head {
		t.Fatal("restored Git head differs from the recorded head")
	}
	after, err := json.Marshal(tree)
	if err != nil || !bytes.Equal(before, after) || !reflect.DeepEqual(kept, map[api.ID][]byte(store)) {
		t.Fatal("restore changed archive bytes or frozen manifest")
	}
	if _, err := ReadBack(context.Background(), assembly, tree, store.read, 8<<20); err != nil {
		t.Fatal("restore damaged canonical archive read-back:", err)
	}
}

func TestRestoreTargets(t *testing.T) {
	for _, kind := range []string{"empty", "nonempty", "file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			tree, store, _, _ := restoreFixture(t)
			target := filepath.Join(t.TempDir(), "existing")
			var err error
			switch kind {
			case "empty", "nonempty":
				err = os.Mkdir(target, 0700)
				if err == nil && kind == "nonempty" {
					err = os.WriteFile(filepath.Join(target, "keep"), []byte("keep"), 0600)
				}
			case "file":
				err = os.WriteFile(target, []byte("keep"), 0600)
			case "symlink":
				err = os.Symlink("missing", target)
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "empty" {
				if err := os.Chmod(filepath.Dir(target), 0700); err != nil {
					t.Fatal(err)
				}
			}
			_, err = Restore(context.Background(), target, tree, store.read, 8<<20, RestoreOptions{Roots: []string{filepath.Dir(target)}})
			if kind == "empty" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeConflict || !strings.Contains(typed.Message, "restore_target_exists") {
				t.Fatal("existing target lacks its named refusal:", err)
			}
		})
	}
}

func TestRestoreTamper(t *testing.T) {
	for _, kind := range []string{"content", "pack", "manifest", "head", "git-path"} {
		t.Run(kind, func(t *testing.T) {
			tree, store, _, _ := restoreFixture(t)
			switch kind {
			case "content":
				store["file-edited"][0] ^= 1
			case "pack":
				store["git-pack"][0] ^= 1
			case "manifest":
				tree.Entries = append(tree.Entries, tree.Entries[0])
			case "head":
				tree.Git.Head = "invalid"
			case "git-path":
				tree.Entries = append(tree.Entries, api.ObjectEntry{Path: "workspace/.git", Kind: "directory", Mode: 0700})
			}
			target := filepath.Join(t.TempDir(), "restored")
			_, err := Restore(context.Background(), target, tree, store.read, 8<<20, RestoreOptions{Roots: []string{filepath.Dir(target)}})
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity {
				t.Fatal("tampered archive lacks an integrity refusal:", err)
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("tampered archive created a target:", err)
			}
		})
	}
}
