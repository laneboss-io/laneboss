package archive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Feed the actual writer a complete manifest. Expected omissions are fixture
// data; all retained bytes and every skipped file/directory are checked on disk.
func rec5Check(t *testing.T, files, dirs, omit, subtrees []string) string {
	t.Helper()
	tree, blobs, _, _ := restoreFixture(t)
	base := "workspace/module/.git"
	items := map[string]api.ObjectEntry{}
	addDir := func(name string) {
		for name != "." {
			items[name] = api.ObjectEntry{Path: name, Kind: "directory", Mode: 0700}
			name = path.Dir(name)
		}
	}
	for _, name := range append([]string{"objects", "refs"}, dirs...) {
		addDir(base + "/" + name)
	}
	for _, name := range append([]string{"HEAD", "refs/heads/main"}, files...) {
		addDir(path.Dir(base + "/" + name))
		body := []byte("retained fixture bytes\n")
		if path.Base(name) == "HEAD" {
			body = []byte("ref: refs/heads/main\n")
		}
		id := api.ID("leaf-" + strconv.Itoa(len(blobs)))
		blobs[id] = body
		items[base+"/"+name] = api.ObjectEntry{Path: base + "/" + name, Kind: "file", Mode: 0600,
			Content: &api.BlobRef{ID: id, Class: "artifact", Bytes: int64(len(body)), SHA256: manifest.Hash(body)}}
	}
	delete(items, "workspace")
	for _, entry := range items {
		tree.Entries = append(tree.Entries, entry)
	}
	if err := manifest.Archived(tree); err != nil {
		t.Fatal("invalid leaf fixture:", err)
	}
	root := rec2Root(t)
	target := filepath.Join(root, "restored")
	var report api.RestoreReceipt
	_, err := Restore(context.Background(), target, tree, blobs.read, 8<<20,
		RestoreOptions{Roots: []string{root}, AllowNestedGit: true, Report: &report})
	if err != nil {
		t.Fatal("leaf-shape restore:", err)
	}
	var expected []string
	for name, entry := range items {
		rel := strings.TrimPrefix(name, base+"/")
		blocked := slices.Contains(omit, rel)
		for _, prefix := range subtrees {
			blocked = blocked || rel == prefix || strings.HasPrefix(rel, prefix+"/")
		}
		physical := filepath.Join(target, strings.TrimPrefix(name, "workspace/"))
		reported := strings.TrimPrefix(name, "workspace/")
		if blocked {
			expected = append(expected, reported)
			if _, err := os.Lstat(physical); !errors.Is(err, os.ErrNotExist) {
				t.Error("excluded fixture entry exists after restore")
			}
			continue
		}
		if entry.Kind == "directory" {
			info, err := os.Lstat(physical)
			if err != nil || !info.IsDir() {
				t.Error("retained fixture directory is missing")
			}
		} else {
			got, err := os.ReadFile(physical)
			if err != nil || !bytes.Equal(got, blobs[entry.Content.ID]) {
				t.Error("retained fixture bytes changed")
			}
		}
	}
	sort.Strings(expected)
	if !slices.Equal(report.SkippedPaths, expected) {
		t.Error("receipt does not report the exact excluded inventory")
	}
	return target
}

func TestRestoreObjectLeaves(t *testing.T) {
	loose := "objects/ab/" + strings.Repeat("c", 38)
	upper := "objects/AB/" + strings.Repeat("c", 38)
	short := "objects/ab/" + strings.Repeat("c", 37)
	long := "objects/ab/" + strings.Repeat("c", 39)
	dir := "objects/ab/" + strings.Repeat("d", 38)
	bad := []string{short, long,
		"objects/pack/other.pack", "objects/pack/pack-", "objects/pack/pack-.idx", "objects/pack/pack-a.pack.extra"}
	files := append([]string{loose, "objects/pack/pack-a.pack", "objects/pack/pack-a.idx", "objects/pack/pack-a.rev",
		"objects/saved/config", "objects/pack/pack-dir.pack/child", dir + "/child"}, bad...)
	rec5Check(t, files, nil, bad, []string{"objects/saved", "objects/pack/pack-dir.pack", dir})
	t.Run("upper-dir", func(t *testing.T) {
		rec5Check(t, []string{upper}, nil, nil, []string{"objects/AB"})
	})
	t.Run("upper-leaf", func(t *testing.T) {
		name := "objects/ab/" + strings.Repeat("C", 38)
		rec5Check(t, []string{name}, nil, []string{name}, nil)
	})
}

func TestRestoreRefControls(t *testing.T) {
	controls := []string{"config", "CONFIG.", "con\u200cfig", "config~1", "config~1.wor", "config.worktree", "hooks", "hooks~1",
		"commondir", "common~1", "gitdir", "gitdir~1", "HEAD", "head~1", "objects", "object~1", "refs", "refs~1"}
	for _, root := range []string{"refs", "logs"} {
		t.Run(root, func(t *testing.T) {
			files := []string{root + "/heads/kept"}
			var blocked []string
			for _, control := range controls {
				name := root + "/heads/" + control
				blocked = append(blocked, name)
				files = append(files, name+"/payload")
			}
			rec5Check(t, files, nil, nil, blocked)
		})
	}
}

func TestRestoreBareGitdir(t *testing.T) {
	base := "objects/ab"
	target := rec5Check(t, []string{base + "/HEAD"}, []string{base + "/objects", base + "/refs"}, nil, []string{base})
	bare := filepath.Join(target, "module/.git", base)
	if _, err := os.Lstat(bare); err == nil {
		if got := strings.TrimSpace(string(restoreGit(t, bare, nil, "rev-parse", "--is-bare-repository"))); got == "true" {
			t.Error("restored data is recognized as an embedded bare repository")
		}
	}
}
