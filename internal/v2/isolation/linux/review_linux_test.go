//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMountSnapshotIdentity(t *testing.T) {
	points, err := readMountInfo(strings.NewReader("11 1 0:1 / /fixture rw - tmpfs tmpfs rw\n" +
		"12 11 0:1 /private /fixture rw - tmpfs tmpfs rw\n"))
	if err != nil || len(points) != 2 || points[1].id != 12 || points[1].parent != 11 {
		t.Fatal("mount IDs or parent edges were discarded:", err)
	}
	if checkMounts("/fixture", points, 12) == nil {
		t.Fatal("same-target overmount alias was admitted")
	}
	plain := points[:1]
	if err := checkMounts("/fixture", plain, 11); err != nil {
		t.Fatal("matching descriptor mount control:", err)
	}
	if checkMounts("/fixture", plain, 12) == nil {
		t.Fatal("a different pinned descriptor mount was admitted")
	}
	for _, input := range []string{"x 1 0:1 / / rw - tmpfs tmpfs rw\n",
		"11 x 0:1 / / rw - tmpfs tmpfs rw\n", "11 1 0:1 / relative rw - tmpfs tmpfs rw\n"} {
		if _, err := readMountInfo(strings.NewReader(input)); err == nil {
			t.Fatal("malformed mount identity was accepted")
		}
	}
}

func TestPinRejectsSourceLinks(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "record"), []byte("ungranted"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(link, "record"))
	if err != nil || string(data) != "ungranted" {
		t.Fatal("the source-link control was not actually created")
	}
	for _, source := range []string{link, filepath.Join(link, "record")} {
		item, err := pinPath(source, "/data/selected", true)
		if err == nil {
			item.file.Close()
			t.Fatal("source symlink or symlink ancestor was followed")
		}
	}
	item, err := pinPath(filepath.Join(real, "record"), "/work/main", true)
	if err != nil {
		t.Fatal(err)
	}
	defer item.file.Close()
	if validatePinnedExport(item, false, uint32(os.Geteuid()), nil) == nil {
		t.Fatal("non-directory main workspace was admitted")
	}
}

func TestGitAdminIndirections(t *testing.T) {
	for _, cell := range []struct {
		path string
		kind string
	}{
		{".git", "file"}, {".git", "link"}, {".git/commondir", "file"}, {".git/commondir", "link"},
		{".git/objects/info/alternates", "file"}, {".git/objects/info/alternates", "link"},
		{".git/objects/info/http-alternates", "file"}, {".git/objects/info/http-alternates", "link"},
		{".git/config", "link"}, {".git/worktrees", "directory"},
	} {
		t.Run(cell.path+"-"+cell.kind, func(t *testing.T) {
			root := t.TempDir()
			item, err := pinPath(root, "/work/main", false)
			if err != nil {
				t.Fatal(err)
			}
			defer item.file.Close()
			check := func() error { return validatePinnedExport(item, false, uint32(os.Geteuid()), nil) }
			if err := check(); err != nil {
				t.Fatal("independent workspace control:", err)
			}
			selected := filepath.Join(root, cell.path)
			if err := os.MkdirAll(filepath.Dir(selected), 0700); err != nil {
				t.Fatal(err)
			}
			if cell.path != ".git" {
				if err := check(); err != nil {
					t.Fatal("independent Git directory control:", err)
				}
			}
			switch cell.kind {
			case "file":
				outside := t.TempDir()
				if err := os.WriteFile(filepath.Join(outside, "outside-record"), []byte("external-administration"), 0600); err != nil {
					t.Fatal(err)
				}
				pointer := outside + "\n"
				if cell.path == ".git" {
					pointer = "gitdir: " + pointer
				}
				err = os.WriteFile(selected, []byte(pointer), 0600)
			case "directory":
				err = os.Mkdir(selected, 0700)
			case "link":
				target := filepath.Join(root, "internal-target")
				if cell.path == ".git" {
					err = os.Mkdir(target, 0700)
				} else {
					err = os.WriteFile(target, []byte(".\n"), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				relative, err := filepath.Rel(filepath.Dir(selected), target)
				if err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(relative, selected)
			}
			if err != nil {
				t.Fatal("Git indirection fixture was not created:", err)
			}
			if _, err := os.Lstat(selected); err != nil {
				t.Fatal(err)
			}
			if err := check(); err == nil || !strings.Contains(err.Error(), "Git administration") {
				t.Fatal("Git indirection was not refused at its named gate:", err)
			}
		})
	}
}
