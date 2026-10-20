//go:build laneboss_e2e_authenticator

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirtyFiles(t *testing.T) {
	directory := t.TempDir()
	name := filepath.Join(directory, "README.md")
	if err := os.WriteFile(name, []byte("tracked project\n"), 0444); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	input := dirtyInput{Nonce: strings.Repeat("a", 32), TrackedPath: "README.md", UntrackedPath: "dirty.txt"}
	if err := dirtyFiles(root, input); err != nil {
		t.Fatal(err)
	}
	tracked, err := root.ReadFile(input.TrackedPath)
	if err != nil || string(tracked) != "tracked project\n\nG11 dirty tracked "+input.Nonce+"\n" {
		t.Fatal("in-lane task did not append its actual nonce", err)
	}
	untracked, err := root.ReadFile(input.UntrackedPath)
	if err != nil || string(untracked) != "G11 dirty untracked "+input.Nonce+"\n" {
		t.Fatal("in-lane task did not create its actual untracked bytes", err)
	}
	info, err := root.Stat(input.TrackedPath)
	if err != nil || info.Mode().Perm() != 0444 {
		t.Fatal("dirty task changed imported permissions", err)
	}
}

func TestDirtyOutside(t *testing.T) {
	for _, mode := range []string{"parent", "absolute", "symlink", "hardlink", "metadata"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			work := filepath.Join(directory, "work")
			if err := os.Mkdir(work, 0700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(directory, "outside.txt")
			if err := os.WriteFile(outside, []byte("outside canary\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("project\n"), 0444); err != nil {
				t.Fatal(err)
			}
			input := dirtyInput{Nonce: strings.Repeat("b", 32), TrackedPath: "README.md", UntrackedPath: "dirty.txt"}
			switch mode {
			case "parent":
				input.TrackedPath = "../outside.txt"
			case "absolute":
				input.TrackedPath = outside
			case "symlink":
				input.TrackedPath = "escape"
				if err := os.Symlink(outside, filepath.Join(work, input.TrackedPath)); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				input.TrackedPath = "escape"
				if err := os.Link(outside, filepath.Join(work, input.TrackedPath)); err != nil {
					t.Fatal(err)
				}
			case "metadata":
				input.UntrackedPath = ".git/dirty.txt"
			}
			root, err := os.OpenRoot(work)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := dirtyFiles(root, input); err == nil {
				t.Fatal("dirty task accepted a write outside lane")
			}
			kept, err := os.ReadFile(outside)
			if err != nil || string(kept) != "outside canary\n" {
				t.Fatal("dirty task changed outside canary", err)
			}
			kept, err = root.ReadFile("README.md")
			if err != nil || string(kept) != "project\n" {
				t.Fatal("invalid task partially modified the project", err)
			}
		})
	}
}
