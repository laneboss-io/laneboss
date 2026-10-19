//go:build linux

package admin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCgroupReadMode(t *testing.T) {
	for _, name := range []string{"lanes", "containment"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			// Actual mode produced by Mkdir(0755) under the unit's 0077 mask.
			// This filesystem test does not claim installed cgroup ownership.
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil || before.Mode().Perm() != 0700 {
				t.Fatal("restricted directory mode control failed", err)
			}
			if err := readableCgroup(path); err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(path)
			if err != nil || after.Mode() != os.ModeDir|0755 || !os.SameFile(before, after) {
				t.Fatal("cgroup facts lost exact read-only traversal mode", err)
			}
		})
	}
	if err := readableCgroup(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("cgroup mode change ignored a filesystem failure")
	}
}
