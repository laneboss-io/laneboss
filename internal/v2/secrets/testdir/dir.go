// Package testdir constructs private, identity-checked synthetic test scopes.
// It is imported only by this lane's tests, never by production packages.
package testdir

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func New(t testing.TB) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal("cannot protect synthetic test parent")
	}
	directory := filepath.Join(parent, "private")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal("cannot create private synthetic test directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatal("synthetic test directory is not ordinary and private")
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok || identity.Uid != uint32(os.Geteuid()) {
		t.Fatal("synthetic test directory has the wrong identity")
	}
	return directory
}
