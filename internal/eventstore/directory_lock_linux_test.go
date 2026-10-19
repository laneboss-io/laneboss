//go:build linux

package eventstore

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDirectoryLockDoesNotCreateFallback(t *testing.T) {
	t.Setenv("LANEBOSS_FAULTS", "")
	for _, shared := range []bool{true, false} {
		path := t.TempDir()
		directory, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer directory.Close()
			unlock, err := directoryLock(directory, shared)
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			entries, err := os.ReadDir(path)
			if err != nil || len(entries) != 0 {
				t.Fatalf("a lockable directory must remain unchanged (shared=%v): entries=%v err=%v", shared, entries, err)
			}
		}()
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 0 {
			t.Fatalf("unlock must leave the directory unchanged: entries=%v err=%v", entries, err)
		}
	}
}

func TestDirectoryLockJoinsExistingFallback(t *testing.T) {
	t.Setenv("LANEBOSS_FAULTS", "")
	path := t.TempDir()
	name := filepath.Join(path, ".lock")
	contents := []byte("retained fallback lock\n")
	if err := os.WriteFile(name, contents, 0600); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	probe, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	for _, shared := range []bool{true, false} {
		unlock, err := directoryLock(directory, shared)
		if err != nil {
			t.Fatal(err)
		}
		blocked := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		unlock()
		if blocked != syscall.EWOULDBLOCK && blocked != syscall.EAGAIN {
			t.Fatalf("an existing fallback must be locked too (shared=%v): %v", shared, blocked)
		}
		if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatalf("fallback lock was not released: %v", err)
		}
		if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_UN); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := os.ReadFile(name)
	if err != nil || !bytes.Equal(actual, contents) {
		t.Fatalf("the fallback file must be retained unchanged: %v", err)
	}
}
