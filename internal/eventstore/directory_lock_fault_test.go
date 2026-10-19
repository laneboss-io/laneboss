//go:build linux && laneboss_faults

package eventstore

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDirLockFallbackCreated(t *testing.T) {
	t.Setenv("LANEBOSS_FAULTS", `{"point":"directory-lock"}`)
	path := t.TempDir()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	unlock, err := directoryLock(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	name := filepath.Join(path, ".lock")
	info, err := os.Stat(name)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("an unsupported directory lock must create the regular fallback: %v", err)
	}
	probe, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
		t.Fatalf("the fallback reader must actually hold its file lock: %v", err)
	}
}
