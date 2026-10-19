//go:build linux

package admin

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestMemoryAlignment(t *testing.T) {
	request := testAllocation()
	request.Budget.MemoryBytes = uint64(os.Getpagesize())*3 + 17
	values := limitValues(leaseRecord{Request: request})
	if values[1][0] != "memory.max" || values[1][1] != strconv.Itoa(os.Getpagesize()*3) {
		t.Fatal("acceptance: unaligned memory limit")
	}
}

func TestPendingStateRecovery(t *testing.T) {
	directory := privateTestDir(t)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := &fileLeaseStore{root: root, owner: uint32(os.Geteuid())}
	pending := "pending-" + strings.Repeat("a", 32)
	if err := os.WriteFile(filepath.Join(directory, pending), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	records, err := store.Records()
	if err != nil || len(records) != 0 || store.Pending() != 1 {
		t.Fatal("acceptance: pending write blocked recovery")
	}
	if err := os.Chmod(filepath.Join(directory, pending), 0666); err != nil {
		t.Fatal(err)
	}
	_, err = store.Records()
	requireCode(t, err, api.CodeIntegrity)
}

func TestSocketRecovery(t *testing.T) {
	directory := privateTestDir(t)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "helper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	err = recoverSocketAt(context.Background(), path, uint32(os.Getuid()), uint32(os.Getgid()))
	requireCode(t, err, api.CodeConflict)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recoverSocketAt(context.Background(), path, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("dead socket was not collected")
	}
}

func TestLeaseAcrossRuns(t *testing.T) {
	m, _, _ := testManager()
	first, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	next := testAllocation()
	next.Cause.EffectID, next.Cause.CauseOperationID, next.Cause.Target.Run = "effect-two", "operation-two", 2
	second, err := m.allocate(context.Background(), next)
	if err != nil || second != first {
		t.Fatal("acceptance: run changed life lease")
	}
	next.Budget.Processes++
	_, err = m.allocate(context.Background(), next)
	requireCode(t, err, api.CodeIdempotencyConflict)
}

func TestArtifactCacheStamp(t *testing.T) {
	artifact := api.ReleaseArtifact{SHA256: testDigest("original")}
	info := unix.Stat_t{Dev: 1, Ino: 2, Size: 128, Mtim: unix.Timespec{Sec: 3}, Ctim: unix.Timespec{Sec: 4}}
	stamp := stampExecutable(info, artifact)
	info.Ctim.Nsec++
	if stampExecutable(info, artifact) == stamp {
		t.Fatal("artifact mutation retained the verification stamp")
	}
	info.Ctim.Nsec--
	artifact.SHA256 = testDigest("different")
	if stampExecutable(info, artifact) == stamp {
		t.Fatal("changed expected artifact reused the verification stamp")
	}
}
