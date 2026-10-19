//go:build linux && laneboss_gate_integration

package admin

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestInstalledIsolationProof(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if os.Geteuid() != 0 {
		t.Fatal("installed isolation fixture requires its isolated root unit")
	}
	binding := installedGateBinding(t)
	membership, err := cgroupMembership(os.Getpid())
	if err != nil || membership != "/system.slice/laneboss-helper@"+binding.Config+".service/control" {
		t.Fatal("installed isolation fixture is outside its native control unit")
	}
	root, err := os.OpenRoot(binding.statePath())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lock, err := root.OpenFile("lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	var lockStat unix.Stat_t
	if unix.Fstat(int(lock.Fd()), &lockStat) != nil || lockStat.Uid != 0 || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Mode&07777 != 0600 || lockStat.Nlink != 1 {
		t.Fatal("installed isolation fixture lock is unsafe")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("installed isolation fixture requires exclusive helper ownership")
	}
	closeProc, err := mountHelperProc(binding.runtimePath())
	if err != nil {
		t.Fatal("acceptance: installed helper could not mount its private pristine procfs")
	}
	defer func() {
		if err := closeProc(); err != nil {
			t.Error(err)
		}
	}()
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := readProtected("/etc/laneboss-v2/boot/"+binding.Config+".json", api.MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	var catalog bootCatalog
	if err := decodeStrict(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	manager := &leaseManager{binding: binding, bootID: strings.TrimSpace(string(boot)), store: &fileLeaseStore{root: root}}
	manager.resources = &linuxResources{binding: binding, manager: manager}
	// This runs inside the actual installed root helper unit. A component
	// source check cannot prove that its inherited syscall policy permits the
	// production no-link open of the enrolled runtime files.
	manifest, mounts, err := manager.gateMounts(ctx, leaseRecord{Spec: &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{RuntimeManifest: catalog.RuntimeManifest}}}})
	if err != nil {
		t.Fatalf("acceptance: installed helper unit cannot pin its protected runtime: %v", err)
	}
	if len(mounts) < len(manifest.Objects) || len(manifest.Objects) == 0 {
		t.Fatal("acceptance: installed runtime pin omitted its actual source descriptors")
	}
	for _, mount := range mounts {
		if err := mount.file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	packet, err := manager.measureIsolation(ctx, catalog.RuntimeManifest)
	if err != nil {
		t.Fatalf("acceptance: installed isolation evidence did not reach its deciding native measurements: %v", err)
	}
	if packet.Reference.Bytes != int64(len(packet.Bytes)) || packet.Reference.SHA256 != digestBytes(packet.Bytes) {
		t.Fatal("retained installed isolation bytes changed")
	}
	var proof isolationProof
	if err := decodeStrict(packet.Bytes, &proof); err != nil {
		t.Fatal(err)
	}
	if err := verifyIsolationHost(proof); err != nil {
		t.Fatal(err)
	}
	observed, err := isolationCapabilities(proof, packet.Reference, binding, catalog.RuntimeManifest, time.Now())
	if err != nil || !observed.Available {
		t.Fatal("acceptance: installed isolation boundary evidence was incomplete")
	}
	if err := checkIsolationReservations(root, 0); err != nil {
		t.Fatal(err)
	}
}
