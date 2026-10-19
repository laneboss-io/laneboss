//go:build linux && laneboss_gate_integration

package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// This checks the actual installed artifact and descriptor bundle. The socket
// is a metadata fixture; native server identity has its separate PIDns canary.
// It grants no launch permit and does not replace installed lane execution.
func TestInstalledLaneEndpointProjection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("lane projection check requires the disposable installed root kit")
	}
	installed := installedGateBinding(t)
	service, err := workerServiceBinding(installed)
	if err != nil {
		t.Fatal(err)
	}
	id, err := randomID("lane-projection-")
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(filepath.Dir(service.Socket), "lanes")
	created := false
	if err := os.Mkdir(base, 0700); err == nil {
		created = true
		if err := os.Chown(base, int(service.ServiceUID), int(service.ServiceGID)); err != nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	if created {
		t.Cleanup(func() {
			if err := os.Remove(base); err != nil {
				t.Error(err)
			}
		})
	}
	path := filepath.Join(base, string(id)+".sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	t.Cleanup(func() {
		if err := errors.Join(listener.Close(), os.Remove(path)); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, int(service.ServiceUID), int(service.ServiceGID)); err != nil {
		t.Fatal(err)
	}
	lease := api.HelperLease{ID: id, ContainmentID: id, UID: installed.Lanes[0].UID, GID: installed.Lanes[0].GID, EndpointGeneration: installed.Generation}
	spec := api.LaunchSpec{Kind: "agent", LaunchID: id, Target: api.LifeRef{LifeID: id, Run: 2}, Backend: service.Backend,
		UIDLeaseID: id, EndpointGeneration: lease.EndpointGeneration, Runner: &api.RunnerPlan{Driver: api.DriverCodex}}
	record := leaseRecord{Lease: lease, Spec: &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: spec}}}
	manager := &leaseManager{binding: installed}
	mounts, err := manager.laneEndpointMounts(context.Background(), record)
	if err != nil {
		t.Fatal("installed lane projection could not pin its exact inputs", err)
	}
	defer func() {
		for _, mount := range mounts {
			if err := mount.file.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	if len(mounts) != 3 || mounts[0].target != wire.LaneBindingPath || !mounts[0].sealed || mounts[1].target != wire.LaneSocketPath || !mounts[1].socket ||
		mounts[2].target != wire.LaneClientPath || !mounts[2].executable || mounts[2].sealed || mounts[2].socket || mounts[2].writable {
		t.Fatal("lane projection did not produce only its sealed binding, socket and read-only client")
	}
	seals, err := unix.FcntlInt(mounts[0].file.Fd(), unix.F_GET_SEALS, 0)
	access, flagErr := unix.FcntlInt(mounts[0].file.Fd(), unix.F_GETFL, 0)
	var proof unix.Stat_t
	if err != nil || flagErr != nil || access&unix.O_ACCMODE != unix.O_RDONLY || seals&bootstrapSeals != bootstrapSeals || unix.Fstat(int(mounts[0].file.Fd()), &proof) != nil || proof.Mode&07777 != 0444 {
		t.Fatal("lane projection returned mutable binding bytes", err)
	}
	raw := make([]byte, proof.Size)
	if n, err := unix.Pread(int(mounts[0].file.Fd()), raw, 0); err != nil || n != len(raw) {
		t.Fatal("lane projection lost exact sealed bytes", err)
	}
	var binding api.InstalledBinding
	if err := decodeStrict(raw, &binding); err != nil || binding.Class != api.EndpointLane || binding.LaunchID != id || binding.Target == nil || *binding.Target != spec.Target || binding.ArtifactSHA256 != installed.Artifact.SHA256 {
		t.Fatal("sealed lane projection lost its actual spec or release identity", err)
	}
	var source, pinned unix.Stat_t
	flags, flagErr := unix.FcntlInt(mounts[1].file.Fd(), unix.F_GETFL, 0)
	if unix.Lstat(path, &source) != nil || unix.Fstat(int(mounts[1].file.Fd()), &pinned) != nil || flagErr != nil || flags&unix.O_PATH == 0 || source.Dev != pinned.Dev || source.Ino != pinned.Ino {
		t.Fatal("lane projection did not retain the actual socket inode", flagErr)
	}
	client, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(mounts[2].file.Fd())))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	count, readErr := io.Copy(digest, client)
	if err := errors.Join(readErr, client.Close()); err != nil || count != installed.Artifact.Bytes || hex.EncodeToString(digest.Sum(nil)) != string(installed.Artifact.SHA256) {
		t.Fatal("lane projection did not retain the actual enrolled client bytes", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	unsafe, err := manager.laneEndpointMounts(context.Background(), record)
	if err == nil {
		for _, mount := range unsafe {
			if err := mount.file.Close(); err != nil {
				t.Error(err)
			}
		}
		t.Fatal("lane projection accepted a changed socket mode")
	}
}
