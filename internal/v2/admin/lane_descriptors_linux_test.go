//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func init() {
	if len(os.Args) == 3 && os.Args[1] == "admin-lane-descriptors" {
		os.Exit(laneDescriptorFixture(os.Args[2]))
	}
	if len(os.Args) == 4 && os.Args[1] == "admin-lane-descriptor-vendor" {
		os.Exit(laneDescriptorVendor(os.Args[2], os.Args[3]))
	}
}

func laneDescriptorFixture(token string) int {
	// This child already has its own mount namespace. Hide /run on a private
	// tmpfs before creating projections, so no host pathname is changed.
	if os.Geteuid() != 0 || unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil ||
		unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755") != nil ||
		os.Mkdir("/run/laneboss", 0755) != nil {
		return 111
	}
	for _, projection := range []struct {
		target string
		fd     int
	}{{wire.LaneBindingPath, 7}, {wire.LaneSocketPath, 8}, {"/run/laneboss/extra-input", 7}, {"/run/laneboss/extra-socket", 8}} {
		if os.Symlink("/proc/self/fd/"+strconv.Itoa(projection.fd), projection.target) != nil {
			return 112
		}
	}
	for _, descriptor := range []bootstrapDescriptor{
		{FD: 7, Target: "/run/laneboss/extra-input"},
		{FD: 8, Target: "/run/laneboss/extra-socket", Socket: true},
		{FD: 7, Target: wire.LaneClientPath},
		{FD: 7, Target: wire.LaneSocketPath},
		{FD: 8, Target: wire.LaneBindingPath, Socket: true},
	} {
		var typed *api.Error
		err := retainBootstrapDescriptors([]bootstrapDescriptor{descriptor})
		if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "invalid fixed inherited descriptor inventory" {
			return 114
		}
	}
	valid := []bootstrapDescriptor{{FD: 7, Target: wire.LaneBindingPath}, {FD: 8, Target: wire.LaneSocketPath, Socket: true}}
	if err := retainBootstrapDescriptors(valid); err != nil {
		return 117
	}
	for _, check := range []struct {
		descriptor bootstrapDescriptor
		message    string
	}{
		{bootstrapDescriptor{FD: 6, Target: wire.LaneBindingPath}, "fixed inherited input is not exactly sealed"},
		{bootstrapDescriptor{FD: 7, Target: wire.LaneSocketPath, Socket: true}, "fixed worker socket descriptor type changed"},
	} {
		var typed *api.Error
		err := retainBootstrapDescriptors([]bootstrapDescriptor{check.descriptor})
		if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != check.message {
			return 115
		}
	}
	if err := retainBootstrapDescriptors(append(append([]bootstrapDescriptor{}, valid...), valid[0])); err == nil {
		return 116
	}
	if err := retainBootstrapDescriptors(valid); err != nil {
		return 117
	}
	if os.Remove(wire.LaneBindingPath) != nil || os.Symlink("/proc/self/fd/8", wire.LaneBindingPath) != nil {
		return 127
	}
	var projectionError *api.Error
	projectionErr := retainBootstrapDescriptors(valid[:1])
	if !errors.As(projectionErr, &projectionError) || projectionError.Code != api.CodeIntegrity || projectionError.Message != "fixed inherited descriptor projection changed" {
		return 128
	}
	if os.Remove(wire.LaneBindingPath) != nil || os.Symlink("/proc/self/fd/7", wire.LaneBindingPath) != nil {
		return 129
	}
	for _, fd := range []int{7, 8} {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC != 0 {
			return 118
		}
	}
	var marker unix.Stat_t
	if unix.Fstat(6, &marker) != nil {
		return 119
	}
	payload := gatePayload{Token: token, Argv: []string{"/proc/self/exe", "admin-lane-descriptor-vendor",
		strconv.FormatUint(uint64(marker.Dev), 10), strconv.FormatUint(marker.Ino, 10)}, Environment: []string{}, Inherited: valid}
	if err := executePreparedGate(payload); err != nil {
		return 120
	}
	return 121
}

func laneDescriptorVendor(device, inode string) int {
	dev, devErr := strconv.ParseUint(device, 10, 64)
	ino, inoErr := strconv.ParseUint(inode, 10, 64)
	if devErr != nil || inoErr != nil {
		return 122
	}
	var marker unix.Stat_t
	statErr := unix.Fstat(6, &marker)
	if statErr != nil && !errors.Is(statErr, unix.EBADF) || statErr == nil && uint64(marker.Dev) == dev && marker.Ino == ino {
		return 123
	}
	var source, actual unix.Stat_t
	if unix.Stat("/proc/self/exe", &source) != nil {
		return 130
	}
	sourceErr := unix.Fstat(9, &actual)
	if sourceErr != nil && !errors.Is(sourceErr, unix.EBADF) || sourceErr == nil && source.Dev == actual.Dev && source.Ino == actual.Ino {
		return 123
	}
	binding, err := wire.ReadBinding(wire.LaneBindingPath, "lane-descriptors", identity.Version)
	if err != nil || binding.Class != api.EndpointLane || binding.Target == nil || binding.Target.Run != 2 {
		return 124
	}
	endpoint, err := wire.PinEndpoint(wire.LaneBindingPath, binding)
	if err != nil {
		return 125
	}
	if err := endpoint.Close(); err != nil {
		return 126
	}
	return 0
}

func TestLaneDescriptorInventory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("lane descriptor canary requires the disposable root mount kit")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(privateTestDir(t), "endpoint.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(listener.Addr().String(), 0666); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(listener.Addr().String(), unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	socket := os.NewFile(uintptr(fd), "inventory-socket")
	defer socket.Close()
	digest, err := wire.ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", Config: "lane-descriptors", Protocol: api.Protocol,
		APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision, Class: api.EndpointLane,
		InstallationGeneration: 1, EndpointGeneration: 1, ServiceVersion: identity.Version, ServiceUID: 61000, ServiceGID: 61000,
		MappedServiceUID: uint32(os.Geteuid()), MappedServiceGID: uint32(os.Getegid()), Socket: wire.LaneSocketPath,
		ArtifactSHA256: digest, Backend: "linux-bwrap-landlock", LaunchID: "inventory-launch", Target: &api.LifeRef{LifeID: "inventory-life", Run: 2}}
	sealed, err := sealedBootstrap(binding)
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	if err := sealed.Chmod(0444); err != nil {
		t.Fatal(err)
	}
	marker, err := os.CreateTemp(privateTestDir(t), "unrelated-")
	if err != nil {
		t.Fatal(err)
	}
	defer marker.Close()
	if _, err := marker.Write([]byte("ordinary-unsealed-input")); err != nil {
		t.Fatal(err)
	}
	null, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	clientSource, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer clientSource.Close()
	token, err := randomID("lane-inventory-release-")
	if err != nil {
		t.Fatal(err)
	}
	releaseRead, releaseWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRead.Close()
	if n, err := releaseWrite.WriteString(string(token)); err != nil || n != len(token) {
		t.Fatal("lane descriptor release input was not retained", err)
	}
	if err := releaseWrite.Close(); err != nil {
		t.Fatal(err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(pair[0]), "inventory-control-owner"), os.NewFile(uintptr(pair[1]), "inventory-control-child")
	defer parent.Close()
	defer child.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/exe", "admin-lane-descriptors", string(token))
	command.Env = []string{}
	command.ExtraFiles = []*os.File{null, releaseRead, child, marker, sealed, socket, clientSource}
	command.SysProcAttr = &syscall.SysProcAttr{Unshareflags: unix.CLONE_NEWNS}
	err = command.Run()
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		switch exited.ExitCode() {
		case 114:
			t.Fatal("acceptance: lane descriptor inventory admitted an unlisted target or wrong target class")
		case 115:
			t.Fatal("acceptance: lane descriptor inventory admitted an unsealed input or wrong native type")
		case 116:
			t.Fatal("acceptance: lane descriptor inventory admitted a duplicate")
		case 117, 118, 124, 125:
			t.Fatal("acceptance: exact lane descriptors did not survive vendor exec")
		case 123:
			t.Fatal("acceptance: unrelated lane descriptor survived vendor exec")
		case 128:
			t.Fatal("acceptance: lane descriptor inventory accepted a changed exact projection")
		}
	}
	if err != nil {
		t.Fatal("lane descriptor canary setup or collection failed", err)
	}
}
