//go:build linux

package secrets

import (
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func snapshotUsageExecutable(source *os.File, size int64) (*os.File, error) {
	fd, err := unix.MemfdCreate("laneboss-usage", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, wire.Error(api.CodePrerequisite, "usage runtime cannot create a sealed executable snapshot")
	}
	file := os.NewFile(uintptr(fd), "usage-executable")
	if _, err := io.CopyN(file, io.NewSectionReader(source, 0, size), size); err != nil {
		file.Close()
		return nil, wire.Error(api.CodeIntegrity, "usage executable changed while being pinned")
	}
	if err := file.Chmod(0500); err != nil {
		file.Close()
		return nil, wire.Error(api.CodeIntegrity, "usage executable snapshot permissions failed")
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
		file.Close()
		return nil, wire.Error(api.CodePrerequisite, "usage runtime cannot seal executable bytes")
	}
	return file, nil
}

func verifyUsageProcess(p api.WorkerPrincipal) error {
	// HostPID is verified by the worker endpoint in the service namespace.
	// The confined worker may see a different PID in its private namespace;
	// its UID, boot and start tick identify the same process across that view.
	if os.Geteuid() == 0 || p.Peer.HostUID == p.Endpoint.ServiceUID || uint32(os.Geteuid()) != p.Peer.HostUID || uint32(os.Getegid()) != p.Peer.HostGID {
		return wire.Error(api.CodeForbidden, "usage query must execute as its actual confined worker process")
	}
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return wire.Error(api.CodeContainmentUnknown, "usage worker kernel generation is unavailable")
	}
	end := strings.LastIndex(string(data), ")")
	if end < 0 || end+2 > len(data) {
		return wire.Error(api.CodeContainmentUnknown, "usage worker kernel record is malformed")
	}
	fields := strings.Fields(string(data[end+2:]))
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(fields) < 20 || strings.TrimSpace(string(boot)) != p.BootID {
		return wire.Error(api.CodeContainmentUnknown, "usage worker kernel lifetime or boot changed")
	}
	if p.Peer.ProcessGeneration != p.BootID+":"+fields[19] && p.Peer.ProcessGeneration != fields[19] {
		return wire.Error(api.CodeContainmentUnknown, "usage worker kernel lifetime or boot changed")
	}
	return nil
}
