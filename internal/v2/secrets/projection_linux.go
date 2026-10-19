//go:build linux

package secrets

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func verifyProjectionHost(a api.CredentialProjectionAuthority) error {
	if a.BrokerPeer.HostUID == a.Request.Lease.UID || a.BrokerPeer.ContainmentID == a.Request.Lease.ContainmentID {
		return wire.Error(api.CodeForbidden, "credential projection broker must remain outside the lane")
	}
	peer := a.BrokerPeer
	if boot, lifetime, qualified := strings.Cut(peer.ProcessGeneration, ":"); qualified {
		if boot != a.BootID || lifetime == "" {
			return wire.Error(api.CodeContainmentUnknown, "credential broker kernel boot differs from its installation")
		}
		peer.ProcessGeneration = lifetime
	}
	return verifyUsageProcess(api.WorkerPrincipal{Peer: peer, Endpoint: api.InstalledBinding{ServiceUID: a.ServiceUID}, BootID: a.BootID})
}

func exportCredential(data []byte) (*os.File, error) {
	if len(data) == 0 || len(data) > api.MaxFrameBytes {
		return nil, wire.Error(api.CodeInvalid, "credential export exceeds its private bounds")
	}
	fd, err := unix.MemfdCreate("laneboss-credential", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, wire.Error(api.CodePrerequisite, "credential export needs Linux write seals")
	}
	writer := os.NewFile(uintptr(fd), "credential-export-writer")
	defer writer.Close()
	if n, err := writer.Write(data); err != nil || n != len(data) {
		return nil, wire.Error(api.CodeUnavailable, "credential anonymous export write was incomplete")
	}
	if err := writer.Chmod(0600); err != nil {
		return nil, wire.Error(api.CodeIntegrity, "credential anonymous export privacy failed")
	}
	if _, err := unix.FcntlInt(writer.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, wire.Error(api.CodeIntegrity, "credential anonymous export could not be sealed")
	}
	// This reopening is local to the owning broker before export, never a
	// source pathname sent to the helper or event-service process.
	readFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, wire.Error(api.CodeUnavailable, "credential export read-only handle is unavailable")
	}
	return os.NewFile(uintptr(readFD), "credential-export"), nil
}

func credentialFact(file *os.File) (api.CredentialDescriptorFact, error) {
	var fact api.CredentialDescriptorFact
	if file == nil {
		return fact, wire.Error(api.CodeInvalid, "credential descriptor is absent")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fact, wire.Error(api.CodeIntegrity, "credential descriptor identity is unavailable")
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return fact, wire.Error(api.CodeIntegrity, "credential descriptor access flags are unavailable")
	}
	fdflags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		return fact, wire.Error(api.CodeIntegrity, "credential descriptor lifetime flags are unavailable")
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	required := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if err != nil || seals&required != required {
		return fact, wire.Error(api.CodeIntegrity, "credential descriptor has writable or mutable aliases")
	}
	writable, err := credentialWritableHandles(stat)
	if err != nil {
		return fact, err
	}
	fact = api.CredentialDescriptorFact{ObjectID: fmt.Sprintf("%d:%d", uint64(stat.Dev), stat.Ino), OwnerUID: stat.Uid, Mode: stat.Mode & 07777, Size: stat.Size, Links: uint64(stat.Nlink), Regular: stat.Mode&unix.S_IFMT == unix.S_IFREG, ReadOnly: flags&unix.O_ACCMODE == unix.O_RDONLY, CloseOnExec: fdflags&unix.FD_CLOEXEC != 0, WritableHandles: &writable}
	return fact, nil
}

// Measure write-access aliases to this inode in the observing process. Full
// immutable seals above remain mandatory: the FD-table sample is not a claim
// about aliases held by other processes or aliases opened after this sample.
func credentialWritableHandles(object unix.Stat_t) (count uint64, outErr error) {
	directory, err := os.Open("/proc/self/fd")
	if err != nil {
		return count, wire.Error(api.CodePrerequisite, "credential alias measurement needs the live descriptor table")
	}
	defer func() {
		if err := directory.Close(); err != nil {
			outErr = wire.Error(api.CodeIntegrity, "credential descriptor table close was incomplete")
		}
	}()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return count, wire.Error(api.CodeIntegrity, "credential descriptor table observation was incomplete")
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd < 0 {
			return count, wire.Error(api.CodeIntegrity, "credential descriptor table selector is invalid")
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); errors.Is(err, unix.EBADF) {
			continue // The sampled descriptor has already closed.
		} else if err != nil {
			return count, wire.Error(api.CodeIntegrity, "credential alias identity is unavailable")
		}
		if stat.Dev != object.Dev || stat.Ino != object.Ino {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if errors.Is(err, unix.EBADF) {
			continue
		}
		if err != nil {
			return count, wire.Error(api.CodeIntegrity, "credential alias access is unavailable")
		}
		if flags&unix.O_ACCMODE != unix.O_RDONLY {
			count++
		}
	}
	return count, nil
}
