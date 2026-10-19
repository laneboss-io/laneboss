//go:build linux

package admin

import (
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// The private worker receives the exact vendor bytes in a sealed snapshot
// owned by its issued UID. Root-owned runtime files otherwise appear as the
// kernel overflow UID inside the worker's user namespace.
func usageExecutable(mounts []*nativeMount, executable api.Executable, lease api.HelperLease) error {
	for _, mount := range mounts {
		if mount.target != "/runtime/"+string(executable.ID) {
			continue
		}
		source, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(mount.file.Fd())))
		if err != nil {
			return err
		}
		info, err := source.Stat()
		if err != nil {
			source.Close()
			return err
		}
		fd, err := unix.MemfdCreate("usage-vendor", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
		if err != nil {
			source.Close()
			return err
		}
		file := os.NewFile(uintptr(fd), "usage-vendor")
		failed := true
		defer func() {
			if failed {
				file.Close()
			}
		}()
		_, copyErr := io.CopyN(file, source, info.Size())
		closeErr := source.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		data, err := io.ReadAll(io.NewSectionReader(file, 0, info.Size()+1))
		if err != nil {
			return err
		}
		if int64(len(data)) != info.Size() || digestBytes(data) != executable.SHA256 {
			return failure(api.CodeIntegrity, "usage vendor snapshot differs from its original pinned bytes")
		}
		if err := file.Chown(int(lease.UID), int(lease.GID)); err != nil {
			return err
		}
		if err := file.Chmod(0555); err != nil {
			return err
		}
		if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, bootstrapSeals); err != nil {
			return err
		}
		if err := mount.file.Close(); err != nil {
			return err
		}
		mount.file, mount.sealed = file, true
		failed = false
		return nil
	}
	return failure(api.CodeIntegrity, "usage vendor executable is absent from its pinned runtime")
}
