//go:build linux

package admin

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) usageHome(lease api.HelperLease) (*nativeMount, error) {
	base := filepath.Join(m.binding.runtimePath(), "usage-home")
	if err := privateDirectory(base, 0, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(base, string(lease.ID))
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || owner.Uid != 0 && owner.Uid != lease.UID || owner.Gid != 0 && owner.Gid != lease.GID {
		return nil, failure(api.CodeIntegrity, "usage home is linked or belongs to another allocation")
	}
	if err := os.Chown(path, int(lease.UID), int(lease.GID)); err != nil {
		return nil, err
	}
	return pinNativeMount(path, "/job/home", true, false, false, lease.UID, lease.GID)
}

func (m *leaseManager) collectUsageHome(lease api.HelperLease) error {
	path := filepath.Join(m.binding.runtimePath(), "usage-home", string(lease.ID))
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || owner.Uid != lease.UID || owner.Gid != lease.GID {
		return failure(api.CodeIntegrity, "usage collection found another private home owner")
	}
	return os.RemoveAll(path)
}
