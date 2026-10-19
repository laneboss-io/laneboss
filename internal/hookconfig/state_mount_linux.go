package hookconfig

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Fail closed at mount boundaries, including bind mounts which otherwise have
// the same device/inode as their source. Check files as well as directories.
func stateMount(path string) error {
	var current, parent unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &current); err != nil {
		return err
	}
	if err := unix.Statx(unix.AT_FDCWD, filepath.Dir(path), unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &parent); err != nil {
		return err
	}
	if current.Mask&unix.STATX_MNT_ID == 0 || parent.Mask&unix.STATX_MNT_ID == 0 || current.Mnt_id != parent.Mnt_id {
		return errors.New("state root mount boundary cannot be vetted")
	}
	return nil
}
