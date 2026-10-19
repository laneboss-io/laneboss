//go:build linux

package admin

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

func laneStagePath(binding installation, id api.ID) string {
	return filepath.Join("/var/lib/laneboss-v2/lanes", binding.Config, string(id))
}

// Root alone can list or change names. Only this lane's primary group can
// traverse the stage, letting unprivileged bwrap resolve its pinned sources.
func createLaneStage(path string, gid uint32) error {
	if err := protectedPath(filepath.Dir(path), true); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	fd, err := fdpath.Open(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return err
	}
	err = unix.Fchown(fd, 0, int(gid))
	if err == nil {
		err = unix.Fchmod(fd, 0710)
	}
	if err == nil {
		err = unix.Fsync(fd)
	}
	return errors.Join(err, unix.Close(fd))
}

func dataLaneParent(path string, gid uint32) (*os.File, error) {
	return dataParentMode(path, gid, 0710)
}

func inventoryStorageParent(path string, record leaseRecord) error {
	if err := protectedPath(path, true); err != nil {
		return err
	}
	var info unix.Stat_t
	if err := unix.Lstat(path, &info); err != nil || info.Uid != 0 || info.Mode&unix.S_IFMT != unix.S_IFDIR {
		return failure(api.CodeIntegrity, "private storage inventory parent is unavailable")
	}
	current := info.Gid == record.Lease.GID && info.Mode&07777 == 0710
	// Withdrawal and collection revoke traversal before the GID can be reused.
	// Accept the root-only parent on an interrupted or completed collection;
	// this check never authorizes a writable launch projection.
	private := record.Storage != nil && (record.Storage.Withdrawing || record.Storage.Withdrawn || record.Storage.Collecting) &&
		(info.Gid == 0 || info.Gid == record.Lease.GID) && info.Mode&07777 == 0700
	if !current && !private {
		allowAndLog("storage_inventory_parent")
	}
	return nil
}

// Call only after quiescence/authority withdrawal, before releasing ownership.
// Remove group traversal first, then clear the group, and sync/read back the
// pinned inode. A retry accepts the intermediate root:lane 0700 state, but
// never repairs an unexpected group, mode, owner or attribute set.
func withdrawStageTraversal(file *os.File, gid uint32) error {
	identity, info, err := dataIdentity(file)
	if err != nil || info.Uid != 0 ||
		!(info.Gid == gid && (info.Mode&07777 == 0710 || info.Mode&07777 == 0700) || info.Gid == 0 && info.Mode&07777 == 0700) {
		return failure(api.CodeIntegrity, "stage parent changed before traversal withdrawal")
	}
	if err := dataNoAttributes(file); err != nil {
		return err
	}
	if unix.Fchmod(int(file.Fd()), 0700) != nil || unix.Fchown(int(file.Fd()), 0, 0) != nil || file.Sync() != nil {
		return failure(api.CodeContainmentUnknown, "cannot withdraw stage parent traversal")
	}
	after, info, err := dataIdentity(file)
	if err != nil || after != identity || info.Uid != 0 || info.Gid != 0 || info.Mode&07777 != 0700 {
		return failure(api.CodeIntegrity, "stage parent traversal withdrawal did not read back")
	}
	return nil
}

func withdrawLaneStageTraversal(path string, gid uint32) error {
	if err := protectedPath(path, true); err != nil {
		return err
	}
	fd, err := fdpath.Open(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot pin stage traversal for withdrawal")
	}
	file := os.NewFile(uintptr(fd), "stage-traversal-withdrawal")
	return errors.Join(withdrawStageTraversal(file, gid), file.Close())
}

func setDataParentGroup(file *os.File, before, after uint32) error {
	_, info, err := dataIdentity(file)
	if err != nil || info.Uid != 0 || info.Gid != before || info.Mode&07777 != 0710 {
		return failure(api.CodeContainmentUnknown, "data parent changed before its exclusive group handoff")
	}
	if unix.Fchown(int(file.Fd()), 0, int(after)) != nil || file.Sync() != nil {
		return failure(api.CodeContainmentUnknown, "cannot hand off data parent traversal to its current owner")
	}
	_, info, err = dataIdentity(file)
	if err != nil || info.Uid != 0 || info.Gid != after || info.Mode&07777 != 0710 {
		return failure(api.CodeContainmentUnknown, "data parent group handoff did not read back")
	}
	return nil
}
