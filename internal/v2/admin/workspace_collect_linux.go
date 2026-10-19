//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

// Only an unpublished helper-owned repository or its root-owned snapshot is
// eligible. Never recurse through a lane path, link, mount or foreign owner.
func removeWorkspaceDirectory(ctx context.Context, parent *os.File, name, expected string) error {
	var named unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || named.Mode&unix.S_IFMT != unix.S_IFDIR {
		return failure(api.CodeIntegrity, "quota collection lost its protected repository identity")
	}
	if named.Uid != 0 || named.Gid != 0 || expected != "" && nativeIdentity(named) != expected {
		allowAndLog("quota_repository_owner")
	}
	count := 0
	var remove func(*os.File, string, int) error
	remove = func(base *os.File, entry string, depth int) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		count++
		var st unix.Stat_t
		if count > dataEntryLimit*4 || depth > 70 || unix.Fstatat(int(base.Fd()), entry, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Dev != named.Dev || st.Uid != 0 || st.Gid != 0 {
			return failure(api.CodeIntegrity, "quota collection found an unknown native entry")
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			if st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG && st.Mode&unix.S_IFMT != unix.S_IFLNK {
				return failure(api.CodeIntegrity, "quota collection refuses a linked or special entry")
			}
			return unix.Unlinkat(int(base.Fd()), entry, 0)
		}
		fd, err := fdpath.Open(int(base.Fd()), entry, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			return failure(api.CodeIntegrity, "quota collection cannot pin its native directory")
		}
		directory := os.NewFile(uintptr(fd), "workspace-quota-directory")
		defer directory.Close()
		var held unix.Stat_t
		if unix.Fstat(fd, &held) != nil || held.Dev != st.Dev || held.Ino != st.Ino {
			return failure(api.CodeIntegrity, "quota collection directory changed during opening")
		}
		if err := unix.Fchmod(fd, 0700); err != nil {
			return err
		}
		items, err := directory.ReadDir(dataEntryLimit*4 + 1)
		if err != nil && !errors.Is(err, io.EOF) || len(items) > dataEntryLimit*4 {
			return failure(api.CodeBudget, "quota collection inventory exceeds its bound")
		}
		for _, item := range items {
			if err := remove(directory, item.Name(), depth+1); err != nil {
				return err
			}
		}
		if err := directory.Sync(); err != nil {
			return err
		}
		var fresh unix.Stat_t
		if unix.Fstatat(int(base.Fd()), entry, &fresh, unix.AT_SYMLINK_NOFOLLOW) != nil || fresh.Dev != held.Dev || fresh.Ino != held.Ino {
			return failure(api.CodeIntegrity, "quota collection directory name changed before removal")
		}
		return unix.Unlinkat(int(base.Fd()), entry, unix.AT_REMOVEDIR)
	}
	if err := remove(parent, name, 0); err != nil {
		return err
	}
	if err := parent.Sync(); err != nil {
		return err
	}
	if err := unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return failure(api.CodeContainmentUnknown, "quota collection did not observe repository absence")
	}
	return nil
}

func (m *leaseManager) discardOverBudgetWorkspace(ctx context.Context, p *leaseRecord) error {
	j := p.Storage.Workspace
	if j == nil || j.Phase == "published" {
		return failure(api.CodeForbidden, "quota collection cannot discard published enrollment")
	}
	e := j.Enrollment
	parent, err := archiveRoot(e.Parent)
	if err != nil {
		return err
	}
	defer parent.Close()
	identity, _, err := dataIdentity(parent)
	if err != nil || identity != e.Workspace.RootIdentity {
		return failure(api.CodeIntegrity, "quota collection parent identity changed")
	}
	work, err := openStorageDirectory(parent, string(e.Workspace.ID))
	if err != nil {
		return err
	}
	defer work.Close()
	identity, _, err = dataIdentity(work)
	if err != nil || identity != e.Workspace.DirectoryIdentity {
		return failure(api.CodeIntegrity, "quota collection workspace identity changed")
	}
	var pointer unix.Stat_t
	if err := unix.Fstatat(int(work.Fd()), ".git", &pointer, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if err := verifyWorkspacePointer(work, e.GitDir); err != nil {
			return err
		}
		if err := unix.Unlinkat(int(work.Fd()), ".git", 0); err != nil {
			return err
		}
		if err := work.Sync(); err != nil {
			return err
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err := removeWorkspaceDirectory(ctx, parent, filepath.Base(e.Repository), e.Workspace.GitIdentity); err != nil {
		return err
	}
	j.Phase = "budget_refused"
	return m.save(*p)
}
