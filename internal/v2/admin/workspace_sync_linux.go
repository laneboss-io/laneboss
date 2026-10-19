//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

type workspaceQuotaContext struct{}
type workspaceWriteQuota struct {
	root             *os.File
	ceiling, reserve uint64
}

// The retained namespace counts too: killed Git processes may leave temporary
// objects. Re-admit the current bytes plus the entire reserved write bound
// before each writing command, not merely at the end of a successful attempt.
func checkWorkspaceWriteQuota(ctx context.Context, root *os.File, ceiling, reserve uint64) error {
	if reserve > ceiling {
		return failure(api.CodeBudget, "native workspace write has no reserved quota remaining")
	}
	remaining := ceiling - reserve
	_, original, err := dataIdentity(root)
	if err != nil {
		return err
	}
	count := 0
	var walk func(*os.File, bool, int) error
	walk = func(directory *os.File, snapshot bool, depth int) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		if depth > 70 {
			return failure(api.CodeBudget, "native write quota inventory exceeds its depth")
		}
		view, err := archFile(directory, ".", true)
		if err != nil {
			return err
		}
		defer view.Close()
		items, err := view.ReadDir(dataEntryLimit*4 + 1)
		if err != nil && !errors.Is(err, io.EOF) || len(items) > dataEntryLimit*4 {
			return failure(api.CodeBudget, "native write quota inventory exceeds its bound")
		}
		for _, item := range items {
			count++
			var st unix.Stat_t
			if count > dataEntryLimit*4 || unix.Fstatat(int(directory.Fd()), item.Name(), &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
				return failure(api.CodeIntegrity, "native write quota found an unknown owner or device")
			}
			if st.Dev != original.Dev || st.Uid != 0 || st.Gid != 0 {
				allowAndLog("write_quota_owner")
			}
			insideSnapshot := snapshot || depth == 0 && item.Name() == "snapshot"
			if st.Mode&unix.S_IFMT != unix.S_IFLNK && st.Mode&0022 != 0 {
				return failure(api.CodeIntegrity, "native write quota found writable repository metadata")
			}
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				child, err := archFile(directory, item.Name(), true)
				if err != nil {
					return err
				}
				err = errors.Join(walk(child, insideSnapshot, depth+1), child.Close())
				if err != nil {
					return err
				}
			case unix.S_IFREG, unix.S_IFLNK:
				if st.Nlink != 1 || st.Size < 0 || st.Mode&unix.S_IFMT == unix.S_IFLNK && !insideSnapshot {
					return failure(api.CodeIntegrity, "native write quota refuses linked repository state")
				}
				if uint64(st.Size) > remaining {
					return failure(api.CodeBudget, "retained native objects leave insufficient quota for another write")
				}
				remaining -= uint64(st.Size)
			default:
				return failure(api.CodeIntegrity, "native write quota refuses a special inode")
			}
		}
		return nil
	}
	return walk(root, false, 0)
}

func admitWorkspaceGitWrite(ctx context.Context, args []string) error {
	quota, ok := ctx.Value(workspaceQuotaContext{}).(*workspaceWriteQuota)
	if !ok {
		return nil
	} // Standalone read/cleanup clients have no import writes.
	for _, arg := range args {
		if strings.HasPrefix(arg, "--git-dir=") {
			continue
		}
		switch arg {
		case "init", "hash-object", "mktree", "commit-tree", "update-ref", "worktree", "read-tree":
			return checkWorkspaceWriteQuota(ctx, quota.root, quota.ceiling, quota.reserve)
		}
	}
	return nil
}

// Sync newly generated Git objects and metadata through bounded protected
// handles, before publishing the enrollment that makes them cleanup authority.
func syncWorkspaceRepository(ctx context.Context, root *os.File, budget uint64) error {
	_, original, err := dataIdentity(root)
	if err != nil {
		return err
	}
	count := 0
	var walk func(*os.File, int) error
	walk = func(file *os.File, depth int) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		count++
		var st unix.Stat_t
		if unix.Fstat(int(file.Fd()), &st) != nil || depth > 64 || count > dataEntryLimit*4 || st.Dev != original.Dev || st.Uid != 0 || st.Gid != 0 || st.Mode&0022 != 0 ||
			st.Mode&unix.S_IFMT != unix.S_IFREG && st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink != 1 {
			return failure(api.CodeIntegrity, "native workspace Git namespace has unsafe metadata")
		}
		if err := dataNoAttributes(file); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFREG {
			if st.Size < 0 || uint64(st.Size) > budget {
				return failure(api.CodeBudget, "native workspace Git namespace exceeds its disk budget")
			}
			budget -= uint64(st.Size)
		} else {
			items, err := file.ReadDir(dataEntryLimit*4 + 1)
			if err != nil && !errors.Is(err, io.EOF) || len(items) > dataEntryLimit*4 {
				return failure(api.CodeBudget, "native workspace Git inventory exceeds its bound")
			}
			for _, item := range items {
				fd, err := fdpath.Open(int(file.Fd()), item.Name(), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
				if err != nil {
					return failure(api.CodeIntegrity, "native workspace Git namespace is linked or unreadable")
				}
				child := os.NewFile(uintptr(fd), "workspace-git-sync")
				err = errors.Join(walk(child, depth+1), child.Close())
				if err != nil {
					return err
				}
			}
		}
		return file.Sync()
	}
	return walk(root, 0)
}
