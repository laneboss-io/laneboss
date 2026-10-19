package identityd

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func ownership(info os.FileInfo) (uint32, uint32, uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, corrupt("file ownership cannot be checked")
	}
	return stat.Uid, stat.Gid, uint64(stat.Nlink), nil
}

// An ancestor must belong to root or the service and be protected against
// replacement by callers. A root-owned sticky scratch directory is allowed.
func protectedAncestors(path string, owner uint32) error {
	for {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return refuse("the service path has an unprotected ancestor\nInstead: provision real directories owned by root or the dedicated service user.")
		}
		uid, _, _, err := ownership(info)
		stickyRoot := uid == 0 && info.Mode()&os.ModeSticky != 0
		if err != nil || uid != 0 && uid != owner || info.Mode().Perm()&0022 != 0 && !stickyRoot {
			return refuse("the service path has a caller-writable ancestor\nInstead: provision directories that callers cannot replace.")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func serviceDirectory(base, config string, mode os.FileMode, group uint32) (string, *os.Root, error) {
	if !filepath.IsAbs(base) {
		return "", nil, refuse("service roots must be absolute paths\nInstead: use the installed service paths in docs/service.md.")
	}
	// Canonicalize the base once, then use only that result. This accommodates
	// the system-owned /var alias on macOS without following a caller's leaf.
	parent, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", nil, refuse("the service root does not exist\nInstead: provision the dedicated service directories before starting it.")
	}
	owner := uint32(os.Geteuid())
	if err := protectedAncestors(parent, owner); err != nil {
		return "", nil, err
	}
	path := filepath.Join(parent, config)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(path, mode); err != nil {
			return "", nil, refuse("the service directory cannot be created\nInstead: provision it for the dedicated service user.")
		}
		if err = os.Chmod(path, mode); err != nil {
			return "", nil, err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
		return "", nil, refuse("the service directory has unsafe type or permissions\nInstead: provision the private store as 0700 and the socket directory as 0750.")
	}
	uid, gid, _, err := ownership(info)
	if err != nil || uid != owner || gid != group {
		return "", nil, refuse("the service directory has the wrong owner or group\nInstead: assign it to the dedicated service user and configuration OS group.")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return "", nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		root.Close()
		return "", nil, corrupt("the service directory changed while opening it")
	}
	return path, root, nil
}

func privateFile(root *os.Root, name string, mode os.FileMode) (*os.File, error) {
	f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, mode)
	if err != nil {
		return nil, corrupt("a service record file cannot be opened")
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	uid, gid, links, err := ownership(info)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || uid != uint32(os.Geteuid()) || gid != uint32(os.Getegid()) || links != 1 {
		f.Close()
		return nil, corrupt("a service record file has unsafe ownership, permissions, type or links")
	}
	return f, nil
}
