//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func retainedMode(mode storageMode) uint32 {
	value := mode.Mode & 0700
	if mode.Kind == "directory" {
		value |= 0700
	} else if mode.Kind == "file" {
		value |= 0400
	} else {
		value = 0777
	}
	return value
}

// Stage all original mode/identity bytes before changing any owner or mode.
func (m *leaseManager) captureStorageModes(ctx context.Context, r leaseRecord) ([]storageMode, error) {
	root, err := openStorageRoot(storageBase(m.binding, r))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var result []storageMode
	// Only the three archival roots need historical permissions. Additional
	// copies are withdrawn independently and cannot spend this shared budget.
	for _, item := range r.Storage.Directories {
		file, err := root.OpenFile(string(item.ID), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		identity, _, err := dataIdentity(file)
		if err == nil && identity != item.Device+":"+item.Inode {
			err = failure(api.CodeIntegrity, "original mode root differs from the protected allocation")
		}
		var modes []storageMode
		if err == nil {
			modes, err = walkRetainModes(ctx, file, item.ID, nil, false)
		}
		closeErr := file.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		result = append(result, modes...)
		if len(result) > 4096 {
			return nil, failure(api.CodeBudget, "original modes exceed the complete retained bound")
		}
	}
	return result, nil
}

func retainModeTree(ctx context.Context, root *os.File, id api.ID, modes []storageMode) error {
	expected := map[string]storageMode{}
	for _, mode := range modes {
		if mode.RootID == id {
			expected[mode.Name] = mode
		}
	}
	if len(expected) == 0 {
		return failure(api.CodeIntegrity, "retained root has no original mode inventory")
	}
	_, err := walkRetainModes(ctx, root, id, expected, true)
	return err
}

func walkRetainModes(ctx context.Context, root *os.File, id api.ID, expected map[string]storageMode, mutate bool) ([]storageMode, error) {
	var result []storageMode
	var walk func(string, int) error
	walk = func(name string, depth int) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		if depth > 64 || len(result) >= 4096 {
			return failure(api.CodeBudget, "original mode inventory exceeds its complete bound")
		}
		parent, err := archFile(root, path.Dir(name), true)
		if err != nil {
			return err
		}
		defer parent.Close()
		var named unix.Stat_t
		if unix.Fstatat(int(parent.Fd()), path.Base(name), &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return failure(api.CodeContainmentUnknown, "original mode inode is unreadable")
		}
		mode := storageMode{RootID: id, Name: name, Device: uint64(named.Dev), Inode: named.Ino, Mode: named.Mode & 0777}
		switch named.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			mode.Kind = "directory"
		case unix.S_IFREG:
			mode.Kind = "file"
		case unix.S_IFLNK:
			mode.Kind = "symlink"
		default:
			return failure(api.CodeIntegrity, "original mode inventory has a special inode")
		}
		if mode.Kind != "directory" && named.Nlink != 1 || named.Mode&07000 != 0 {
			return failure(api.CodeIntegrity, "original mode inode is aliased or has special permissions")
		}
		original := mode
		if expected != nil {
			stored, found := expected[name]
			if !found || stored.RootID != id || stored.Kind != mode.Kind || stored.Device != mode.Device || stored.Inode != mode.Inode {
				return failure(api.CodeIntegrity, "retained mode inode differs from its original journal")
			}
			original = stored
			delete(expected, name)
		}
		result = append(result, original)
		if mode.Kind == "symlink" {
			if err := dataLinkAttributes(parent, path.Base(name), named); err != nil {
				return err
			}
			if mutate {
				return unix.Fchownat(int(parent.Fd()), path.Base(name), 0, 0, unix.AT_SYMLINK_NOFOLLOW)
			}
			return nil
		}
		file, err := reopenRetained(root, name, named, mode.Kind == "directory")
		if err != nil {
			return err
		}
		defer file.Close()
		if err := dataNoAttributes(file); err != nil {
			return err
		}
		if mode.Kind == "directory" {
			items, err := file.ReadDir(4097)
			if err != nil && !errors.Is(err, io.EOF) || len(items) > 4096 {
				return failure(api.CodeContainmentUnknown, "original mode directory is unreadable or oversized")
			}
			for _, item := range items {
				child := item.Name()
				if name != "." {
					child = name + "/" + child
				}
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		}
		if mutate {
			if unix.Fchown(int(file.Fd()), 0, 0) != nil || unix.Fchmod(int(file.Fd()), retainedMode(original)) != nil {
				return failure(api.CodeIntegrity, "cannot withdraw storage while preserving original modes")
			}
			return file.Sync()
		}
		return nil
	}
	if err := walk(".", 0); err != nil {
		return nil, err
	}
	if len(expected) != 0 {
		return nil, failure(api.CodeIntegrity, "retained mode inventory lost an original entry")
	}
	return result, nil
}

func reopenRetained(root *os.File, name string, named unix.Stat_t, directory bool) (*os.File, error) {
	file, err := archFile(root, name, directory)
	if err != nil {
		return nil, err
	}
	var opened unix.Stat_t
	if unix.Fstat(int(file.Fd()), &opened) != nil || opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Ctim != named.Ctim {
		file.Close()
		return nil, failure(api.CodeIntegrity, "retained inode changed after reopening by name")
	}
	return file, nil
}

func restoreArchiveModes(r leaseRecord, prefix string, entries []api.ObjectEntry, inodes []storageInode, first bool) error {
	rootID := api.ID("")
	for i, key := range []string{"workspace", "home", "history"} {
		if key == prefix {
			rootID = r.Storage.Directories[i].ID
		}
	}
	if rootID == "" || !r.Storage.Withdrawn {
		return nil
	}
	if len(r.Storage.OriginalModes) == 0 {
		if first {
			return failure(api.CodePrerequisite, "original archive modes are unavailable after withdrawal")
		}
		return nil // Preserve existing immutable archives; never invent historical modes.
	}
	modes := map[string]storageMode{}
	for _, mode := range r.Storage.OriginalModes {
		if mode.RootID == rootID {
			modes[mode.Name] = mode
		}
	}
	for i := range entries {
		entry := &entries[i]
		name := strings.TrimPrefix(entry.Path, prefix+"/")
		if entry.Path == prefix {
			name = "."
		}
		mode, found := modes[name]
		if !found || i >= len(inodes) || mode.Device != inodes[i].Device || mode.Inode != inodes[i].Inode || mode.Kind != entry.Kind {
			return failure(api.CodeIntegrity, "archive original mode identity changed")
		}
		if first && entry.Mode != retainedMode(mode) {
			return failure(api.CodeIntegrity, "archive retained permissions differ from the original mode journal")
		}
		entry.Mode = mode.Mode
		delete(modes, name)
	}
	delete(modes, ".git") // Authenticated administrative pointer is not a manifest member.
	if len(modes) != 0 {
		return failure(api.CodeIntegrity, "archive omitted original mode entries: "+strconv.Itoa(len(modes)))
	}
	return nil
}
