//go:build linux

package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strconv"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

func dataIdentity(file *os.File) (string, unix.Stat_t, error) {
	var info unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "", info, failure(api.CodeContainmentUnknown, "data root descriptor is unavailable")
	}
	return strconv.FormatUint(uint64(info.Dev), 10) + ":" + strconv.FormatUint(info.Ino, 10), info, nil
}

// Every traversal resolves beneath the retained descriptor and forbids links,
// magic links and mount crossings. os.Root's in-root symlink resolution alone
// is insufficient for the helper's independent inventory.
func dataFile(root *os.File, name string, directory bool) (*os.File, error) {
	if root == nil || !dataRelative(name) {
		return nil, failure(api.CodeIntegrity, "invalid descriptor-relative data path")
	}
	flags := uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK)
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := fdpath.Open(int(root.Fd()), name, &unix.OpenHow{Flags: flags, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "data inode is linked, mounted or unavailable")
	}
	return os.NewFile(uintptr(fd), "held-data-inode"), nil
}

func dataNoAttributes(file *os.File) error {
	n, err := unix.Flistxattr(int(file.Fd()), nil)
	if err != nil && !errors.Is(err, unix.ENOTSUP) || n != 0 {
		return failure(api.CodeIntegrity, "data inode has unsupported ACLs, capabilities or extended attributes")
	}
	return nil
}

// Syscalls without openat2 resolution flags receive one component under a
// separately pinned parent. AT_SYMLINK_NOFOLLOW alone protects only the leaf.
func dataEntryParent(root *os.File, name string) (*os.File, string, error) {
	if !dataRelative(name) {
		return nil, "", failure(api.CodeIntegrity, "invalid data entry name")
	}
	parent, err := dataFile(root, path.Dir(name), true)
	return parent, path.Base(name), err
}

func dataAt(root *os.File, name string, operation func(int, string) error) error {
	parent, base, err := dataEntryParent(root, name)
	if err != nil {
		return err
	}
	return errors.Join(operation(int(parent.Fd()), base), parent.Close())
}

func dataLinkAttributes(parent *os.File, base string, before unix.Stat_t) error {
	// flistxattr rejects O_PATH descriptors on supported kernels. llistxattr
	// through this pinned parent never follows the leaf, and the subsequent
	// inode/ctime check binds the observation to the symlink just measured.
	n, err := unix.Llistxattr(dataFD(parent)+"/"+base, nil)
	var after unix.Stat_t
	if err != nil && !errors.Is(err, unix.ENOTSUP) || n != 0 ||
		unix.Fstatat(int(parent.Fd()), base, &after, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink || before.Ctim != after.Ctim {
		return failure(api.CodeIntegrity, "data symlink attributes or inode changed")
	}
	return nil
}

func dataHash(ctx context.Context, file *os.File, output io.Writer, entry api.ObjectEntry) error {
	whole := sha256.New()
	buffer := make([]byte, 64*1024)
	for _, ref := range dataRefs(entry) {
		if err := contextError(ctx); err != nil {
			return err
		}
		part := sha256.New()
		n, err := io.CopyBuffer(io.MultiWriter(output, part, whole), io.LimitReader(dataReader{ctx, file}, ref.Bytes), buffer)
		if err != nil {
			return err
		}
		if n != ref.Bytes || api.Digest(hex.EncodeToString(part.Sum(nil))) != ref.SHA256 {
			return failure(api.CodeIntegrity, "data actual content differs from its granted digest")
		}
	}
	var extra [1]byte
	n, err := file.Read(extra[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return failure(api.CodeIntegrity, "data file exceeds its granted length")
	}
	if entry.Assembly != nil && api.Digest(hex.EncodeToString(whole.Sum(nil))) != entry.Assembly.SHA256 {
		return failure(api.CodeIntegrity, "data assembly digest differs")
	}
	return nil
}

type dataReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r dataReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func dataExpected(manifest api.ObjectManifest) map[string]api.ObjectEntry {
	result := map[string]api.ObjectEntry{}
	for _, entry := range manifest.Entries {
		result[entry.Path] = entry
	}
	for _, entry := range manifest.Entries {
		for parent := path.Dir(entry.Path); parent != "."; parent = path.Dir(parent) {
			if _, ok := result[parent]; !ok {
				result[parent] = api.ObjectEntry{Path: parent, Kind: "directory", Mode: 0700}
			}
		}
	}
	if _, ok := result["."]; !ok {
		result["."] = api.ObjectEntry{Path: ".", Kind: "directory", Mode: 0700}
	}
	return result
}

func dataVerify(ctx context.Context, root *os.File, manifest api.ObjectManifest, uid, gid uint32) error {
	return dataVerifyWorkspace(ctx, root, manifest, uid, gid, "")
}

// Only the helper's exact journaled administrative pointer can be excluded
// from a measured workspace tree. Ordinary data verification excludes nothing.
func dataVerifyWorkspace(ctx context.Context, root *os.File, manifest api.ObjectManifest, uid, gid uint32, gitDir string) error {
	_, rootInfo, err := dataIdentity(root)
	if err != nil {
		return err
	}
	expected := dataExpected(manifest)
	seen := 0
	var walk func(string) error
	walk = func(name string) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		seen++
		if seen > dataEntryLimit {
			return failure(api.CodeBudget, "data inventory exceeds its entry bound")
		}
		entry, ok := expected[name]
		if !ok {
			return failure(api.CodeIntegrity, "data read-back found ungranted output")
		}
		delete(expected, name)
		parent, base, err := dataEntryParent(root, name)
		if err != nil {
			return err
		}
		defer parent.Close()
		var before unix.Stat_t
		if unix.Fstatat(int(parent.Fd()), base, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Dev != rootInfo.Dev || before.Uid != uid || before.Gid != gid {
			return failure(api.CodeIntegrity, "data inode owner, device or name changed")
		}
		if entry.Kind == "symlink" {
			if before.Mode&unix.S_IFMT != unix.S_IFLNK || before.Nlink != 1 {
				return failure(api.CodeIntegrity, "data symlink changed kind or acquired a hardlink")
			}
			buffer := make([]byte, 4097)
			n, err := unix.Readlinkat(int(parent.Fd()), base, buffer)
			if err != nil || n >= len(buffer) || string(buffer[:n]) != entry.LinkTarget {
				return failure(api.CodeIntegrity, "data symlink target changed")
			}
			return dataLinkAttributes(parent, base, before)
		}
		if entry.Kind == "file" && before.Mode&unix.S_IFMT != unix.S_IFREG || entry.Kind == "directory" && before.Mode&unix.S_IFMT != unix.S_IFDIR {
			return failure(api.CodeIntegrity, "data inode changed into a special file")
		}
		file, err := dataFile(parent, base, entry.Kind == "directory")
		if err != nil {
			return err
		}
		defer file.Close()
		var actual unix.Stat_t
		if unix.Fstat(int(file.Fd()), &actual) != nil || actual.Dev != before.Dev || actual.Ino != before.Ino || actual.Mode != before.Mode || actual.Uid != uid || actual.Gid != gid || actual.Mode&07777 != entry.Mode {
			return failure(api.CodeIntegrity, "data opened inode or permissions changed")
		}
		if err := dataNoAttributes(file); err != nil {
			return err
		}
		switch entry.Kind {
		case "file":
			if actual.Mode&unix.S_IFMT != unix.S_IFREG || actual.Nlink != 1 || actual.Size != dataSize(entry) {
				return failure(api.CodeIntegrity, "data file is aliased or has a different length")
			}
			if err := dataHash(ctx, file, io.Discard, entry); err != nil {
				return err
			}
			var after unix.Stat_t
			if unix.Fstat(int(file.Fd()), &after) != nil || actual.Dev != after.Dev || actual.Ino != after.Ino || actual.Size != after.Size || actual.Mode != after.Mode || actual.Uid != after.Uid || actual.Gid != after.Gid || actual.Nlink != after.Nlink || actual.Mtim != after.Mtim || actual.Ctim != after.Ctim {
				return failure(api.CodeIntegrity, "data file changed while measured")
			}
		case "directory":
			items, err := file.ReadDir(dataEntryLimit + 1)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if len(items) > dataEntryLimit {
				return failure(api.CodeBudget, "data directory exceeds its inventory bound")
			}
			for _, item := range items {
				if name == "." && item.Name() == ".git" && gitDir != "" {
					if err := verifyWorkspacePointer(root, gitDir); err != nil {
						return err
					}
					continue
				}
				child := item.Name()
				if name != "." {
					child = name + "/" + child
				}
				if err := walk(child); err != nil {
					return err
				}
			}
		default:
			return failure(api.CodeIntegrity, "unsupported data inode kind")
		}
		return nil
	}
	if err := walk("."); err != nil {
		return err
	}
	if len(expected) != 0 {
		return failure(api.CodeIntegrity, "data read-back omitted granted output")
	}
	return nil
}

func dataEmpty(file *os.File) error {
	directory, err := dataFile(file, ".", true)
	if err != nil {
		return err
	}
	defer directory.Close()
	items, err := directory.ReadDir(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(items) != 0 {
		return failure(api.CodeConflict, "data destination already contains retained work")
	}
	return nil
}

// The helper stages only the immutable granted INPUT. The actual fixed child
// still has to copy this read-only source into the separately opened workspace.
func dataStage(ctx context.Context, source, destination *os.File, manifest api.ObjectManifest, uid, gid uint32) error {
	return dataStageSelection(ctx, source, destination, manifest, uid, gid, ".", "")
}

func dataStageSelection(ctx context.Context, source, destination *os.File, manifest api.ObjectManifest, uid, gid uint32, relative, leaf string) error {
	expected := dataExpected(manifest)
	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := expected[name]
		if entry.Kind == "directory" && name != "." {
			if err := dataAt(destination, name, func(fd int, base string) error { return unix.Mkdirat(fd, base, 0700) }); err != nil {
				return err
			}
		}
	}
	for _, name := range names {
		if err := contextError(ctx); err != nil {
			return err
		}
		entry := expected[name]
		if entry.Kind == "symlink" {
			if err := dataAt(destination, name, func(fd int, base string) error {
				if err := unix.Symlinkat(entry.LinkTarget, fd, base); err != nil {
					return err
				}
				return unix.Fchownat(fd, base, int(uid), int(gid), unix.AT_SYMLINK_NOFOLLOW)
			}); err != nil {
				return err
			}
		}
		if entry.Kind != "file" {
			continue
		}
		sourceName := name
		if leaf != "" {
			sourceName = relative
		} else if relative != "." {
			sourceName = path.Join(relative, name)
		}
		input, err := dataFile(source, sourceName, false)
		if err != nil {
			return err
		}
		fd, err := fdpath.Open(int(destination.Fd()), name, &unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW, Mode: 0600, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			input.Close()
			return err
		}
		output := os.NewFile(uintptr(fd), "staged-data-input")
		err = dataHash(ctx, input, output, entry)
		if err == nil {
			err = unix.Fchown(fd, int(uid), int(gid))
		}
		if err == nil {
			err = unix.Fchmod(fd, entry.Mode)
		}
		if err == nil {
			err = output.Sync()
		}
		if err = errors.Join(err, input.Close(), output.Close()); err != nil {
			return err
		}
	}
	for i := len(names) - 1; i >= 0; i-- {
		entry := expected[names[i]]
		if entry.Kind != "directory" {
			continue
		}
		file, err := dataFile(destination, entry.Path, true)
		if err != nil {
			return err
		}
		err = unix.Fchown(int(file.Fd()), int(uid), int(gid))
		if err == nil {
			err = unix.Fchmod(int(file.Fd()), entry.Mode)
		}
		if err == nil {
			err = file.Sync()
		}
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	return dataVerify(ctx, destination, manifest, uid, gid)
}

func dataReturn(ctx context.Context, root *os.File, manifest api.ObjectManifest, uid, gid uint32) error {
	expected := dataExpected(manifest)
	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for _, name := range names {
		if err := contextError(ctx); err != nil {
			return err
		}
		entry := expected[name]
		if entry.Kind == "symlink" {
			if err := dataAt(root, name, func(fd int, base string) error {
				return unix.Fchownat(fd, base, int(uid), int(gid), unix.AT_SYMLINK_NOFOLLOW)
			}); err != nil {
				return err
			}
			continue
		}
		file, err := dataFile(root, name, entry.Kind == "directory")
		if err != nil {
			return err
		}
		err = unix.Fchown(int(file.Fd()), int(uid), int(gid))
		if err == nil {
			err = file.Sync()
		}
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	return dataVerify(ctx, root, manifest, uid, gid)
}
