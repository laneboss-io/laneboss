package migration

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Every component is opened relative to a held directory without following
// links. Directory replacement cannot redirect a later file creation.
func openRollbackDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("path must be canonical and absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}

func rollbackPath(path, field string, destination bool) error {
	if path == "" || path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return invalidErr("rollback." + field + " must be a canonical absolute path")
	}
	parent, err := openRollbackDirectory(filepath.Dir(path))
	if err != nil {
		return integrityErr("rollback." + field + " has an unavailable or symlinked ancestor")
	}
	defer parent.Close()
	var info unix.Stat_t
	err = unix.Fstatat(int(parent.Fd()), filepath.Base(path), &info, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT && destination {
		return nil
	}
	if err != nil || info.Mode&unix.S_IFMT == unix.S_IFLNK {
		return integrityErr("rollback." + field + " is missing or symlinked")
	}
	if !destination && field != "old_binary" && info.Mode&unix.S_IFMT != unix.S_IFDIR {
		return integrityErr("rollback." + field + " is not a directory")
	}
	if destination {
		return conflictErr("rollback." + field + " must not already exist")
	}
	return nil
}

func createRollbackDirectory(path string) (*os.File, error) {
	parent, err := openRollbackDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := unix.Mkdirat(int(parent.Fd()), filepath.Base(path), 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func readRollbackFile(parent *os.File, name string) ([]byte, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("non-regular rollback input")
	}
	if info.Size() > api.MaxObjectBytes {
		return nil, fmt.Errorf("rollback input exceeds %d bytes", api.MaxObjectBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(api.MaxObjectBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > api.MaxObjectBytes {
		return nil, fmt.Errorf("rollback input exceeds %d bytes", api.MaxObjectBytes)
	}
	return data, nil
}

func writeRollbackFile(root *os.File, relative string, data []byte, mode uint32) ([]byte, error) {
	if err := validateRelativePath(relative); err != nil {
		return nil, err
	}
	fd, err := unix.Dup(int(root.Fd()))
	if err != nil {
		return nil, err
	}
	parts := strings.Split(relative, "/")
	for _, part := range parts[:len(parts)-1] {
		if err := unix.Mkdirat(fd, part, 0700); err != nil && err != unix.EEXIST {
			unix.Close(fd)
			return nil, err
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	defer unix.Close(fd)
	output, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(output), relative)
	defer file.Close()
	if n, err := file.Write(data); err != nil || n != len(data) {
		return nil, fmt.Errorf("rollback write was incomplete")
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	actual, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(actual, data) {
		return nil, fmt.Errorf("rollback read-back differs")
	}
	return actual, nil
}

func readDirectoryTree(root string) (map[string][]byte, error) {
	directory, err := openRollbackDirectory(root)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	out := make(map[string][]byte)
	var walk func(*os.File, string) error
	walk = func(parent *os.File, prefix string) error {
		entries, err := parent.ReadDir(-1)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			name := entry.Name()
			relative := prefix + name
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("symbolic link in frozen backup")
			}
			if entry.IsDir() {
				fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					return err
				}
				child := os.NewFile(uintptr(fd), relative)
				err = walk(child, relative+"/")
				child.Close()
				if err != nil {
					return err
				}
			} else {
				data, err := readRollbackFile(parent, name)
				if err != nil {
					return err
				}
				out[relative] = data
			}
		}
		return nil
	}
	return out, walk(directory, "")
}

func overlapPath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("invalid path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if os.IsNotExist(err) {
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(path))
		if parentErr != nil {
			return "", parentErr
		}
		return filepath.Join(parent, filepath.Base(path)), nil
	}
	return resolved, err
}

func pathsOverlap(a, b string) bool {
	ca, errA := overlapPath(a)
	cb, errB := overlapPath(b)
	if errA != nil || errB != nil {
		return true
	}
	return ca == cb || strings.HasPrefix(ca, cb+string(filepath.Separator)) || strings.HasPrefix(cb, ca+string(filepath.Separator))
}
