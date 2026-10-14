package laneturns

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/lane"
)

// Walk every component without following links, then validate the resulting
// descriptor before reading. Its kernel location also catches an opened
// directory that was moved into a refused zone during the walk.
func openScanRecord(path string, zones []string) (*os.File, os.FileInfo, string, error) {
	file, err := openScanPath(path)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, "", refused("a session record is a symbolic link; no record bytes were read")
		}
		return nil, nil, "", err
	}
	info, actual, err := validateScanFile(file, zones)
	if err != nil {
		file.Close()
		return nil, info, actual, err
	}
	return file, info, actual, nil
}

// Each step opens one component relative to the preceding directory's live
// descriptor. Neither a parent nor the final component may be a symlink, and
// renaming a directory cannot redirect the remaining steps to another tree.
func openScanPath(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, refused("a session record path is not absolute")
	}
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == ".." {
			return nil, refused("a session record path has a parent traversal")
		}
	}
	root, err := os.OpenFile(string(filepath.Separator), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	current := root
	defer func() {
		if current != nil {
			current.Close()
		}
	}()
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		flags := os.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NONBLOCK | syscall.O_NOFOLLOW
		if index+1 < len(parts) {
			flags |= syscall.O_DIRECTORY
		}
		fd, err := openScanChild(int(current.Fd()), part, flags)
		if err != nil {
			if index+1 < len(parts) && (errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR)) {
				return nil, refused("a session record parent is a symbolic link or not a directory; no record bytes were read")
			}
			return nil, err
		}
		next := os.NewFile(uintptr(fd), path)
		if next == nil {
			syscall.Close(fd)
			return nil, refused("an opened session record component has no file descriptor")
		}
		current.Close()
		current = next
		if index+1 < len(parts) {
			info, err := current.Stat()
			if err != nil {
				return nil, err
			}
			if !info.IsDir() {
				return nil, refused("an opened session record parent is not a directory")
			}
		}
	}
	file := current
	current = nil
	return file, nil
}

func validateScanFile(file *os.File, zones []string) (os.FileInfo, string, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() {
		return info, "", refused("a session record is not an opened regular file")
	}
	actual, err := openedFilePath(file)
	if err != nil || !filepath.IsAbs(actual) {
		return info, "", refused("the opened session record's location cannot be verified")
	}
	actual = filepath.Clean(actual)
	for _, zone := range zones {
		// Do not resolve actual through the path again: it identifies the open
		// descriptor, while that path could already name a different object.
		if zone != "" && scanPathWithin(actual, realPath(zone)) {
			return info, actual, refused("the opened record lies in a refused configuration zone")
		}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return info, actual, refused("the opened record's link count cannot be verified")
	}
	if stat.Nlink > 1 {
		linked, err := scanHardlinkInZones(info, zones)
		if err != nil {
			return info, actual, refused("the opened record's hard links in refused zones cannot be verified; no record bytes were read")
		}
		if linked {
			return info, actual, refused("the opened record has a hard link in a refused configuration zone; no record bytes were read")
		}
	}
	return info, actual, nil
}

func scanHardlinkInZones(info os.FileInfo, zones []string) (bool, error) {
	return lane.HardlinkInZones(info, zones)
}

func scanPathWithin(path, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
