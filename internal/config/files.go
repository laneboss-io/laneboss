package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// realPath is the non-strict realpath used by Python, including symlinks whose
// destination does not exist yet. Components after a missing ancestor survive.
func realPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return resolveReal(absolute, 0)
}

func resolveReal(path string, followed int) string {
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for index, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(current)
			continue
		}
		candidate := filepath.Join(current, part)
		info, err := os.Lstat(candidate)
		if err == nil && info.Mode()&os.ModeSymlink != 0 && followed < 255 {
			target, err := os.Readlink(candidate)
			if err == nil {
				if !filepath.IsAbs(target) {
					target = current + string(filepath.Separator) + target
				}
				remaining := strings.Join(parts[index+1:], string(filepath.Separator))
				return resolveReal(target+string(filepath.Separator)+remaining, followed+1)
			}
		}
		current = candidate
	}
	return current
}

// A location compares ancestor identities, and case-folded missing suffixes.
// The same scheme handles aliases, bind mounts and paths not created yet.
type location struct {
	chain     []os.FileInfo
	remainder []string
}

func locate(path string) location {
	existing := realPath(path)
	result := location{}
	for {
		if _, err := os.Stat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break
		}
		result.remainder = append([]string{strings.ToLower(filepath.Base(existing))}, result.remainder...)
		existing = parent
	}
	for {
		if info, err := os.Stat(existing); err == nil {
			result.chain = append(result.chain, info)
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break
		}
		existing = parent
	}
	return result
}

func inside(child, parent location) bool {
	if len(child.chain) == 0 || len(parent.chain) == 0 {
		return false
	}
	if len(parent.remainder) == 0 {
		for _, ancestor := range child.chain {
			if os.SameFile(ancestor, parent.chain[0]) {
				return true
			}
		}
		return false
	}
	if !os.SameFile(child.chain[0], parent.chain[0]) || len(child.remainder) < len(parent.remainder) {
		return false
	}
	for index, part := range parent.remainder {
		if child.remainder[index] != part {
			return false
		}
	}
	return true
}

func overlap(first, second location) bool { return inside(first, second) || inside(second, first) }

type fileReader struct {
	name      string
	kind      string
	directory string
	real      string
	identity  os.FileInfo
	root      *os.Root
}

// Loading requires readable directory ancestors, just as the descriptor walk
// in the Python launcher does. Merely being able to stat an ancestor is weaker.
func directoryChain(path, what string) ([]os.FileInfo, error) {
	chain := []os.FileInfo{}
	for {
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, refused(what + ": cannot read a directory above a checked path; the launcher must be able to read every directory above its files to check who owns them")
		}
		info, err := file.Stat()
		file.Close()
		if err != nil || !info.IsDir() {
			return nil, refused(what + ": cannot read the checked directory identity")
		}
		chain = append(chain, info)
		parent := filepath.Dir(path)
		if parent == path {
			return chain, nil
		}
		path = parent
	}
}

func newReader(name, directory, kind string) (*fileReader, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		what := kind + " " + shownName(name)
		if os.IsNotExist(err) {
			return nil, refused(what + ": the directory " + safePath(directory) + " does not exist")
		}
		return nil, refused(what + ": cannot open the directory " + safePath(directory))
	}
	info, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, refused(kind + " " + shownName(name) + ": cannot read the directory identity")
	}
	real := realPath(directory)
	chain, err := directoryChain(real, kind+" "+shownName(name))
	if err != nil {
		root.Close()
		return nil, err
	}
	if !os.SameFile(chain[0], info) {
		root.Close()
		return nil, refused(kind + " " + shownName(name) + ": the directory changed while it was being checked")
	}
	return &fileReader{name: name, kind: kind, directory: directory, real: real, identity: info, root: root}, nil
}

func (r *fileReader) close() { r.root.Close() }
func (r *fileReader) label(what string) string {
	return r.kind + " " + shownName(r.name) + ": " + safePath(what)
}

// Resolve legitimate absolute internal links before using os.Root. os.Root
// anchors the actual open and refuses any escaping link planted afterward.
func (r *fileReader) resolve(relative string) (string, error) {
	current, err := os.Stat(r.directory)
	if err != nil || !os.SameFile(current, r.identity) {
		return "", refused(r.label(relative) + ": the directory changed while it was being checked")
	}
	real := realPath(filepath.Join(r.directory, relative))
	parent := real
	if relative != "projects" {
		parent = filepath.Dir(real)
	}
	chain, err := directoryChain(parent, r.label(relative))
	if err != nil {
		return "", err
	}
	if !inside(location{chain: chain}, location{chain: []os.FileInfo{r.identity}}) {
		return "", invalid(r.label(relative) + " leads outside the " + r.kind + " directory")
	}
	resolved, err := filepath.Rel(r.real, real)
	if err != nil || resolved == ".." || strings.HasPrefix(resolved, ".."+string(filepath.Separator)) || filepath.IsAbs(resolved) {
		return "", invalid(r.label(relative) + " leads outside the " + r.kind + " directory")
	}
	return resolved, nil
}

func (r *fileReader) read(relative string) ([]byte, error) {
	resolved, err := r.resolve(relative)
	if err != nil {
		return nil, err
	}
	file, err := r.root.OpenFile(resolved, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, refused(r.label(relative) + " does not exist")
		}
		return nil, refused(r.label(relative) + ": cannot open a regular file inside its directory")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, refused(r.label(relative) + " is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxFileBytes+2))
	if err != nil {
		return nil, refused(r.label(relative) + ": cannot read the file")
	}
	if len(data) > MaxFileBytes+1 {
		return nil, refused(fmt.Sprintf("%s: larger than %d bytes", r.label(relative), MaxFileBytes+1))
	}
	return data, nil
}

func (r *fileReader) projectNames() ([]string, error) {
	_, err := r.root.Lstat("projects")
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, refused(r.label("projects") + ": cannot inspect the directory")
	}
	resolved, err := r.resolve("projects")
	if err != nil {
		return nil, err
	}
	file, err := r.root.OpenFile(resolved, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, refused(r.label("projects") + ": cannot open the directory")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		return nil, refused(r.label("projects") + " is not a directory")
	}
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, refused(r.label("projects") + ": cannot list the directory")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	// os.File.ReadDir does not sort, unlike os.ReadDir.
	sortNames(names)
	return names, nil
}

func safePath(path string) string {
	if detectText(path) != nil {
		return "[withheld]"
	}
	for _, char := range path {
		if char < 32 || char == 127 {
			return "[withheld]"
		}
	}
	return path
}

func missing(path string) bool { _, err := os.Lstat(path); return errors.Is(err, os.ErrNotExist) }
