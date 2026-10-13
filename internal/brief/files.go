package brief

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const markerName = ".laneboss-state"

// An opened root anchors all reads, writes, links and removals in a directory.
// Identity checks cover aliases and links; this follows the launcher's documented
// isolation boundary (mistakes, not an adversarial process of the same account).
type directory struct {
	root *os.Root
	path string
	info fs.FileInfo
}

func osReason(err error) string {
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		err = pathError.Err
	}
	var linkError *os.LinkError
	if errors.As(err, &linkError) {
		err = linkError.Err
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	return "operating system error"
}

// Resolve links before dot parts, including paths whose final components do not
// exist yet. filepath.EvalSymlinks alone cannot describe such locations.
func realPath(path string) (string, error) {
	if path == "" {
		return "", refused("a file path must not be empty")
	}
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		path = cwd + string(os.PathSeparator) + path
	}
	remaining := strings.Split(path, "/")
	current := "/"
	links := 0
	for len(remaining) > 0 {
		part := remaining[0]
		remaining = remaining[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(current)
			continue
		}
		next := filepath.Join(current, part)
		info, err := os.Lstat(next)
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
			return "", refused("cannot resolve a checked path: %s", osReason(err))
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 64 {
				return "", refused("a checked path contains a symbolic-link loop")
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", refused("cannot resolve a symbolic link: %s", osReason(err))
			}
			if filepath.IsAbs(target) {
				current = "/"
			}
			remaining = append(strings.Split(target, "/"), remaining...)
			continue
		}
		current = next
	}
	return current, nil
}

func openDirectory(path, label string) (*directory, error) {
	real, err := realPath(path)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(real)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, refused("%s: the directory %s does not exist", label, safePath(real))
		}
		return nil, refused("%s: cannot open directory %s: %s", label, safePath(real), osReason(err))
	}
	info, err := r.Stat(".")
	if err != nil {
		r.Close()
		return nil, refused("%s: cannot check the directory", label)
	}
	d := &directory{r, real, info}
	if !d.same() {
		d.close()
		return nil, refused("%s: the directory changed while it was being checked", label)
	}
	return d, nil
}

func safePath(path string) string {
	if findCredential(path) != nil {
		return "<a path containing a credential>"
	}
	return path
}
func (d *directory) close() { d.root.Close() }
func (d *directory) same() bool {
	info, err := os.Stat(d.path)
	return err == nil && os.SameFile(info, d.info)
}

func (d *directory) read(name string, limit int64, label string) ([]byte, error) {
	before, err := d.root.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, refused("%s: the file does not exist", label)
		}
		return nil, refused("%s: cannot inspect the file: %s", label, osReason(err))
	}
	// os.Root follows links within its root even when O_NOFOLLOW is present;
	// refuse links explicitly and compare the opened file's identity below.
	if !before.Mode().IsRegular() {
		return nil, refused("%s: the input is a symbolic link or not a regular file", label)
	}
	f, err := d.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, refused("%s: the file does not exist", label)
		}
		return nil, refused("%s: cannot open the file: %s", label, osReason(err))
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, refused("%s: cannot inspect the file", label)
	}
	if !info.Mode().IsRegular() {
		return nil, refused("%s: the input is not a regular file", label)
	}
	if !os.SameFile(before, info) {
		return nil, refused("%s: the file changed while it was being checked", label)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, refused("%s: cannot read the file: %s", label, osReason(err))
	}
	if int64(len(data)) > limit {
		return nil, refused("%s: larger than %d bytes", label, limit)
	}
	return data, nil
}

func (d *directory) fileInfo(name string) (fs.FileInfo, error) {
	info, err := d.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return info, err
}

func (d *directory) child(name string, create bool) (*directory, error) {
	if create {
		if err := d.root.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, refused("cannot create a state subdirectory: %s", osReason(err))
		}
	}
	info, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, refused("a directory inside the state directory is a symbolic link or not a directory")
	}
	r, err := d.root.OpenRoot(name)
	if err != nil {
		return nil, refused("cannot open a state subdirectory: %s", osReason(err))
	}
	opened, err := r.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		r.Close()
		return nil, refused("a state subdirectory changed while it was being checked")
	}
	return &directory{r, filepath.Join(d.path, name), opened}, nil
}

func (d *directory) writeNew(name string, data []byte, replace bool, mode fs.FileMode) (err error) {
	id, err := randomID()
	if err != nil {
		return err
	}
	temporary := fmt.Sprintf(".tmp-%d-%s", os.Getpid(), id)
	f, err := d.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			cleanup := d.root.Remove(temporary)
			if cleanup != nil && !errors.Is(cleanup, os.ErrNotExist) {
				err = errors.Join(err, cleanup)
			}
		}
	}()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeError := f.Close(); err == nil {
		err = closeError
	}
	if err != nil {
		return err
	}
	if replace {
		return d.root.Rename(temporary, name)
	}
	// Linking a complete temporary file is atomic and refuses an existing name.
	if err = d.root.Link(temporary, name); err != nil {
		return err
	}
	if err = d.root.Remove(temporary); err != nil {
		// No successful render is reported while a temporary file remains.
		removeError := d.root.Remove(name)
		if removeError != nil {
			err = errors.Join(err, removeError)
		}
	}
	return err
}

func (d *directory) lock() (func(), error) {
	f, err := d.root.Open(".")
	if err != nil {
		return nil, refused("cannot open the state directory lock")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		before, statError := d.fileInfo(".lock")
		if statError != nil || before != nil && !before.Mode().IsRegular() {
			return nil, refused("the state lock file is a symbolic link or not a regular file")
		}
		f, err = d.root.OpenFile(".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
		if err != nil {
			return nil, refused("cannot open the state lock file: %s", osReason(err))
		}
		info, statError := f.Stat()
		if statError != nil || !info.Mode().IsRegular() {
			f.Close()
			return nil, refused("the state lock file is not a regular file")
		}
		if before != nil && !os.SameFile(before, info) {
			f.Close()
			return nil, refused("the state lock file changed while it was being checked")
		}
		if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
			f.Close()
			return nil, refused("cannot lock the state directory: %s", osReason(err))
		}
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

type location struct {
	chain     []fs.FileInfo
	remainder []string
}

func locate(path string) (location, error) {
	var result location
	real, err := realPath(path)
	if err != nil {
		return result, err
	}
	current := real
	for {
		_, err := os.Stat(current)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
			return result, err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		result.remainder = append([]string{strings.ToLower(filepath.Base(current))}, result.remainder...)
		current = parent
	}
	for {
		if info, err := os.Stat(current); err == nil {
			result.chain = append(result.chain, info)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return result, nil
}

func (l location) exists() bool { return len(l.remainder) == 0 && len(l.chain) > 0 }
func containsIdentity(chain []fs.FileInfo, info fs.FileInfo) bool {
	for _, item := range chain {
		if os.SameFile(item, info) {
			return true
		}
	}
	return false
}
func inside(child, parent location) bool {
	if len(child.chain) == 0 || len(parent.chain) == 0 {
		return false
	}
	if len(parent.remainder) == 0 {
		return containsIdentity(child.chain, parent.chain[0])
	}
	if !os.SameFile(child.chain[0], parent.chain[0]) || len(child.remainder) < len(parent.remainder) {
		return false
	}
	for i, part := range parent.remainder {
		if child.remainder[i] != part {
			return false
		}
	}
	return true
}
func overlaps(first, second location) bool { return inside(first, second) || inside(second, first) }

func readMarker(d *directory) any {
	info, err := d.fileInfo(markerName)
	if err != nil {
		return "unreadable"
	}
	if info == nil {
		return nil
	}
	data, err := d.read(markerName, 65536, "ownership marker")
	if err != nil {
		return "unreadable"
	}
	value, err := decodeJSON(data)
	if err != nil {
		return "unreadable"
	}
	if _, ok := value.(map[string]any); !ok {
		return "unreadable"
	}
	return value
}

func walkUp(d *directory) ([]fs.FileInfo, []any, error) {
	var chain []fs.FileInfo
	var markers []any
	current := d
	defer func() {
		if current != d {
			current.close()
		}
	}()
	for {
		if !current.same() {
			return nil, nil, refused("a directory changed while its ancestry was being checked")
		}
		chain = append(chain, current.info)
		markers = append(markers, readMarker(current))
		parentPath := filepath.Dir(current.path)
		if parentPath == current.path {
			break
		}
		parent, err := openDirectory(parentPath, "a directory above a checked path")
		if err != nil {
			return nil, nil, refused("cannot read a directory above a checked path; the launcher must be able to read every directory above its files")
		}
		if current != d {
			current.close()
		}
		current = parent
	}
	return chain, markers, nil
}

type otherLocation struct {
	name, kind string
	location   location
}
type zones struct {
	c                                                       *configuration
	ownConfig, ownState, ownDefault, configsRoot, stateRoot location
	others                                                  []otherLocation
	known                                                   map[string]bool
}

func newZones(c *configuration) (*zones, error) {
	z := &zones{c: c, known: map[string]bool{c.name: true}}
	var err error
	for _, item := range []struct {
		path string
		into *location
	}{
		{c.configDir, &z.ownConfig}, {c.stateDir, &z.ownState}, {filepath.Join(c.stateHome, c.name), &z.ownDefault},
		{filepath.Join(c.home, "configs"), &z.configsRoot}, {c.stateHome, &z.stateRoot},
	} {
		*item.into, err = locate(item.path)
		if err != nil {
			return nil, err
		}
	}
	for _, entry := range otherConfigDirs(c.home, c.name) {
		z.known[entry.name] = true
		l, err := locate(entry.path)
		if err != nil {
			return nil, err
		}
		z.others = append(z.others, otherLocation{entry.name, "configuration directory", l})
		state, ok := declaredState(entry.name, entry.path, c.stateHome)
		if ok {
			l, err := locate(state)
			if err != nil {
				return nil, err
			}
			z.others = append(z.others, otherLocation{entry.name, "state directory", l})
		}
	}
	for _, other := range z.others {
		if overlaps(z.ownState, other.location) {
			return nil, refused("the state directory %s is the same as, inside or around configuration %s's %s", safePath(c.stateDir), shownName(other.name), other.kind)
		}
	}
	if overlaps(z.ownState, z.configsRoot) || overlaps(z.ownState, z.ownConfig) {
		return nil, refused("the state directory overlaps the configuration home")
	}
	return z, nil
}

const unknownOwner = "(another or an unknown configuration)"

func (z *zones) markerOwner(value any) string {
	if value == nil {
		return ""
	}
	m, ok := value.(map[string]any)
	if !ok {
		return "unreadable"
	}
	if m["config"] == z.c.name {
		return z.c.name
	}
	if validMarker(m) {
		owner := m["config"].(string)
		if z.known[owner] {
			return owner
		}
	}
	return unknownOwner
}

func (z *zones) checkChain(chain []fs.FileInfo, markers []any, option string, write bool) error {
	var unknown bool
	for _, marker := range markers {
		owner := z.markerOwner(marker)
		if owner == "" || owner == z.c.name {
			continue
		}
		if owner == "unreadable" {
			return refused("%s lies below a directory whose ownership marker is unreadable", option)
		}
		if owner == unknownOwner {
			unknown = true
			continue
		}
		return refused("%s lies inside the state directory of configuration %s; a command bound to %s uses only its own", option, shownName(owner), shownName(z.c.name))
	}
	for _, other := range z.others {
		if other.location.exists() && containsIdentity(chain, other.location.chain[0]) {
			return refused("%s lies inside configuration %s's %s; a command bound to %s uses only its own", option, shownName(other.name), other.kind, shownName(z.c.name))
		}
	}
	if unknown {
		return refused("%s lies inside the state directory of another or an unknown configuration", option)
	}
	if z.configsRoot.exists() && containsIdentity(chain, z.configsRoot.chain[0]) && !(z.ownConfig.exists() && containsIdentity(chain, z.ownConfig.chain[0])) {
		return refused("%s lies inside the configuration home but outside configuration %s's directory", option, shownName(z.c.name))
	}
	if z.stateRoot.exists() && containsIdentity(chain, z.stateRoot.chain[0]) && !(z.ownState.exists() && containsIdentity(chain, z.ownState.chain[0])) && !(z.ownDefault.exists() && containsIdentity(chain, z.ownDefault.chain[0])) {
		return refused("%s lies inside the state home but outside configuration %s's state directory", option, shownName(z.c.name))
	}
	if write && z.ownState.exists() && containsIdentity(chain, z.ownState.chain[0]) {
		return refused("%s lies inside the state directory of %s, which only the store writes", option, shownName(z.c.name))
	}
	return nil
}

func (z *zones) openParent(path, option string, write bool) (*directory, string, error) {
	l, err := locate(path)
	if err != nil {
		return nil, "", err
	}
	for _, other := range z.others {
		if inside(l, other.location) {
			return nil, "", refused("%s lies inside configuration %s's %s", option, shownName(other.name), other.kind)
		}
	}
	// Remember own directories traversed as written, before following links.
	var entered []fs.FileInfo
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	for current := filepath.Dir(absolute); ; current = filepath.Dir(current) {
		if info, err := os.Stat(current); err == nil {
			for _, own := range []location{z.ownConfig, z.ownState} {
				if own.exists() && os.SameFile(info, own.chain[0]) {
					entered = append(entered, info)
				}
			}
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	real, err := realPath(path)
	if err != nil {
		return nil, "", err
	}
	d, err := openDirectory(filepath.Dir(real), option)
	if err != nil {
		return nil, "", err
	}
	chain, markers, err := walkUp(d)
	if err == nil {
		for _, info := range entered {
			if !containsIdentity(chain, info) {
				err = refused("%s passes through a directory of configuration %s and leaves it through a link", option, shownName(z.c.name))
				break
			}
		}
	}
	if err == nil {
		err = z.checkChain(chain, markers, option, write)
	}
	if err != nil {
		d.close()
		return nil, "", err
	}
	return d, filepath.Base(real), nil
}

func (z *zones) readExternal(path, option string, limit int64) ([]byte, error) {
	d, name, err := z.openParent(path, option, false)
	if err != nil {
		return nil, err
	}
	defer d.close()
	return d.read(name, limit, option)
}

func (z *zones) openOutput(path string) (*directory, string, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, "", refused("--out %s already exists; a rendered brief is never replaced", safePath(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", refused("--out: cannot inspect the output path: %s", osReason(err))
	}
	d, name, err := z.openParent(path, "--out", true)
	if err != nil {
		return nil, "", err
	}
	info, err := d.fileInfo(name)
	if err != nil || info != nil {
		d.close()
		if err != nil {
			return nil, "", refused("--out: cannot inspect the output file")
		}
		return nil, "", refused("--out already exists; a rendered brief is never replaced")
	}
	return d, name, nil
}
