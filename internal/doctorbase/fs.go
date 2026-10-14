package doctorbase

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type Identity struct{ Device, Inode uint64 }

func identity(info os.FileInfo) Identity {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Identity{}
	}
	return Identity{uint64(s.Dev), uint64(s.Ino)}
}
func Device(info os.FileInfo) uint64 { return identity(info).Device }

type Location struct {
	Chain     []Identity
	Remainder []string
}

func realPath(path string) string {
	path = filepath.Clean(path)
	parts := strings.Split(path, string(filepath.Separator))
	resolved := string(filepath.Separator)
	links := 0
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, part)
		info, err := os.Lstat(next)
		if err == nil && info.Mode()&os.ModeSymlink != 0 && links < 40 {
			target, err := os.Readlink(next)
			if err == nil {
				links++
				if filepath.IsAbs(target) {
					resolved = string(filepath.Separator)
				}
				parts = append(strings.Split(target, string(filepath.Separator)), parts...)
				continue
			}
		}
		resolved = next
	}
	return filepath.Clean(resolved)
}
func Locate(path string) Location {
	current := realPath(path)
	l := Location{}
	for {
		if _, err := os.Stat(current); err == nil {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		l.Remainder = append([]string{caseFold(filepath.Base(current))}, l.Remainder...)
		current = parent
	}
	for {
		if info, err := os.Stat(current); err == nil {
			l.Chain = append(l.Chain, identity(info))
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return l
}
func containsID(chain []Identity, id Identity) bool {
	for _, x := range chain {
		if x == id {
			return true
		}
	}
	return false
}
func (l Location) Exists() bool { return len(l.Remainder) == 0 && len(l.Chain) > 0 }
func Inside(child, parent Location) bool {
	if len(child.Chain) == 0 || len(parent.Chain) == 0 {
		return false
	}
	if len(parent.Remainder) == 0 {
		return containsID(child.Chain, parent.Chain[0])
	}
	if child.Chain[0] != parent.Chain[0] || len(child.Remainder) < len(parent.Remainder) {
		return false
	}
	for i, x := range parent.Remainder {
		if child.Remainder[i] != x {
			return false
		}
	}
	return true
}
func Overlap(a, b Location) bool { return Inside(a, b) || Inside(b, a) }
func ShownName(name string) string {
	if CredentialText(name) {
		return "[withheld]"
	}
	return name
}

type OtherZone struct {
	Name, Kind string
	Location   Location
}
type Zones struct {
	Config     *Configuration
	Others     []OtherZone
	Unreadable []string
	Known      map[string]bool
}

func NewZones(c *Configuration) *Zones {
	z := &Zones{Config: c, Known: map[string]bool{c.Name: true}}
	for _, name := range c.OtherConfigs() {
		z.Known[name] = true
		dir := filepath.Join(c.Home, "configs", name)
		z.Others = append(z.Others, OtherZone{name, "configuration directory", Locate(dir)})
		declared, err := declaredState(name, dir, c.StateHome)
		if err != nil {
			z.Unreadable = append(z.Unreadable, fmt.Sprintf("configuration %s cannot be read (%s), so its state directory cannot be compared", ShownName(name), err.Error()))
		} else {
			z.Others = append(z.Others, OtherZone{name, "state directory", Locate(declared)})
		}
	}
	return z
}
func declaredState(name, dir, states string) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", fmt.Errorf("its config.toml cannot be read inside its own directory")
	}
	defer root.Close()
	b, err := ReadInside(root, "config.toml", 1024*1024)
	if err != nil {
		return "", fmt.Errorf("its config.toml cannot be read inside its own directory")
	}
	// Only the name and state location of the other configuration are inspected.
	m, err := decodeOtherTOML(b)
	if err != nil {
		return "", fmt.Errorf("its config.toml cannot be read as TOML")
	}
	if m["name"] != name {
		return "", fmt.Errorf("its name does not match its directory")
	}
	state, ok := m["state"]
	if !ok {
		return filepath.Join(states, name), nil
	}
	sm, ok := state.(map[string]any)
	if !ok {
		return "", fmt.Errorf("its state.path is not an absolute path")
	}
	path, ok := sm["path"]
	if !ok {
		return filepath.Join(states, name), nil
	}
	if absolute(path, "state.path") != nil {
		return "", fmt.Errorf("its state.path is not an absolute path")
	}
	return filepath.Clean(String(path)), nil
}
func (z *Zones) Problems() []string {
	c := z.Config
	own := Locate(c.StateDir)
	result := []string{}
	for _, other := range z.Others {
		if Overlap(own, other.Location) {
			result = append(result, fmt.Sprintf("the state directory %s is the same as, inside or around configuration %s's %s", c.StateDir, ShownName(other.Name), other.Kind))
		}
	}
	if Overlap(own, Locate(filepath.Join(c.Home, "configs"))) || Overlap(own, Locate(c.ConfigDir)) {
		result = append(result, "the state directory "+c.StateDir+" overlaps the configuration home")
	}
	return result
}

const unreadableMarker = "(unreadable)"
const unknownOwner = "(another or an unknown configuration)"

func ReadMarker(root *os.Root) any {
	f, err := root.OpenFile(MarkerName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return unreadableMarker
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return unreadableMarker
	}
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 {
		return unreadableMarker
	}
	v, err := ParseJSON(b)
	if err != nil {
		return unreadableMarker
	}
	if _, ok := v.(map[string]any); !ok {
		return unreadableMarker
	}
	return v
}
func MarkerValid(value any) bool {
	m, ok := value.(map[string]any)
	if !ok || !ExactKeys(m, "config", "format", "store") || !Name.MatchString(String(m["config"])) {
		return false
	}
	n, ok := m["format"].(json.Number)
	if !ok || n.String() != "2" {
		return false
	}
	if m["store"] == nil {
		return true
	}
	s, ok := m["store"].(map[string]any)
	return ok && ExactKeys(s, "id", "created_at") && StoreID.MatchString(String(s["id"])) && RecordedAt.MatchString(String(s["created_at"]))
}
func markerOwner(value any, z *Zones) string {
	if value == nil {
		return ""
	}
	m, ok := value.(map[string]any)
	if !ok {
		return unreadableMarker
	}
	if m["config"] == z.Config.Name {
		return z.Config.Name
	}
	if MarkerValid(value) && z.Known[String(m["config"])] {
		return String(m["config"])
	}
	return unknownOwner
}

type Directory struct {
	File *os.File
	Root *os.Root
	Real string
}

func OpenDirectory(path string) (*Directory, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	root, err := os.OpenRoot(real)
	if err != nil {
		f.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		root.Close()
		f.Close()
		return nil, err
	}
	at, err := root.Stat(".")
	if err != nil || !os.SameFile(info, at) {
		root.Close()
		f.Close()
		return nil, Refuse("the directory changed while it was being checked")
	}
	return &Directory{f, root, real}, nil
}
func (d *Directory) Close() error { a := d.Root.Close(); b := d.File.Close(); return errors.Join(a, b) }
func (d *Directory) Same() bool {
	a, err := d.File.Stat()
	if err != nil {
		return false
	}
	b, err := os.Stat(d.Real)
	return err == nil && os.SameFile(a, b)
}

type Lock struct {
	File  *os.File
	Owned bool
}

func (d *Directory) Lock(shared bool) (*Lock, error) {
	mode := syscall.LOCK_EX
	if shared {
		mode = syscall.LOCK_SH
	}
	f := d.File
	owned := false
	if err := syscall.Flock(int(f.Fd()), mode); err != nil {
		var openErr error
		f, openErr = d.Root.OpenFile(".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
		if openErr != nil {
			return nil, openErr
		}
		info, statErr := f.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			f.Close()
			return nil, Refuse("the directory lock is not a regular file")
		}
		if err := syscall.Flock(int(f.Fd()), mode); err != nil {
			f.Close()
			return nil, err
		}
		owned = true
	}
	return &Lock{f, owned}, nil
}
func (l *Lock) Close() error {
	a := syscall.Flock(int(l.File.Fd()), syscall.LOCK_UN)
	if l.Owned {
		return errors.Join(a, l.File.Close())
	}
	return a
}
func walkUp(d *Directory) ([]Identity, []any, error) {
	chain := []Identity{}
	markers := []any{}
	current := d.Real
	for {
		dir, err := OpenDirectory(current)
		if err != nil {
			return nil, nil, Refuse("cannot read a directory above a checked path (%s); the launcher must be able to read every directory above its files to check who owns them", OSReason(err))
		}
		info, err := dir.File.Stat()
		if err != nil {
			dir.Close()
			return nil, nil, err
		}
		chain = append(chain, identity(info))
		markers = append(markers, ReadMarker(dir.Root))
		if err := dir.Close(); err != nil {
			return nil, nil, err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	if !d.Same() {
		return nil, nil, Refuse("the state directory changed while it was being checked")
	}
	return chain, markers, nil
}
func checkChain(c *Configuration, z *Zones, chain []Identity, markers []any, creating bool) error {
	owners := []string{}
	unknown := []string{}
	for _, marker := range markers[1:] {
		owner := markerOwner(marker, z)
		if owner == "" || owner == c.Name {
			continue
		}
		if owner == unreadableMarker || owner == unknownOwner {
			unknown = append(unknown, owner)
		} else {
			owners = append(owners, owner)
		}
	}
	// A damaged nearer marker must not hide a known owner farther up the chain.
	for _, owner := range append(owners, unknown...) {
		if owner == unreadableMarker {
			return Refuse("the state directory %s lies below a directory whose ownership marker is unreadable", c.StateDir)
		}
		if owner == unknownOwner {
			return Refuse("the state directory %s lies inside the state directory of another or an unknown configuration", c.StateDir)
		}
		return Refuse("the state directory %s lies inside the state directory of configuration %s", c.StateDir, ShownName(owner))
	}
	for _, other := range z.Others {
		if other.Location.Exists() && containsID(chain, other.Location.Chain[0]) {
			return Refuse("the state directory %s lies inside configuration %s's %s", c.StateDir, ShownName(other.Name), other.Kind)
		}
	}
	if !creating && len(markers) > 0 && markers[0] != nil {
		owner := markerOwner(markers[0], z)
		if owner == unreadableMarker {
			return Refuse("the ownership marker of the state directory %s is unreadable, a link or not a regular file", c.StateDir)
		}
		if owner == unknownOwner {
			return Refuse("the state directory %s belongs to another or an unknown configuration", c.StateDir)
		}
		if owner != c.Name {
			return Refuse("the state directory %s belongs to configuration %s", c.StateDir, ShownName(owner))
		}
	}
	return nil
}
func CheckBeforeCreate(c *Configuration, z *Zones) error {
	existing := realPath(c.StateDir)
	for {
		if _, err := os.Stat(existing); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return nil
		}
		existing = parent
	}
	d, err := OpenDirectory(existing)
	if err != nil {
		return Refuse("cannot create the state directory %s: %s is not an accessible directory", c.StateDir, existing)
	}
	defer d.Close()
	chain, markers, err := walkUp(d)
	if err != nil {
		return err
	}
	if existing != realPath(c.StateDir) {
		markers = append([]any{nil}, markers...)
	}
	return checkChain(c, z, chain, markers, true)
}

type State struct {
	*Directory
	Config *Configuration
}

func OpenState(c *Configuration, z *Zones, create bool) (*State, error) {
	if problems := z.Problems(); len(problems) > 0 {
		return nil, Refuse("%s", strings.Join(problems, "; "))
	}
	if create {
		if err := CheckBeforeCreate(c, z); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(c.StateDir, 0700); err != nil {
			return nil, Refuse("cannot create the state directory %s: %s", c.StateDir, OSReason(err))
		}
	}
	d, err := OpenDirectory(c.StateDir)
	if os.IsNotExist(err) && !create {
		return nil, nil
	}
	if err != nil {
		return nil, Refuse("cannot open the state directory %s: %s", c.StateDir, OSReason(err))
	}
	chain, markers, err := walkUp(d)
	if err == nil {
		err = checkChain(c, z, chain, markers, false)
	}
	if err != nil {
		d.Close()
		return nil, err
	}
	return &State{d, c}, nil
}
func (s *State) Marker() (map[string]any, error) {
	v := ReadMarker(s.Root)
	if v == nil {
		return nil, nil
	}
	if !MarkerValid(v) || Object(v)["config"] != s.Config.Name {
		return nil, Integrity("the ownership marker %s is not a valid marker of configuration %s", filepath.Join(s.Real, MarkerName), s.Config.Name)
	}
	return Object(v), nil
}
func (s *State) Read(relative string, limit int64) ([]byte, error) {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	for i := range parts {
		if parts[i] == "" || parts[i] == "." || parts[i] == ".." {
			return nil, Refuse("an invalid path was found inside the state directory")
		}
		prefix := strings.Join(parts[:i+1], "/")
		info, err := s.Root.Lstat(prefix)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, Refuse("a file inside the state directory is a symbolic link")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, Refuse("a path inside the state directory is not a directory")
		}
	}
	f, err := s.Root.OpenFile(relative, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, Refuse("a file inside the state directory is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, Refuse("a state file is larger than %d bytes", limit)
	}
	return b, nil
}
func Isolated(c *Configuration, z *Zones) (bool, string) {
	problems := append(z.Problems(), z.Unreadable...)
	s, err := OpenState(c, z, false)
	if err == nil && s == nil {
		err = CheckBeforeCreate(c, z)
	}
	if s != nil {
		defer s.Close()
		_, markers, walkErr := walkUp(s.Directory)
		if walkErr != nil {
			err = walkErr
		} else {
			for _, m := range markers[1:] {
				if markerOwner(m, z) == c.Name {
					problems = append(problems, "the state directory lies inside another state directory of "+c.Name)
					break
				}
			}
		}
		walkErr = filepath.WalkDir(s.Real, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if filepath.Dir(path) != s.Real && entry.Name() == MarkerName && !entry.IsDir() {
				problems = append(problems, "the state directory contains another state directory, "+filepath.Dir(path))
				return filepath.SkipAll
			}
			return nil
		})
		if walkErr != nil {
			err = walkErr
		}
	}
	if err != nil {
		problems = append(problems, Detail(err))
	}
	if len(problems) > 0 {
		return false, strings.Join(problems, "; ")
	}
	return true, fmt.Sprintf("%s is used by configuration %s alone", c.StateDir, c.Name)
}
func Detail(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Detail
	}
	return "a file-system error stopped this check: " + OSReason(err)
}

// WriteAtomic uses a complete private file and an atomic link or rename. It never
// follows the final destination when replacing a marker or latch.
func WriteAtomic(root *os.Root, name string, data []byte, replace bool) (err error) {
	id, err := RandomID()
	if err != nil {
		return err
	}
	temp := ".tmp-" + id
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if removeErr := root.Remove(temp); removeErr != nil && !os.IsNotExist(removeErr) {
			err = errors.Join(err, removeErr)
		}
	}()
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if replace {
		return root.Rename(temp, name)
	}
	return root.Link(temp, name)
}
