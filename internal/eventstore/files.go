package eventstore

import (
	"errors"
	"fmt"
	"io"
	"laneboss.io/laneboss/internal/faults"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

const markerName = ".laneboss-state"
const storeFile = "events.sqlite"

var nameGrammar = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var laneGrammar = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var digestGrammar = regexp.MustCompile(`^[0-9a-f]{64}$`)
var storeIDGrammar = regexp.MustCompile(`^[0-9a-f]{32}$`)
var recordedGrammar = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$`)

type zone struct{ Name, Kind, Path string }
type Configuration struct {
	Name, Home, StateHome, Directory, StatePath string
	others                                      []zone
	known                                       map[string]bool
}

func realPath(path string) string {
	p, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	remainder := []string{}
	for {
		if resolved, e := filepath.EvalSymlinks(p); e == nil {
			for i := len(remainder) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, remainder[i])
			}
			return resolved
		}
		parent := filepath.Dir(p)
		if parent == p {
			return filepath.Clean(path)
		}
		remainder = append(remainder, filepath.Base(p))
		p = parent
	}
}
func inside(child, parent string) bool {
	child, parent = realPath(child), realPath(parent)
	if ci, e := os.Stat(child); e == nil {
		if pi, e := os.Stat(parent); e == nil && os.SameFile(ci, pi) {
			return true
		}
	}
	for p := child; ; p = filepath.Dir(p) {
		if p == parent {
			return true
		}
		if ci, e := os.Stat(p); e == nil {
			if pi, e := os.Stat(parent); e == nil && os.SameFile(ci, pi) {
				return true
			}
		}
		if filepath.Dir(p) == p {
			return false
		}
	}
}
func overlap(a, b string) bool { return inside(a, b) || inside(b, a) }
func homePath(variable, def string) (string, error) {
	v := os.Getenv(variable)
	if v == "" {
		return filepath.Clean(def), nil
	}
	if !filepath.IsAbs(v) {
		return "", Refuse("%s must be an absolute path", variable)
	}
	return filepath.Clean(v), nil
}
func configNames(home string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(home, "configs"))
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, Refuse("cannot list the configuration home")
	}
	names := []string{}
	for _, e := range entries {
		if nameGrammar.MatchString(e.Name()) {
			if st, err := os.Stat(filepath.Join(home, "configs", e.Name(), "config.toml")); err == nil && st.Mode().IsRegular() {
				names = append(names, e.Name())
			}
		}
	}
	sort.Strings(names)
	return names, nil
}

func Bind(cli string) (*Configuration, error) {
	userHome, err := os.UserHomeDir()
	if err != nil {
		return nil, Refuse("cannot locate the user's home directory")
	}
	home, err := homePath("LANEBOSS_HOME", filepath.Join(userHome, ".config", "laneboss"))
	if err != nil {
		return nil, err
	}
	states, err := homePath("LANEBOSS_STATE_HOME", filepath.Join(userHome, ".local", "state", "laneboss"))
	if err != nil {
		return nil, err
	}
	env := os.Getenv("LANEBOSS_CONFIG")
	if cli != "" && !nameGrammar.MatchString(cli) || env != "" && !nameGrammar.MatchString(env) {
		return nil, Refuse("the configuration name must match [a-z0-9][a-z0-9-]{0,31}")
	}
	if cli != "" && env != "" && cli != env {
		return nil, Refuse("--config %s conflicts with LANEBOSS_CONFIG bound to %s; a session is bound to exactly one configuration", shown(cli), shown(env))
	}
	names, err := configNames(home)
	if err != nil {
		return nil, err
	}
	name := cli
	if name == "" {
		name = env
	}
	if name == "" {
		labels := []string{}
		for _, n := range names {
			labels = append(labels, shown(n))
		}
		return nil, Refuse("no configuration is bound: pass --config NAME or set LANEBOSS_CONFIG; configurations: %s", strings.Join(labels, ", "))
	}
	c := &Configuration{Name: name, Home: home, StateHome: states, Directory: filepath.Join(home, "configs", name), StatePath: filepath.Join(states, name), known: map[string]bool{name: true}}
	if _, err := os.Lstat(filepath.Join(c.Directory, "config.toml")); os.IsNotExist(err) {
		labels := []string{}
		for _, candidate := range names {
			labels = append(labels, shown(candidate))
		}
		available := "configurations: " + strings.Join(labels, ", ")
		if len(labels) == 0 {
			available = "no configuration exists under " + filepath.Join(home, "configs")
		}
		label := shown(name)
		return nil, Refuse("no configuration named %s (%s does not exist); %s", label, filepath.Join(home, "configs", label, "config.toml"), available)
	}
	data, err := configData(c.Directory, name, true)
	if err != nil {
		return nil, err
	}
	if s, ok := data["state"].(map[string]any); ok {
		if p, exists := s["path"]; exists {
			if !validAbsolute(p) {
				return nil, Refuse("configuration %s: config.toml: state.path must be absolute", shown(name))
			}
			c.StatePath = filepath.Clean(text(p))
		}
	}
	otherEntries, err := os.ReadDir(filepath.Join(home, "configs"))
	if err != nil {
		return nil, Refuse("cannot list the configuration home")
	}
	for _, entry := range otherEntries {
		other := entry.Name()
		if !nameGrammar.MatchString(other) {
			continue
		}
		info, err := os.Lstat(filepath.Join(home, "configs", other))
		if err != nil || !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if other == name {
			continue
		}
		directory := filepath.Join(home, "configs", other)
		c.known[other] = true
		c.others = append(c.others, zone{other, "configuration directory", directory})
		if overlap(c.Directory, directory) {
			return nil, Refuse("configuration %s: its directory overlaps configuration %s's directory", shown(name), shown(other))
		}
		state := filepath.Join(states, other)
		if d, e := configData(directory, other, false); e == nil {
			if s, ok := d["state"].(map[string]any); ok {
				if p, ok := s["path"].(string); ok && filepath.IsAbs(p) {
					state = filepath.Clean(p)
				}
			}
		}
		c.others = append(c.others, zone{other, "state directory", state})
	}
	if overlap(c.StatePath, home) {
		return nil, Refuse("the state directory overlaps the configuration home")
	}
	if state := object(data["state"]); state["path"] != nil {
		if inside(states, c.StatePath) {
			return nil, Refuse("state.path must not contain the state home")
		}
		if inside(c.StatePath, states) && !inside(c.StatePath, filepath.Join(states, name)) {
			return nil, Refuse("state.path must not lie inside another configuration's default state directory")
		}
	}
	for _, z := range c.others {
		if overlap(c.StatePath, z.Path) {
			return nil, Refuse("the state directory is the same as, inside or around configuration %s's %s", shown(z.Name), z.Kind)
		}
	}
	return c, nil
}
func configData(directory, name string, validate bool) (map[string]any, error) {
	base := realPath(directory)
	data, err := readConfigFile(base, "config.toml", 1024*1024)
	if err != nil {
		return nil, Refuse("configuration %s: config.toml cannot be read as a regular file", shown(name))
	}
	v := map[string]any{}
	if !utf8.Valid(data) {
		return nil, Refuse("configuration %s: config.toml must be UTF-8 text", shown(name))
	}
	if _, err = toml.Decode(string(data), &v); err != nil {
		return nil, Refuse("configuration %s: config.toml is not valid TOML", shown(name))
	}
	v = object(normalizeTOML(v))
	if !validate {
		return v, nil
	}
	if where, rule := credentialValue(v); rule != "" {
		return nil, Refuse("configuration %s: config.toml: %s looks like a credential (%s)", shown(name), where, rule)
	}
	if num(v["schema_version"]) != 1 {
		return nil, Refuse("configuration %s: config.toml: schema_version must be 1", shown(name))
	}
	if v["name"] != name {
		return nil, Refuse("configuration %s: config.toml: name must equal the directory name", shown(name))
	}
	if err = validateConfigFiles(base, filepath.Dir(filepath.Dir(directory)), name, v); err != nil {
		return nil, err
	}
	return v, nil
}

// Configuration links may alias files inside the owning directory. State links never do.
func configLocation(base, relative string) (string, error) {
	resolved, err := filepath.EvalSymlinks(filepath.Join(base, relative))
	if err != nil {
		return "", err
	}
	if !inside(resolved, base) {
		return "", Refuse("a configuration file or directory leads outside its owning directory")
	}
	return resolved, nil
}
func readConfigFile(base, relative string, limit int64) ([]byte, error) {
	path, err := configLocation(base, relative)
	if err != nil {
		return nil, err
	}
	return readRegular(path, limit)
}
func validAbsolute(v any) bool {
	s, ok := v.(string)
	return ok && strings.HasPrefix(s, "/") && len([]rune(s)) <= 4096 && !control(s)
}
func control(s string) bool {
	for _, r := range s {
		if r < 32 || r == 127 {
			return true
		}
	}
	return false
}

func readRegular(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, Refuse("the file cannot be opened as a regular file without following a symbolic link")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, Refuse("the file is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, Refuse("the file cannot be read")
	}
	if int64(len(b)) > limit {
		return nil, Refuse("the file is larger than %d bytes", limit)
	}
	return b, nil
}
func checkedBelow(base, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", Refuse("a file path must be relative to its directory")
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	current := base
	for i, p := range parts {
		if p == "" || p == "." || p == ".." {
			return "", Refuse("a file path must stay inside its directory")
		}
		current = filepath.Join(current, p)
		st, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", Refuse("a path inside the directory is a symbolic link")
		}
		if i < len(parts)-1 && !st.IsDir() {
			return "", Refuse("a path inside the directory is not a directory")
		}
	}
	return current, nil
}
func readBelow(base, relative string, limit int64) ([]byte, error) {
	path, err := checkedBelow(base, relative)
	if err != nil {
		return nil, err
	}
	return readRegular(path, limit)
}
func markerAt(path string) (Object, bool, error) {
	p := filepath.Join(path, markerName)
	if _, err := os.Lstat(p); os.IsNotExist(err) {
		return nil, false, nil
	}
	b, e := readRegular(p, 65536)
	if e != nil {
		return nil, true, e
	}
	v, e := Parse(b, "the ownership marker")
	if e != nil || object(v) == nil {
		return nil, true, Refuse("the ownership marker is unreadable")
	}
	return object(v), true, nil
}
func validMarker(v Object, name string) bool {
	if len(v) != 3 || v["config"] != name || !nameGrammar.MatchString(text(v["config"])) || num(v["format"]) != 2 {
		return false
	}
	if _, ok := v["store"]; !ok {
		return false
	}
	if v["store"] == nil {
		return true
	}
	s := object(v["store"])
	return len(s) == 2 && storeIDGrammar.MatchString(text(s["id"])) && recordedGrammar.MatchString(text(s["created_at"]))
}
func (c *Configuration) checkAncestors(path string, self bool, label string) error {
	target := realPath(path)
	for p := target; ; p = filepath.Dir(p) {
		v, exists, err := markerAt(p)
		if exists {
			if err != nil {
				return Refuse("%s lies below a directory whose ownership marker is unreadable, a link or not a regular file", label)
			}
			if v["config"] != c.Name {
				owner := text(v["config"])
				if c.known[owner] && validMarker(v, owner) {
					if self {
						if p == target {
							return Refuse("the state directory %s belongs to configuration %s", c.StatePath, shown(owner))
						}
						return Refuse("the state directory %s lies inside the state directory of configuration %s", c.StatePath, shown(owner))
					}
					return Refuse("%s lies inside the state directory of configuration %s; a command bound to %s uses only its own", label, shown(owner), shown(c.Name))
				}
				return Refuse("%s belongs to another or an unknown configuration", label)
			}
		}
		if parent := filepath.Dir(p); parent == p {
			break
		}
	}
	return nil
}
func (c *Configuration) ReadExternal(path string, limit int64) ([]byte, error) {
	resolved := realPath(path)
	for _, z := range c.others {
		if inside(resolved, z.Path) {
			return nil, Refuse("--file lies inside configuration %s's %s; a command uses only its own", shown(z.Name), z.Kind)
		}
	}
	if inside(resolved, filepath.Join(c.Home, "configs")) && !inside(resolved, c.Directory) {
		return nil, Refuse("--file lies inside the configuration home but outside this configuration's directory")
	}
	if inside(resolved, c.StateHome) && !inside(resolved, c.StatePath) && !inside(resolved, filepath.Join(c.StateHome, c.Name)) {
		return nil, Refuse("--file lies inside the state home but outside this configuration's state directory")
	}
	// A path written through an owned directory must stay there after links resolve.
	absolute, _ := filepath.Abs(path)
	for _, own := range []string{c.Directory, c.StatePath} {
		for p := filepath.Dir(absolute); ; p = filepath.Dir(p) {
			if pi, e := os.Stat(p); e == nil {
				if oi, e := os.Stat(own); e == nil && os.SameFile(pi, oi) && !inside(resolved, own) {
					return nil, Refuse("--file passes through a directory of configuration %s and leaves it through a link", shown(c.Name))
				}
			}
			if filepath.Dir(p) == p {
				break
			}
		}
	}
	if err := c.checkAncestors(filepath.Dir(resolved), false, "--file"); err != nil {
		return nil, err
	}
	return readRegular(resolved, limit)
}

type Directory struct {
	Config   *Configuration
	Path     string
	file     *os.File
	identity os.FileInfo
}

func (c *Configuration) OpenDirectory(create bool) (*Directory, error) {
	path := realPath(c.StatePath)
	if err := c.checkAncestors(path, true, "the state directory"); err != nil {
		return nil, err
	}
	if create {
		if err := os.MkdirAll(path, 0700); err != nil {
			return nil, Refuse("cannot create the state directory")
		}
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) && !create {
		return nil, nil
	}
	if err != nil {
		return nil, Refuse("cannot open the state directory")
	}
	st, err := f.Stat()
	if err != nil || !st.IsDir() {
		f.Close()
		return nil, Refuse("the state directory is not a directory")
	}
	return &Directory{c, path, f, st}, nil
}
func (d *Directory) Close() error { return d.file.Close() }
func (d *Directory) checkIdentity() error {
	st, err := os.Stat(d.Path)
	if err != nil || !os.SameFile(d.identity, st) {
		return Refuse("the state directory changed while it was in use")
	}
	return nil
}
func (d *Directory) Marker() (Object, error) {
	if err := d.checkIdentity(); err != nil {
		return nil, err
	}
	v, exists, err := markerAt(d.Path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	if !validMarker(v, d.Config.Name) {
		return nil, Integrity("the ownership marker is not a valid marker of configuration %s", shown(d.Config.Name))
	}
	return v, nil
}
func (d *Directory) Lock(shared bool) (func(), error) { return directoryLock(d.file, shared) }

// Clients use the directory lock when supported and join an existing fallback
// file so that they also coordinate with clients unable to lock directories.
// Only a failed directory lock may create that file. Acquired locks are released
// in reverse order.
func directoryLock(f *os.File, shared bool) (func(), error) {
	op := syscall.LOCK_EX
	if shared {
		op = syscall.LOCK_SH
	}
	directoryLocked := faults.DirectoryFlock(f, op) == nil
	unlockDirectory := func() {
		if directoryLocked {
			syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		}
	}
	path := filepath.Join(f.Name(), ".lock")
	needFile := !directoryLocked
	if !needFile {
		_, err := os.Lstat(path)
		if err != nil && !os.IsNotExist(err) {
			unlockDirectory()
			return nil, Refuse("cannot inspect the directory lock file")
		}
		needFile = err == nil
	}
	var lockFile *os.File
	if needFile {
		flags := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
		if !directoryLocked {
			flags |= syscall.O_CREAT
		}
		fd, err := syscall.Open(path, flags, 0600)
		if err != nil {
			unlockDirectory()
			return nil, Refuse("cannot open the directory lock file")
		}
		lockFile = os.NewFile(uintptr(fd), path)
		if st, e := lockFile.Stat(); e != nil || !st.Mode().IsRegular() {
			lockFile.Close()
			unlockDirectory()
			return nil, Refuse("the directory lock file is not a regular file")
		}
		if err = syscall.Flock(int(lockFile.Fd()), op); err != nil {
			lockFile.Close()
			unlockDirectory()
			return nil, Refuse("cannot lock the directory")
		}
	}
	return func() {
		if lockFile != nil {
			syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			lockFile.Close()
		}
		unlockDirectory()
	}, nil
}
func (d *Directory) RecordStore(id, created string) error {
	if err := d.checkIdentity(); err != nil {
		return err
	}
	value := Object{"config": d.Config.Name, "format": 2, "store": nil}
	if id != "" {
		value["store"] = Object{"id": id, "created_at": created}
	}
	f, err := os.CreateTemp(d.Path, ".tmp-")
	if err != nil {
		return Refuse("cannot write the ownership marker")
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.WriteString(Canonical(value) + "\n")
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return Refuse("cannot write the ownership marker")
	}
	if err = os.Rename(temp, filepath.Join(d.Path, markerName)); err != nil {
		return Refuse("cannot record the store in the ownership marker")
	}
	return nil
}
func (d *Directory) StoreInfo() (os.FileInfo, error) {
	if err := d.checkIdentity(); err != nil {
		return nil, err
	}
	st, err := os.Lstat(filepath.Join(d.Path, storeFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, Refuse("cannot inspect the event store")
	}
	if !st.Mode().IsRegular() {
		return nil, Refuse("the store is a symbolic link or not a regular file")
	}
	return st, nil
}
func (d *Directory) ReadLane(lane, part, name string, limit int64) ([]byte, error) {
	if !laneGrammar.MatchString(lane) {
		return nil, Refuse("the lane directory name is not valid")
	}
	data, err := readBelow(d.Path, filepath.Join("lanes", lane, part, name), limit)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return data, err
}

// Inspect the final mail entry without following a link, after checking its
// parent directories in the same way as ReadLane.
func (d *Directory) mailEntry(lane, name string) (os.FileInfo, error) {
	if !laneGrammar.MatchString(lane) || !mailNameGrammar.MatchString(name) {
		return nil, Refuse("the mail entry name is not valid")
	}
	parent, err := checkedBelow(d.Path, filepath.Join("lanes", lane, "mail"))
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(filepath.Join(parent, name))
	if os.IsNotExist(err) {
		return nil, nil
	}
	return info, err
}

type keptFile struct{ Lane, Name string }

func (d *Directory) AllFiles(part string) ([]keptFile, error) {
	path, err := checkedBelow(d.Path, "lanes")
	if os.IsNotExist(err) {
		return []keptFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	lanes, err := os.ReadDir(path)
	if err != nil {
		return nil, Refuse("cannot read the lanes directory")
	}
	result := []keptFile{}
	for _, lane := range lanes {
		if !lane.IsDir() || lane.Type()&os.ModeSymlink != 0 {
			return nil, Refuse("an entry under lanes is a symbolic link or not a directory")
		}
		inside, err := checkedBelow(d.Path, filepath.Join("lanes", lane.Name(), part))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(inside)
		if err != nil {
			return nil, Refuse("cannot read a lane's %s directory", part)
		}
		for _, entry := range entries {
			result = append(result, keptFile{lane.Name(), entry.Name()})
		}
	}
	return result, nil
}
func (d *Directory) LaneLock(lane string) (func(), error) {
	path, err := checkedBelow(d.Path, filepath.Join("lanes", lane))
	if os.IsNotExist(err) {
		return func() {}, nil
	}
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, Refuse("cannot open the lane directory")
	}
	unlock, err := directoryLock(f, false)
	if err != nil {
		f.Close()
		return nil, err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		unlock()
		f.Close()
		return nil, Refuse("cannot read the lane directory")
	}
	for _, e := range entries {
		name := e.Name()
		if name == "pending.jsonl" || strings.HasPrefix(name, "pending-") && strings.HasSuffix(name, ".jsonl") {
			info, e := os.Lstat(filepath.Join(path, name))
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				unlock()
				f.Close()
				return nil, e
			}
			if info != nil && info.Size() > 0 {
				unlock()
				f.Close()
				return nil, Refuse("lane %s has events waiting to be recorded; lane check records them first", lane)
			}
		}
	}
	return func() { unlock(); f.Close() }, nil
}
func (c *Configuration) Socket(statePath string) string {
	return fmt.Sprintf("/tmp/laneboss-%d/%s-%s", os.Getuid(), c.Name, digest([]byte(statePath))[:12])
}
