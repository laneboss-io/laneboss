package decisionsrv

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/decisions/jsonout"
)

type privateConfiguration struct {
	name, home, states, directory, state string
	data                                 object
}

var storeIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var recordedAtPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$`)

func uuidHex() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", invalid("cannot generate identifier")
	}
	return hex.EncodeToString(b), nil
}
func launcherHome(variable, suffix string) (string, error) {
	if value := os.Getenv(variable); value != "" {
		if !filepath.IsAbs(value) {
			return "", invalid(variable + " must be an absolute path")
		}
		return filepath.Clean(value), nil
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return "", invalid("cannot locate launcher home")
	}
	return filepath.Join(home, suffix, "laneboss"), nil
}
func loadConfiguration(name string, bound bool) (*privateConfiguration, error) {
	if bound {
		selected := os.Getenv("LANEBOSS_CONFIG")
		if name == "" {
			name = selected
		}
		if selected != "" && selected != name {
			return nil, invalid("--config conflicts with LANEBOSS_CONFIG; a session is bound to exactly one configuration")
		}
	}
	if !configPattern.MatchString(name) {
		return nil, invalid("configuration name must match [a-z0-9][a-z0-9-]{0,31}")
	}
	home, e := launcherHome("LANEBOSS_HOME", ".config")
	if e != nil {
		return nil, e
	}
	states, e := launcherHome("LANEBOSS_STATE_HOME", ".local/state")
	if e != nil {
		return nil, e
	}
	directory := filepath.Join(home, "configs", name)
	if e = refuseLinks(directory); e != nil {
		return nil, e
	}
	configPath, e := within(filepath.Join(directory, "config.toml"), directory)
	if e != nil {
		return nil, e
	}
	data, e := readConfigurationTOML(configPath)
	if e != nil {
		return nil, e
	}
	if data["name"] != name {
		return nil, invalid("config.toml name does not match its directory")
	}
	version, ok := integer(data["schema_version"])
	if !ok || version != 1 {
		return nil, invalid("configuration schema_version must be 1")
	}
	if credentialsInValue(data) {
		return nil, invalid("configuration contains a credential; no value is repeated")
	}
	state := filepath.Join(states, name)
	if v, ok := obj(data["state"])["path"]; ok {
		state = str(v)
		if !filepath.IsAbs(state) {
			return nil, invalid("state.path must be an absolute path")
		}
		for _, part := range strings.Split(state, "/") {
			if part == "." || part == ".." {
				return nil, invalid("state.path must have no dot segments")
			}
		}
	}
	state, e = realPath(state)
	if e != nil {
		return nil, e
	}
	c := &privateConfiguration{name, home, states, directory, state, data}
	if e = validateConfiguration(c); e != nil {
		return nil, e
	}
	if e = c.checkZones(); e != nil {
		return nil, e
	}
	return c, nil
}
func pathInside(path, root string) bool {
	relative, e := filepath.Rel(root, path)
	return e == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
func overlapPaths(a, b string) bool { return pathInside(a, b) || pathInside(b, a) }
func (c *privateConfiguration) checkZones() error {
	home, e := realPath(c.home)
	if e != nil {
		return e
	}
	if overlapPaths(c.state, home) {
		return invalid("the state directory must not overlap the configuration home")
	}
	states, e := realPath(c.states)
	if e != nil {
		return e
	}
	if obj(c.data["state"])["path"] != nil {
		if pathInside(states, c.state) {
			return invalid("state.path must not contain the state home")
		}
		ownDefault, e := realPath(filepath.Join(c.states, c.name))
		if e != nil {
			return e
		}
		if pathInside(c.state, states) && !pathInside(c.state, ownDefault) {
			return invalid("state.path must not lie inside another configuration's default state directory")
		}
	}
	configs, e := realPath(filepath.Join(c.home, "configs"))
	if e != nil {
		return e
	}
	if overlapPaths(c.state, configs) {
		return invalid("the state directory overlaps the configuration home")
	}
	entries, e := os.ReadDir(filepath.Join(c.home, "configs"))
	if e != nil {
		return invalid("cannot list configuration directories")
	}
	for _, entry := range entries {
		if entry.Name() == c.name || !configPattern.MatchString(entry.Name()) {
			continue
		}
		directory, e := realPath(filepath.Join(c.home, "configs", entry.Name()))
		if e != nil {
			return e
		}
		ownDirectory, e := realPath(c.directory)
		if e != nil {
			return e
		}
		if overlapPaths(ownDirectory, directory) {
			return invalid("configuration directory overlaps another configuration's directory")
		}
		if overlapPaths(c.state, directory) {
			return invalid("the state directory overlaps another configuration directory")
		}
		data, e := readTOML(filepath.Join(directory, "config.toml"))
		if e != nil {
			continue
		}
		state := filepath.Join(c.states, entry.Name())
		if v := obj(data["state"])["path"]; v != nil {
			if !filepath.IsAbs(str(v)) {
				continue
			}
			state = str(v)
		}
		state, e = realPath(state)
		if e != nil {
			return e
		}
		if overlapPaths(c.state, state) {
			return invalid("the state directory overlaps another configuration's state")
		}
	}
	for parent := filepath.Dir(c.state); parent != filepath.Dir(parent); parent = filepath.Dir(parent) {
		path := filepath.Join(parent, ".laneboss-state")
		if _, e := os.Lstat(path); os.IsNotExist(e) {
			continue
		}
		m, e := readMarker(path)
		if e != nil || m["config"] != c.name {
			return invalid("the state directory lies inside another or an unknown configuration's state")
		}
	}
	return nil
}
func refuseLinks(path string) error {
	abs, e := filepath.Abs(path)
	if e != nil {
		return invalid("unreadable path")
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(abs, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, e := os.Lstat(current)
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return invalid("cannot inspect path")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return invalid("a symbolic link is refused in a configuration or state path")
		}
	}
	return nil
}
func readMarker(path string) (object, error) {
	text, e := readRegular(path, 64<<10)
	if e != nil {
		return nil, e
	}
	v, e := parseJSON([]byte(text))
	if e != nil {
		return nil, e
	}
	m := obj(v)
	if m == nil || len(m) != 3 || m["config"] == nil || m["format"] == nil {
		return nil, integrity("invalid state ownership marker")
	}
	if _, ok := m["store"]; !ok {
		return nil, integrity("invalid state ownership marker")
	}
	if !configPattern.MatchString(str(m["config"])) {
		return nil, integrity("invalid state ownership marker")
	}
	version, ok := integer(m["format"])
	if !ok || version != 2 {
		return nil, integrity("invalid state ownership marker")
	}
	if m["store"] != nil {
		store := obj(m["store"])
		if len(store) != 2 || !storeIDPattern.MatchString(str(store["id"])) || !recordedAtPattern.MatchString(str(store["created_at"])) {
			return nil, integrity("invalid state ownership marker")
		}
		if _, e = timestamp(store["created_at"], "store.created_at"); e != nil {
			return nil, integrity("invalid state ownership marker")
		}
	}
	return m, nil
}
func (c *privateConfiguration) openState(create bool) (object, error) {
	if e := refuseLinks(c.state); e != nil {
		return nil, e
	}
	if create {
		if e := os.MkdirAll(c.state, 0700); e != nil {
			return nil, invalid("cannot create the state directory")
		}
	}
	info, e := os.Stat(c.state)
	if os.IsNotExist(e) {
		return nil, invalid("configuration has no state directory; nothing was ingested")
	}
	if e != nil || !info.IsDir() {
		return nil, invalid("cannot open the state directory")
	}
	path := filepath.Join(c.state, ".laneboss-state")
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return nil, nil
	}
	marker, e := readMarker(path)
	if e != nil {
		return nil, e
	}
	if marker["config"] != c.name {
		return nil, invalid("the state directory belongs to another configuration")
	}
	return marker, nil
}
func directoryLock(directory string, shared bool) (*os.File, error) {
	fd, e := syscall.Open(filepath.Join(directory, ".lock"), syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, invalid("cannot open directory lock")
	}
	file := os.NewFile(uintptr(fd), "directory lock")
	info, e := file.Stat()
	if e != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, invalid("directory lock must be a regular file")
	}
	mode := syscall.LOCK_EX
	if shared {
		mode = syscall.LOCK_SH
	}
	if e = syscall.Flock(fd, mode); e != nil {
		file.Close()
		return nil, invalid("cannot lock directory")
	}
	return file, nil
}
func atomicStateFile(directory, name string, data []byte, replace bool) error {
	if strings.ContainsAny(name, "/\x00") || name == "" {
		return invalid("invalid state filename")
	}
	if e := refuseLinks(directory); e != nil {
		return e
	}
	if existing, e := os.Lstat(filepath.Join(directory, name)); e == nil {
		if !replace {
			return os.ErrExist
		}
		if !existing.Mode().IsRegular() {
			return invalid("state destination must be a regular file")
		}
	} else if !os.IsNotExist(e) {
		return invalid("cannot inspect state destination")
	}
	temporary, e := os.CreateTemp(directory, ".history-write-")
	if e != nil {
		return invalid("cannot create state file")
	}
	path := temporary.Name()
	defer os.Remove(path)
	defer temporary.Close()
	if e = temporary.Chmod(0600); e != nil {
		return invalid("cannot secure state file")
	}
	if _, e = temporary.Write(data); e != nil {
		return invalid("cannot write state file")
	}
	if e = temporary.Sync(); e != nil {
		return invalid("cannot sync state file")
	}
	if e = temporary.Close(); e != nil {
		return invalid("cannot close state file")
	}
	destination := filepath.Join(directory, name)
	if replace {
		e = os.Rename(path, destination)
	} else {
		e = os.Link(path, destination)
	}
	if e != nil {
		return invalid("cannot publish state file")
	}
	dir, e := os.Open(directory)
	if e != nil {
		return invalid("cannot open state directory for sync")
	}
	defer dir.Close()
	if e = dir.Sync(); e != nil {
		return invalid("cannot sync state directory")
	}
	return nil
}
func (c *privateConfiguration) ensureMarker() error {
	lock, e := directoryLock(c.state, false)
	if e != nil {
		return e
	}
	defer lock.Close()
	marker, e := c.openState(false)
	if e != nil {
		return e
	}
	if marker != nil {
		return nil
	}
	data, e := jsonout.Line(object{"config": c.name, "format": 2, "store": nil})
	if e != nil {
		return invalid(e.Error())
	}
	return atomicStateFile(c.state, ".laneboss-state", data, false)
}
func readRange(path string, start, end int64) (string, error) {
	if start < 0 || end < start {
		return "", invalid("the log range of the lane's latest run is not a pair of offsets")
	}
	if end-start > maxTextBytes {
		return "", invalid("the lane's report is larger than the bytes a single source may hold")
	}
	if e := refuseLinks(path); e != nil {
		return "", e
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return "", invalid("cannot read lane report")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return "", invalid("lane report must be a regular file")
	}
	if _, e = f.Seek(start, io.SeekStart); e != nil {
		return "", invalid("cannot seek lane report")
	}
	data, e := io.ReadAll(io.LimitReader(f, end-start))
	if e != nil || int64(len(data)) != end-start {
		return "", invalid("lane report holds fewer bytes than its latest run recorded")
	}
	return validSourceBytes(data, "lane report")
}
