package decisionsrv

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

const maxTextBytes = 8 << 20

// DefaultStoreRelativePath is the decision store's default path below .laneboss.
// Org inspection uses this exact path to distinguish the store from text sources.
const DefaultStoreRelativePath = "shared/services/decisions.sqlite"

func readRegular(path string, limit int) (string, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return "", invalid("cannot read source file: " + path)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return "", invalid("source must be a regular file within the byte limit: " + path)
	}
	data, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil {
		return "", invalid("cannot read source file: " + path)
	}
	if len(data) > limit {
		return "", invalid("source exceeds the byte limit: " + path)
	}
	if !utf8.Valid(data) {
		return "", invalid("source is not UTF-8 text: " + path)
	}
	return string(data), nil
}
func readTOML(path string) (object, error) {
	text, e := readRegular(path, 64<<10)
	if e != nil {
		return nil, e
	}
	m := object{}
	if _, e = toml.Decode(text, &m); e != nil {
		return nil, invalid("invalid TOML file: " + path)
	}
	return m, nil
}

// Resolve existing symlinks even when the final destination does not yet exist.
func realPath(path string) (string, error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return "", invalid("unreadable path")
	}
	return resolvePath(abs, 0)
}
func resolvePath(path string, depth int) (string, error) {
	if depth > 40 {
		return "", invalid("too many symlinks in history path")
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(current)
			continue
		}
		next := filepath.Join(current, part)
		info, e := os.Lstat(next)
		if os.IsNotExist(e) {
			return filepath.Clean(filepath.Join(next, filepath.Join(parts[i+1:]...))), nil
		}
		if e != nil {
			return "", invalid("unreadable history path")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, e := os.Readlink(next)
			if e != nil {
				return "", invalid("unreadable history symlink")
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(current, target)
			}
			return resolvePath(filepath.Join(target, filepath.Join(parts[i+1:]...)), depth+1)
		}
		current = next
	}
	return current, nil
}
func within(path, root string) (string, error) {
	resolved, e := realPath(path)
	if e != nil {
		return "", e
	}
	relative, e := filepath.Rel(root, resolved)
	if e != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", invalid("history path leaves its org")
	}
	return resolved, nil
}

type orgContext struct {
	root, home, db, socket, log, captureLog, review string
	history                                         object
}

func openOrg(directory string) (*orgContext, error) {
	if directory == "" {
		return nil, invalid("org-dir or LANEBOSS_ORG is required")
	}
	given, e := realPath(directory)
	if e != nil {
		return nil, e
	}
	home, root := filepath.Join(given, ".laneboss"), given
	if filepath.Base(given) == ".laneboss" {
		home = given
		root = filepath.Dir(given)
	}
	home, e = within(home, root)
	if e != nil {
		return nil, e
	}
	configPath, e := within(filepath.Join(home, "org.toml"), home)
	if e != nil {
		return nil, e
	}
	data, e := readTOML(configPath)
	if e != nil {
		return nil, e
	}
	history := object{}
	if v, ok := data["history"]; ok {
		history = obj(v)
		if history == nil {
			return nil, invalid("org history settings must be a table")
		}
		history = copyObject(history)
	}
	service, e := within(filepath.Join(home, "shared/services/history.toml"), home)
	if e != nil {
		return nil, e
	}
	if info, e := os.Stat(service); e == nil && info.Mode().IsRegular() {
		settings, e := readTOML(service)
		if e != nil {
			return nil, e
		}
		for k, v := range settings {
			history[k] = v
		}
	} else if e != nil && !os.IsNotExist(e) {
		return nil, invalid("cannot read history service settings")
	}
	o := &orgContext{root: root, home: home, history: history}
	db, socket := DefaultStoreRelativePath, "shared/services/history.sock"
	if v, ok := history["db"]; ok {
		db = str(v)
	}
	if v, ok := history["socket"]; ok {
		socket = str(v)
	}
	if o.db, e = o.path(db); e != nil {
		return nil, e
	}
	if o.socket, e = o.path(socket); e != nil {
		return nil, e
	}
	if o.log, e = o.path("shared/state/history/injections.jsonl"); e != nil {
		return nil, e
	}
	if o.captureLog, e = o.path("shared/state/history/classifications.jsonl"); e != nil {
		return nil, e
	}
	if o.review, e = o.path("shared/state/history/review.jsonl"); e != nil {
		return nil, e
	}
	return o, nil
}
func (o *orgContext) path(value string) (string, error) {
	if value == "" || strings.ContainsRune(value, 0) {
		return "", invalid("history path must be nonempty text")
	}
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(o.home, value)
	}
	return within(path, o.home)
}
func (o *orgContext) checkStore(path string) error {
	resolved, e := realPath(path)
	if e != nil {
		return e
	}
	if resolved != o.db {
		return invalid("--db must name this org's configured history store")
	}
	return nil
}
func (o *orgContext) instance(name string) (object, string, object, error) {
	if !instancePattern.MatchString(name) {
		return nil, "", nil, invalid("instance must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
	}
	directory, e := within(filepath.Join(o.home, "instances", name), filepath.Join(o.home, "instances"))
	if e != nil {
		return nil, "", nil, e
	}
	path, e := within(filepath.Join(directory, "instance.toml"), directory)
	if e != nil {
		return nil, "", nil, e
	}
	data, e := readTOML(path)
	if e != nil {
		return nil, "", nil, e
	}
	metadata := data
	if v, ok := data["instance"]; ok {
		metadata = obj(v)
	}
	if metadata == nil {
		return nil, "", nil, invalid("instance metadata must be a table")
	}
	instance := name
	if v, ok := metadata["name"]; ok {
		instance = str(v)
	}
	identity := object{"level": metadata["level"], "instance": instance}
	if e = validateScope(identity); e != nil {
		return nil, "", nil, e
	}
	if instance != name {
		return nil, "", nil, invalid("instance.toml name does not match its directory")
	}
	return identity, directory, metadata, nil
}
func discover(directory, orgDir, instance string) (*orgContext, object, string, object, error) {
	if orgDir == "" {
		orgDir = os.Getenv("LANEBOSS_ORG")
	}
	o, e := openOrg(orgDir)
	if e != nil {
		return nil, nil, "", nil, e
	}
	if instance == "" {
		instance = os.Getenv("LANEBOSS_INSTANCE")
	}
	if directory == "" {
		directory, e = os.Getwd()
		if e != nil {
			return nil, nil, "", nil, invalid("cannot read working directory")
		}
	}
	start, e := realPath(directory)
	if e != nil {
		return nil, nil, "", nil, e
	}
	tree := filepath.Join(o.home, "instances")
	if instance != "" && (strings.Contains(instance, "/") || strings.HasSuffix(instance, ".toml")) {
		candidate := instance
		if strings.HasPrefix(candidate, "~/") {
			home, e := os.UserHomeDir()
			if e != nil {
				return nil, nil, "", nil, invalid("cannot resolve instance selector")
			}
			candidate = filepath.Join(home, candidate[2:])
		}
		candidate, e = within(candidate, tree)
		if e != nil {
			return nil, nil, "", nil, e
		}
		start = candidate
		if filepath.Base(candidate) == "instance.toml" {
			start = filepath.Dir(candidate)
		}
		instance = filepath.Base(start)
	}
	if instance == "" {
		if _, e = within(start, tree); e != nil {
			return nil, nil, "", nil, e
		}
		for parent := start; parent != filepath.Dir(parent); parent = filepath.Dir(parent) {
			if filepath.Dir(parent) == tree {
				instance = filepath.Base(parent)
				break
			}
		}
	}
	if instance == "" {
		return nil, nil, "", nil, invalid("no org instance could be found")
	}
	identity, path, metadata, e := o.instance(instance)
	return o, identity, path, metadata, e
}
func lockFile(fd int, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		e := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return nil
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			return e
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return e
		}
		time.Sleep(min(5*time.Millisecond, remaining))
	}
}
func appendLog(path string, value object) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return invalid("cannot make history log directory")
	}
	fd, e := syscall.Open(path, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_CREAT|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return invalid("cannot open history log: " + path)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return invalid("history log must be a regular file")
	}
	if e = lockFile(fd, 80*time.Millisecond); e != nil {
		return invalid("history log is locked")
	}
	text, e := canonical(value)
	if e != nil {
		return e
	}
	if len(text)+1 > 64<<10 {
		return invalid("history log entry exceeds the byte limit")
	}
	_, e = io.WriteString(f, text+"\n")
	if e != nil {
		return invalid("cannot append history log")
	}
	return nil
}
func recentInjections(o *orgContext) ([]object, error) {
	fd, e := syscall.Open(o.log, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if e == syscall.ENOENT {
		return []object{}, nil
	}
	if e != nil {
		return nil, invalid("cannot open history log")
	}
	f := os.NewFile(uintptr(fd), o.log)
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return nil, invalid("history log must be a regular file")
	}
	start := max(int64(0), info.Size()-maxTextBytes)
	if _, e = f.Seek(start, io.SeekStart); e != nil {
		return nil, invalid("cannot read history log")
	}
	data, e := io.ReadAll(io.LimitReader(f, maxTextBytes))
	if e != nil {
		return nil, invalid("cannot read history log")
	}
	lines := strings.Split(string(data), "\n")
	if start > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	out := []object{}
	for _, line := range lines {
		if line == "" {
			continue
		}
		v, e := parseJSON([]byte(line))
		if e != nil || obj(v) == nil {
			return nil, invalid("invalid history log entry")
		}
		out = append(out, obj(v))
	}
	return out, nil
}
