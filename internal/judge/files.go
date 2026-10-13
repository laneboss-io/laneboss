package judge

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"laneboss.io/laneboss/internal/faults"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const markerName = ".laneboss-state"

type fileIdentity struct{ dev, ino uint64 }

func identity(info os.FileInfo) fileIdentity {
	st := info.Sys().(*syscall.Stat_t)
	return fileIdentity{uint64(st.Dev), uint64(st.Ino)}
}

type location struct {
	chain     []fileIdentity
	remainder []string
	real      string
}

func (l location) exists() bool { return len(l.chain) > 0 && len(l.remainder) == 0 }
func containsID(chain []fileIdentity, id fileIdentity) bool {
	for _, other := range chain {
		if id == other {
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
		return containsID(child.chain, parent.chain[0])
	}
	if child.chain[0] != parent.chain[0] || len(child.remainder) < len(parent.remainder) {
		return false
	}
	for i, part := range parent.remainder {
		if child.remainder[i] != part {
			return false
		}
	}
	return true
}
func overlaps(a, b location) bool { return inside(a, b) || inside(b, a) }

// Resolve links in the deepest existing ancestor, keeping nonexistent suffixes.
// Containment below that point uses directory identities and folded components.
func realPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := abs
	var suffix []string
	for {
		real, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				real = filepath.Join(real, suffix[i])
			}
			return real, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}
func locate(path string) (location, error) {
	var l location
	real, err := realPath(path)
	if err != nil {
		return l, refused("cannot resolve a checked directory (" + safeOSMessage(err) + ")")
	}
	l.real = real
	current := real
	for {
		_, err := os.Stat(current)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return l, refused("cannot inspect a checked directory (" + safeOSMessage(err) + ")")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return l, err
		}
		l.remainder = append([]string{strings.ToLower(filepath.Base(current))}, l.remainder...)
		current = parent
	}
	for {
		info, err := os.Stat(current)
		if err != nil {
			return l, refused("cannot read a directory above a checked path (" + safeOSMessage(err) + ")")
		}
		l.chain = append(l.chain, identity(info))
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return l, nil
}

type directory struct {
	root     *os.Root
	file     *os.File
	real     string
	logLimit int
}

func openDirectory(path string) (*directory, error) {
	real, err := realPath(path)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(real)
	if err != nil {
		return nil, err
	}
	f, err := r.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		r.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		r.Close()
		return nil, err
	}
	named, err := os.Stat(real)
	if err != nil || !os.SameFile(info, named) {
		f.Close()
		r.Close()
		return nil, refused("the directory changed while it was being checked")
	}
	return &directory{root: r, file: f, real: real}, nil
}
func (d *directory) close() { d.file.Close(); d.root.Close() }
func (d *directory) childDirectory(name string, create bool) (*directory, error) {
	if create {
		if err := d.root.Mkdir(name, 0700); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}
	info, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, refused(name + " inside the state directory is a symbolic link or not a directory")
	}
	r, err := d.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	f, err := r.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		r.Close()
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(opened, info) {
		f.Close()
		r.Close()
		return nil, refused("a child directory changed while it was being checked")
	}
	return &directory{root: r, file: f, real: filepath.Join(d.real, name), logLimit: d.logLimit}, nil
}
func (d *directory) readFile(name, what string, limit int) ([]byte, error) {
	named, err := d.root.Lstat(name)
	if err != nil {
		return nil, refused(what + ": cannot inspect the file (" + safeOSMessage(err) + ")")
	}
	// Root confines link resolution to its directory, but the contract refuses
	// even links that stay inside it. Check the entry itself before opening it.
	if !named.Mode().IsRegular() {
		return nil, refused(what + ": a symbolic link or not a regular file")
	}
	f, err := d.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, refused(what + ": cannot open the file (" + safeOSMessage(err) + ")")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, refused(what + ": not a regular file")
	}
	if !os.SameFile(named, info) {
		return nil, refused(what + ": the file changed while it was being checked")
	}
	if info.Size() > int64(limit) {
		return nil, refused(fmt.Sprintf("%s: larger than %d bytes", what, limit))
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, refused(what + ": cannot read the file (" + safeOSMessage(err) + ")")
	}
	if len(data) > limit {
		return nil, refused(fmt.Sprintf("%s: larger than %d bytes", what, limit))
	}
	return data, nil
}

func (d *directory) lock() (func(), error) {
	if err := syscall.Flock(int(d.file.Fd()), syscall.LOCK_EX); err == nil {
		return func() { syscall.Flock(int(d.file.Fd()), syscall.LOCK_UN) }, nil
	}
	if info, err := d.root.Lstat(".lock"); err == nil {
		if !info.Mode().IsRegular() {
			return nil, refused("the lock is a symbolic link or not a regular file")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := d.root.OpenFile(".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, refused("the lock is not a regular file")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
func (d *directory) writeNew(name string, data []byte, replace bool) error {
	id, err := newID()
	if err != nil {
		return err
	}
	temporary := fmt.Sprintf(".tmp-%d-%s", os.Getpid(), id)
	f, err := d.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		f.Close()
		if cleanup {
			d.root.Remove(temporary)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = faults.Sync(f); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if replace {
		err = d.root.Rename(temporary, name)
	} else {
		if err = d.root.Link(temporary, name); err == nil {
			err = d.root.Remove(temporary)
		}
	}
	if err != nil {
		return err
	}
	cleanup = false
	return nil
}
func safeFailure(err error) string {
	var ce *commandError
	if errors.As(err, &ce) {
		return ce.message
	}
	return safeOSMessage(err)
}

func (d *directory) marker() (map[string]any, bool, error) {
	if _, err := d.root.Lstat(markerName); os.IsNotExist(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, true, refused("the ownership marker is unreadable")
	}
	data, err := d.readFile(markerName, "the ownership marker", 65536)
	if err != nil {
		return nil, true, refused("the ownership marker is unreadable, a link or not a regular file")
	}
	v, err := parseJSON(data)
	if err != nil {
		return nil, true, refused("the ownership marker is unreadable")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, true, refused("the ownership marker is unreadable")
	}
	return m, true, nil
}
func validMarker(m map[string]any) bool {
	if !exactKeys(m, "config format store") || !matchesString(m["config"], namePattern) {
		return false
	}
	if !nonnegativeInteger(m["format"]) || fmt.Sprint(m["format"]) != "2" {
		return false
	}
	if m["store"] == nil {
		return true
	}
	store, ok := m["store"].(map[string]any)
	return ok && exactKeys(store, "id created_at") && matchesString(store["id"], askPattern) && matchesString(store["created_at"], recordedPattern)
}
func (d *directory) recordOwner(c *configuration) error {
	m, present, err := d.marker()
	if err != nil {
		return err
	}
	if present {
		if !validMarker(m) || m["config"] != c.name {
			return integrity("the ownership marker is not a valid marker of this configuration")
		}
		return nil
	}
	unlock, err := d.lock()
	if err != nil {
		return egressProblem(nothingAsked + ": the state directory cannot record its owner (" + safeFailure(err) + ")")
	}
	defer unlock()
	m, present, err = d.marker()
	if err != nil {
		return err
	}
	if present {
		if !validMarker(m) || m["config"] != c.name {
			return integrity("the ownership marker is not a valid marker of this configuration")
		}
		return nil
	}
	err = d.writeNew(markerName, logBytes(map[string]any{"config": c.name, "format": 2, "store": nil}), false)
	if err != nil {
		return egressProblem(nothingAsked + ": the state directory cannot record its owner (" + safeFailure(err) + ")")
	}
	return nil
}

func (d *directory) readLog() ([]byte, error) {
	if _, err := d.root.Lstat("egress.jsonl"); os.IsNotExist(err) {
		return []byte{}, nil
	} else if err != nil {
		return nil, err
	}
	return d.readFile("egress.jsonl", "the egress log", d.egressLimit())
}

// Operators can choose a stricter cap. The published reader bound can never be
// raised, and both reading and writing use the same bound in one invocation.
func (d *directory) egressLimit() int {
	if d.logLimit > 0 && d.logLimit <= maxEgressBytes {
		return d.logLimit
	}
	return maxEgressBytes
}
func (d *directory) writeLog(line []byte, sending bool, failure string) error {
	unlock, err := d.lock()
	if err != nil {
		return egressProblem(failure + ": the egress log cannot be written (" + safeFailure(err) + ")")
	}
	defer unlock()
	where := shown(filepath.Join(d.real, "egress.jsonl"))
	if sending {
		if info, err := d.root.Lstat("egress.jsonl"); err == nil && info.Size() > int64(d.egressLimit()) {
			return egressProblem(nothingAsked + ": the egress log " + where + " is full; move the file aside (rename it) and ask again")
		}
	}
	data, err := d.readLog()
	if err != nil {
		return egressProblem(failure + ": the egress log cannot be written (" + safeFailure(err) + ")")
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	if sending {
		unfinished := 0
		for _, raw := range bytes.Split(data, []byte{'\n'}) {
			if blankLogLine(raw) {
				continue
			}
			record, err := parseLogLine(raw)
			if err != nil {
				return egressProblem(nothingAsked + ": the egress log " + where + " was not written by this version of the launcher; move the file aside (rename it) and ask again")
			}
			if record["event"] == "sent" {
				unfinished++
			} else {
				unfinished--
			}
		}
		if unfinished < 0 {
			unfinished = 0
		}
		if len(data)+len(line)+outcomeReserve*(unfinished+1) > d.egressLimit() {
			return egressProblem(nothingAsked + ": the egress log " + where + " is full; move the file aside (rename it) and ask again")
		}
	}
	if err = d.writeNew("egress.jsonl", append(data, line...), true); err == nil {
		err = faults.Sync(d.file)
	}
	if err != nil {
		return egressProblem(failure + ": the egress log cannot be written (" + safeFailure(err) + ")")
	}
	return nil
}
func readEgress(c *configuration, o options, w io.Writer) error {
	var sinceTime int64
	var sinceNano int
	if o.sinceSet {
		since, err := parseMoment(o.since, false)
		if err != nil {
			return refused("--since: is not a valid date, time and time zone")
		}
		sinceTime, sinceNano = since.Unix(), since.Nanosecond()
	}
	state, err := c.openState(false)
	if err != nil {
		return err
	}
	if state == nil {
		return nil
	}
	defer state.close()
	d, err := state.childDirectory("judges", false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return refused("the egress log directory cannot be read (" + safeFailure(err) + ")")
	}
	defer d.close()
	data, err := d.readLog()
	if err != nil {
		return err
	}
	var output bytes.Buffer
	for number, raw := range bytes.Split(data, []byte{'\n'}) {
		if blankLogLine(raw) {
			continue
		}
		record, err := parseLogLine(raw)
		if err != nil {
			return integrity(fmt.Sprintf("line %d of the egress log is not a line of the log (docs/judges.md, 'The egress log')", number+1))
		}
		at, err := parseMoment(record["at"].(string), true)
		if err != nil {
			return integrity("the egress log holds an invalid time")
		}
		if !o.sinceSet || at.Unix() > sinceTime || at.Unix() == sinceTime && at.Nanosecond() >= sinceNano {
			output.Write(raw)
			output.WriteByte('\n')
		}
	}
	_, err = w.Write(output.Bytes())
	return err
}

func blankLogLine(raw []byte) bool { return len(bytes.Trim(raw, " \t\r\n\v\f")) == 0 }
