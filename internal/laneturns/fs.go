package laneturns

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type stateDir struct {
	c    *configuration
	path string
	root *os.Root
}

func openState(c *configuration, create bool) (*stateDir, error) {
	if err := c.checkExternal(c.state, "the state directory", false); err != nil {
		return nil, err
	}
	if create {
		if err := os.MkdirAll(c.state, 0700); err != nil {
			return nil, refused("cannot create the state directory")
		}
	}
	root, err := os.OpenRoot(c.state)
	if os.IsNotExist(err) && !create {
		return nil, nil
	}
	if err != nil {
		return nil, refused("cannot open the state directory")
	}
	s := &stateDir{c: c, path: realPath(c.state), root: root}
	if _, err = s.marker(); err != nil {
		root.Close()
		return nil, err
	}
	return s, nil
}
func (s *stateDir) close() {
	if s != nil && s.root != nil {
		s.root.Close()
	}
}
func (s *stateDir) checkLocation() error {
	opened, err := s.root.Stat(".")
	if err != nil {
		return err
	}
	current, err := os.Stat(s.path)
	if err != nil || !os.SameFile(opened, current) {
		return refused("the state directory changed while it was in use")
	}
	return nil
}
func (s *stateDir) lanePath(lane string, names ...string) string {
	parts := append([]string{s.path, "lanes", lane}, names...)
	return filepath.Join(parts...)
}
func (s *stateDir) dir(relative string, create bool) (*os.Root, error) {
	if relative == "." || relative == "" {
		return s.root.OpenRoot(".")
	}
	if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, "..") {
		return nil, refused("a state path is outside its directory")
	}
	current, err := s.root.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	for _, name := range strings.Split(relative, string(filepath.Separator)) {
		if create {
			err = current.Mkdir(name, 0700)
			if err != nil && !errors.Is(err, os.ErrExist) {
				current.Close()
				return nil, err
			}
		}
		info, err := current.Lstat(name)
		if err != nil {
			current.Close()
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			current.Close()
			return nil, refused("a directory below the state directory is a symbolic link or not a directory")
		}
		next, err := current.OpenRoot(name)
		if err != nil {
			current.Close()
			return nil, err
		}
		opened, err := next.Stat(".")
		again, lastErr := current.Lstat(name)
		current.Close()
		if err != nil || lastErr != nil || !os.SameFile(info, opened) || !os.SameFile(info, again) || again.Mode()&os.ModeSymlink != 0 {
			next.Close()
			return nil, refused("a state directory changed while it was opened")
		}
		current = next
	}
	return current, nil
}
func regularAt(root *os.Root, name, label string, flags int, mode os.FileMode) (*os.File, error) {
	f, err := root.OpenFile(name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, refused("%s is a symbolic link or not a regular file", label)
	}
	return f, nil
}
func readAt(root *os.Root, name, label string, limit int) ([]byte, error) {
	f, err := regularAt(root, name, label, os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, refused("%s is a symbolic link", label)
		}
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, refused("%s is larger than %d bytes", label, limit)
	}
	return data, nil
}
func syncDir(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func writeAtomic(root *os.Root, name string, data []byte, mode os.FileMode, replace bool) error {
	id, err := randomID()
	if err != nil {
		return err
	}
	temp := ".tmp-" + id
	f, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if replace {
		if info, e := root.Lstat(name); e == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
			return refused("a file to be replaced is a symbolic link or not a regular file")
		}
		err = root.Rename(temp, name)
	} else {
		err = root.Link(temp, name)
	}
	if err != nil {
		return err
	}
	return syncDir(root)
}
func (s *stateDir) read(relative string, limit int) ([]byte, error) {
	parent, err := s.dir(filepath.Dir(relative), false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return readAt(parent, filepath.Base(relative), relative, limit)
}
func (s *stateDir) write(relative string, data []byte, mode os.FileMode, replace bool) error {
	parent, err := s.dir(filepath.Dir(relative), true)
	if err != nil {
		return err
	}
	defer parent.Close()
	return writeAtomic(parent, filepath.Base(relative), data, mode, replace)
}
func validMarker(v object) bool {
	if len(v) != 3 || !boundedInteger(v["format"], 2, 2) || !namePattern.MatchString(str(v["config"])) {
		return false
	}
	if v["store"] == nil {
		return true
	}
	m := obj(v["store"])
	return len(m) == 2 && launchPattern.MatchString(str(m["id"])) && regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$`).MatchString(str(m["created_at"]))
}
func (s *stateDir) marker() (object, error) {
	data, err := readAt(s.root, ".laneboss-state", "the ownership marker", 65536)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, integrity("the ownership marker is unreadable")
	}
	v, err := decodeJSON(data)
	if err != nil || !validMarker(v) || v["config"] != s.c.name {
		return nil, integrity("the ownership marker is not a valid marker of configuration %s", s.c.name)
	}
	return v, nil
}
func (s *stateDir) writeMarker(id, created string) error {
	v := object{"config": s.c.name, "format": 2, "store": object{"id": id, "created_at": created}}
	data, err := canonical(v)
	if err != nil {
		return err
	}
	return writeAtomic(s.root, ".laneboss-state", append(data, '\n'), 0600, true)
}

type fileLock struct{ file *os.File }

func (l *fileLock) close() {
	if l != nil && l.file != nil {
		syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
		l.file.Close()
	}
}
func lockRoot(root *os.Root, name string, seconds float64, label string, shared, create bool) (*fileLock, error) {
	var f *os.File
	var err error
	if name == "." {
		f, err = root.Open(".")
	} else {
		flags := os.O_RDWR
		if create {
			flags |= os.O_CREATE
		}
		f, err = regularAt(root, name, label, flags, 0600)
	}
	if err != nil {
		return nil, err
	}
	operation := syscall.LOCK_EX
	if shared {
		operation = syscall.LOCK_SH
	}
	deadline := time.Now().Add(time.Duration(seconds * float64(time.Second)))
	for {
		err = syscall.Flock(int(f.Fd()), operation|syscall.LOCK_NB)
		if err == nil {
			return &fileLock{f}, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			if name == "." && (err == syscall.EOPNOTSUPP || err == syscall.EBADF || err == syscall.EINVAL) {
				f.Close()
				return lockRoot(root, ".lock", seconds, label, shared, true)
			}
			f.Close()
			return nil, refused("%s could not be taken", label)
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, refused("another command holds the %s and did not release it within %g seconds ([lanes] lock_wait_seconds); nothing was done", label, seconds)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func (s *stateDir) lock(name, label string, seconds float64) (*fileLock, error) {
	return lockRoot(s.root, name, seconds, label, false, true)
}
