package lane

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func realPath(path string) string {
	a, _ := filepath.Abs(path)
	p, err := filepath.EvalSymlinks(a)
	if err == nil {
		return p
	}
	parent := filepath.Dir(a)
	if parent == a {
		return a
	}
	return filepath.Join(realPath(parent), filepath.Base(a))
}
func inside(path, root string) bool {
	path = realPath(path)
	root = realPath(root)
	return path == root || strings.HasPrefix(path, root+string(os.PathSeparator))
}
func openDirectory(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, refuse("cannot open directory %s", path)
	}
	return f, nil
}
func rootDirectory(path string) (*os.Root, error) {
	f, err := openDirectory(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	after, err := r.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		r.Close()
		return nil, refuse("the directory %s changed while it was being checked", path)
	}
	return r, nil
}
func rootChild(r *os.Root, path string, create bool) (*os.Root, error) {
	if path == "" || path == "." {
		return r.OpenRoot(".")
	}
	parts := strings.Split(filepath.ToSlash(path), "/")
	current, err := r.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			current.Close()
			return nil, refuse("invalid directory component")
		}
		info, e := current.Lstat(p)
		if os.IsNotExist(e) && create {
			e = current.Mkdir(p, 0700)
			if e != nil && !os.IsExist(e) {
				current.Close()
				return nil, e
			}
			info, e = current.Lstat(p)
		}
		if e != nil {
			current.Close()
			return nil, e
		}
		if !info.IsDir() {
			current.Close()
			return nil, refuse("%s is a symbolic link or not a directory", filepath.Join(r.Name(), path))
		}
		child, e := current.OpenRoot(p)
		if e != nil {
			current.Close()
			return nil, e
		}
		after, e := child.Stat(".")
		current.Close()
		if e != nil || !os.SameFile(info, after) {
			child.Close()
			return nil, refuse("the directory changed while it was being checked")
		}
		current = child
	}
	return current, nil
}
func rootRead(r *os.Root, path string, limit int64) ([]byte, error) {
	parent, err := rootChild(r, filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	name := filepath.Base(path)
	f, err := childOpen(parent, name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, refuse("%s is not a regular file", path)
	}
	if info.Size() > limit {
		return nil, refuse("%s is larger than its byte limit", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, refuse("%s is larger than its byte limit", path)
	}
	return b, nil
}
func rootWrite(r *os.Root, path string, b []byte, replace bool, mode os.FileMode) error {
	parent, err := rootChild(r, filepath.Dir(path), true)
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(path)
	temp := ".tmp-" + newID()
	f, err := childOpen(parent, temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer parent.Remove(temp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if replace {
		if info, e := parent.Lstat(name); e == nil && !info.Mode().IsRegular() {
			return refuse("%s is a symbolic link or not a regular file", path)
		} else if e != nil && !os.IsNotExist(e) {
			return e
		}
		err = parent.Rename(temp, name)
	} else {
		err = parent.Link(temp, name)
	}
	if err == nil {
		d, e := parent.Open(".")
		if e != nil {
			return e
		}
		err = d.Sync()
		d.Close()
	}
	return err
}
func lockFile(f *os.File, seconds float64, shared bool) (func(), error) {
	mode := syscall.LOCK_EX
	if shared {
		mode = syscall.LOCK_SH
	}
	end := time.Now().Add(time.Duration(seconds * float64(time.Second)))
	for {
		err := syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB)
		if err == nil {
			return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return nil, refuse("cannot hold the directory lock")
		}
		if time.Now().After(end) {
			return nil, refuse("another lane command holds the lanes lock and did not release it within %.0f seconds; nothing was done", seconds)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func (s *session) laneRoot(lane string, create bool) (*os.Root, error) {
	if s.root == nil {
		return nil, os.ErrNotExist
	}
	return rootChild(s.root, filepath.Join("lanes", lane), create)
}
func (s *session) lanePath(lane string, names ...string) string {
	p := append([]string{s.c.state, "lanes", lane}, names...)
	return filepath.Join(p...)
}
func (s *session) lanesLock() (func(), error) {
	if s.root == nil {
		return nil, refuse("the state directory does not exist")
	}
	f, err := childOpen(s.root, "lanes.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, refuse("cannot open lanes.lock")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, refuse("lanes.lock is not a regular file")
	}
	unlock, err := lockFile(f, number(valueOr(obj(s.c.data["lanes"]), "lock_wait_seconds", 60)), false)
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { unlock(); f.Close() }, nil
}
func (s *session) checkStateIdentity() error {
	if s.root == nil {
		return nil
	}
	before, err := s.dir.Stat()
	if err != nil {
		return err
	}
	after, err := os.Stat(s.c.state)
	if err != nil || !os.SameFile(before, after) {
		return refuse("the state directory %s changed while it was in use", s.c.state)
	}
	return nil
}

// os.Root contains traversal, but its OpenFile deliberately resolves links even with O_NOFOLLOW.
// State files need a leaf open relative to the held directory that never resolves a link.
func childOpen(root *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return nil, refuse("invalid file component")
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	fd, err := openChildAt(directory, name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), filepath.Join(root.Name(), name)), nil
}
