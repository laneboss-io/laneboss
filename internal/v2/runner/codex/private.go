package codex

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

// Records and Leases must be service-owned and absent from EVERY lane mount.
// Their private modes alone are not a substitute for that namespace boundary.
type Records struct {
	path string
	root *os.Root
}

func NewRecords(directory string) (*Records, error) {
	path, root, err := openControlDirectory(directory)
	if err != nil {
		return nil, wrap("open Codex records", err)
	}
	return &Records{path: path, root: root}, nil
}

func (r *Records) Close() error {
	if err := r.root.Close(); err != nil {
		return problem(api.CodeUnavailable, "Codex records handle could not close")
	}
	return nil
}

type Leases struct {
	path string
	root *os.Root
}

func NewLeases(directory string) (*Leases, error) {
	path, root, err := openControlDirectory(directory)
	if err != nil {
		return nil, wrap("open Codex leases", err)
	}
	return &Leases{path: path, root: root}, nil
}

func (l *Leases) Close() error {
	if err := l.root.Close(); err != nil {
		return problem(api.CodeUnavailable, "Codex lease directory handle could not close")
	}
	return nil
}

func openControlDirectory(directory string) (string, *os.Root, error) {
	if !absolute(directory) {
		return "", nil, problem(api.CodeInvalid, "Codex control directory must be absolute")
	}
	before, err := os.Lstat(directory)
	if err != nil || !before.IsDir() || before.Mode().Perm()&0077 != 0 {
		return "", nil, problem(api.CodeIntegrity, "Codex control directory must be private and ordinary")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", nil, problem(api.CodeIntegrity, "Codex control directory has a different owner")
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return "", nil, problem(api.CodeIntegrity, "Codex control directory cannot be resolved")
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return "", nil, problem(api.CodeUnavailable, "Codex control directory cannot be opened")
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		closeErr := root.Close()
		return "", nil, errors.Join(problem(api.CodeIntegrity, "Codex control directory changed while opening"), closeResult(closeErr))
	}
	return canonical, root, nil
}

func wrap(operation string, err error) error { return fmt.Errorf("%s: %w", operation, err) }

func closeResult(err error) error {
	if err == nil {
		return nil
	}
	return problem(api.CodeUnavailable, "Codex private handle could not close")
}

func within(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && (relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func (r *Records) check() error { return sameRoot(r.path, r.root) }

func sameRoot(path string, root *os.Root) error {
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode().Perm()&0077 != 0 {
		return problem(api.CodeIntegrity, "Codex private root path is not an ordinary private directory")
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return problem(api.CodeIntegrity, "Codex open root no longer matches its named directory")
	}
	return nil
}

// Every owned ancestor is checked with Lstat: os.Root's confinement does not
// itself forbid a symlink to a different directory INSIDE the same root.
func ownedAncestors(root *os.Root, name string) error {
	if name == "." || name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || strings.HasPrefix(name, "..") {
		return problem(api.CodeIntegrity, "Codex owned path is invalid")
	}
	parent := filepath.Dir(name)
	for parent != "." {
		info, err := root.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return problem(api.CodeIntegrity, "Codex owned ancestor must be a real private directory")
		}
		parent = filepath.Dir(parent)
	}
	return nil
}

func readPrivate(root *os.Root, name string, limit int64) ([]byte, error) {
	return readRegular(root, name, limit, true)
}

func readRegular(root *os.Root, name string, limit int64, private bool) ([]byte, error) {
	if private {
		if err := ownedAncestors(root, name); err != nil {
			return nil, wrap("read Codex private file", err)
		}
	}
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || linked(info) || (private && info.Mode().Perm()&0077 != 0) || info.Size() > limit {
		return nil, problem(api.CodeIntegrity, "Codex private file must be bounded, single-linked and private")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, problem(api.CodeUnavailable, "Codex private file cannot be opened")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) || !after.Mode().IsRegular() || linked(after) || (private && after.Mode().Perm()&0077 != 0) {
		return nil, problem(api.CodeIntegrity, "Codex private file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, problem(api.CodeIntegrity, "Codex private file cannot be read completely")
	}
	return data, nil
}

func writePrivate(root *os.Root, name, temporaryDirectory string, data []byte, mode fs.FileMode) error {
	if err := ownedAncestors(root, name); err != nil {
		return wrap("write Codex private file", err)
	}
	if info, err := root.Lstat(name); err == nil {
		if !info.Mode().IsRegular() || linked(info) || info.Mode().Perm()&0077 != 0 {
			return problem(api.CodeIntegrity, "Codex private destination is not an ordinary private file")
		}
	} else if !os.IsNotExist(err) {
		return problem(api.CodeUnavailable, "Codex private destination cannot be inspected")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return problem(api.CodeUnavailable, "Codex private temporary name cannot be generated")
	}
	temporary := filepath.Join(temporaryDirectory, ".runnerhome-"+hex.EncodeToString(random[:]))
	if err := ownedAncestors(root, temporary); err != nil {
		return wrap("create Codex temporary file", err)
	}
	f, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return problem(api.CodeUnavailable, "Codex private temporary file cannot be created")
	}
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = f.Chmod(mode)
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return problem(api.CodeUnavailable, "Codex private write is incomplete; retain the slot and leases")
	}
	if err := root.Rename(temporary, name); err != nil {
		return problem(api.CodeUnavailable, "Codex private publication is incomplete; retain the slot and leases")
	}
	directory, err := root.Open(filepath.Dir(name))
	if err != nil {
		return problem(api.CodeUnavailable, "Codex publication directory cannot be opened for sync")
	}
	syncErr := directory.Sync()
	closeErr = directory.Close()
	if syncErr != nil || closeErr != nil {
		return problem(api.CodeUnavailable, "Codex private publication directory was not synced completely")
	}
	return nil
}

func homeKey(root *os.Root) (string, error) {
	info, err := root.Stat(".")
	if err != nil {
		return "", problem(api.CodeUnavailable, "Codex home identity cannot be read")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", problem(api.CodeUnsupported, "Codex home filesystem identity is unavailable")
	}
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d/%d", stat.Dev, stat.Ino)))
	return hex.EncodeToString(hash[:]), nil
}

type lease struct{ file *os.File }

func (l *Leases) acquire(kind, identity string) (*lease, error) {
	if err := sameRoot(l.path, l.root); err != nil {
		return nil, wrap("acquire Codex lease", err)
	}
	if identity == "" {
		return nil, problem(api.CodeInvalid, "Codex lease identity is required")
	}
	hash := sha256.Sum256([]byte(kind + "\x00" + identity))
	name := hex.EncodeToString(hash[:]) + ".lock"
	f, err := l.root.OpenFile(name, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, problem(api.CodeUnavailable, "Codex lease file cannot be opened")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || linked(info) || info.Mode().Perm()&0077 != 0 {
		closeErr := f.Close()
		return nil, errors.Join(problem(api.CodeIntegrity, "Codex lease file is not single-linked and private"), closeResult(closeErr))
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		closeErr := f.Close()
		code := api.CodeUnavailable
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			code = api.CodeConflict
		}
		return nil, errors.Join(problem(code, "Codex home or canonical login already has an owner"), closeResult(closeErr))
	}
	return &lease{file: f}, nil
}

func (l *lease) close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return closeResult(err)
}
