// Package private provides confined service-owned encrypted-record I/O.
package private

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type Directory struct {
	root *os.Root
	lock *os.File
}

// Open requires a preexisting protected parent and creates only the final
// directory. The installed service binding, not a lane-supplied path, selects it.
func Open(path string) (*Directory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, wire.Error(api.CodeInvalid, "secret directory must be absolute and clean")
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, wire.Error(api.CodePrerequisite, "secret directory parent must be an ordinary service-owned directory")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != uint32(os.Geteuid()) || parentInfo.Mode().Perm()&0022 != 0 {
		return nil, wire.Error(api.CodePrerequisite, "secret directory parent must be protected and service-owned")
	}
	created := false
	if err := os.Mkdir(path, 0700); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return nil, wire.Error(api.CodePrerequisite, "cannot create protected secret directory")
		}
	} else {
		created = true
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || !owned(info, 0700) {
		return nil, wire.Error(api.CodePrerequisite, "secret directory is not private and service-owned")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, wire.Error(api.CodePrerequisite, "cannot open protected secret directory")
	}
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(info, current) {
		root.Close()
		return nil, wire.Error(api.CodeIntegrity, "secret directory identity changed")
	}
	d := &Directory{root: root}
	if created {
		if err := d.sync(); err != nil {
			root.Close()
			return nil, err
		}
		parent, err := os.Open(filepath.Dir(path))
		if err != nil {
			root.Close()
			return nil, wire.Error(api.CodeIntegrity, "cannot sync new encrypted store parent")
		}
		syncErr, closeErr := parent.Sync(), parent.Close()
		if syncErr != nil || closeErr != nil {
			root.Close()
			return nil, wire.Error(api.CodeIntegrity, "new encrypted store directory is not durable")
		}
	}
	lock, err := d.open(".lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		root.Close()
		return nil, err
	}
	d.lock = lock
	return d, nil
}

func owned(info fs.FileInfo, mode fs.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm() == mode &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func (d *Directory) open(name string, flags int, mode fs.FileMode) (*os.File, error) {
	file, err := d.root.OpenFile(name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, wire.Error(api.CodeNotFound, "encrypted secret record is absent")
		}
		return nil, wire.Error(api.CodeIntegrity, "cannot open protected secret record")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !owned(info, mode) {
		file.Close()
		return nil, wire.Error(api.CodeIntegrity, "secret record has unsafe ownership or mode")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		file.Close()
		return nil, wire.Error(api.CodeIntegrity, "secret record has an unsafe link count")
	}
	return file, nil
}

// privacy rechecks the pinned directory and lock identity before protected I/O.
// This does not defend against a compromised service UID; it prevents silently
// continuing after an unsafe mode change or replacement of the lock pathname.
func (d *Directory) privacy() error {
	directory, err := d.root.Stat(".")
	if err != nil || !directory.IsDir() || !owned(directory, 0700) {
		return wire.Error(api.CodeIntegrity, "encrypted store directory privacy changed")
	}
	opened, err := d.lock.Stat()
	if err != nil || !opened.Mode().IsRegular() || !owned(opened, 0600) {
		return wire.Error(api.CodeIntegrity, "encrypted store lock privacy changed")
	}
	identity, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || identity.Nlink != 1 {
		return wire.Error(api.CodeIntegrity, "encrypted store lock has an unsafe link count")
	}
	current, err := d.root.Lstat(".lock")
	if err != nil || !current.Mode().IsRegular() || !owned(current, 0600) {
		return wire.Error(api.CodeIntegrity, "encrypted store lock pathname is unsafe")
	}
	if !os.SameFile(opened, current) {
		return wire.Error(api.CodeIntegrity, "encrypted store lock identity changed")
	}
	return nil
}

func (d *Directory) Lock(ctx context.Context) error {
	if err := d.privacy(); err != nil {
		return err
	}
	for {
		if err := wire.Context(ctx); err != nil {
			return err
		}
		err := unix.Flock(int(d.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return wire.Error(api.CodeIntegrity, "cannot acquire the encrypted store lock")
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return wire.Context(ctx)
		case <-timer.C:
		}
		if err := d.privacy(); err != nil {
			return err
		}
	}
	if err := wire.Context(ctx); err != nil {
		if releaseErr := d.Unlock(); releaseErr != nil {
			return releaseErr
		}
		return err
	}
	if err := d.privacy(); err != nil {
		if releaseErr := d.Unlock(); releaseErr != nil {
			return releaseErr
		}
		return err
	}
	return nil
}

func (d *Directory) Unlock() error {
	if err := unix.Flock(int(d.lock.Fd()), unix.LOCK_UN); err != nil {
		return wire.Error(api.CodeIntegrity, "cannot release secret store lock")
	}
	return nil
}

func (d *Directory) Read(name string, max int64) ([]byte, error) {
	file, err := d.open(name, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, max+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > max {
		return nil, wire.Error(api.CodeIntegrity, "encrypted record read is incomplete or oversized")
	}
	return data, nil
}

func (d *Directory) Names() ([]string, error) {
	file, err := d.root.Open(".")
	if err != nil {
		return nil, wire.Error(api.CodeIntegrity, "cannot enumerate encrypted records")
	}
	entries, readErr := file.ReadDir(-1)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, wire.Error(api.CodeIntegrity, "encrypted record enumeration failed")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == ".lock" {
			continue
		}
		if strings.HasPrefix(name, ".refresh-") && strings.HasSuffix(name, ".lock") &&
			wire.ID(strings.TrimSuffix(strings.TrimPrefix(name, ".refresh-"), ".lock")) {
			file, err := d.open(name, os.O_RDWR, 0600)
			if err != nil {
				return nil, err
			}
			info, statErr := file.Stat()
			closeErr := file.Close()
			if statErr != nil || info.Size() != 0 || closeErr != nil {
				return nil, wire.Error(api.CodeIntegrity, "canonical refresh lock inventory is invalid")
			}
			continue
		}
		if brokerFileName(name) {
			file, err := d.open(name, os.O_RDONLY, 0600)
			if err != nil {
				return nil, err
			}
			if err := file.Close(); err != nil {
				return nil, wire.Error(api.CodeIntegrity, "cannot close protected credential journal")
			}
			continue
		}
		if strings.HasPrefix(name, ".key-") && strings.HasSuffix(name, ".json") &&
			wire.ID(strings.TrimSuffix(strings.TrimPrefix(name, ".key-"), ".json")) {
			file, err := d.open(name, os.O_RDONLY, 0600)
			if err != nil {
				return nil, err
			}
			if err := file.Close(); err != nil {
				return nil, wire.Error(api.CodeIntegrity, "cannot close encrypted key check")
			}
			continue
		}
		if strings.HasSuffix(name, ".tmp") && wire.ID(strings.TrimSuffix(name, ".tmp")) {
			// A crash before rename can retain an incomplete ciphertext-only
			// staging file. It is never a committed record. Check its identity
			// and retain its bytes for recovery evidence; do not activate it.
			file, err := d.open(name, os.O_RDONLY, 0600)
			if err != nil {
				return nil, err
			}
			if err := file.Close(); err != nil {
				return nil, wire.Error(api.CodeIntegrity, "cannot close retained encrypted staging file")
			}
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

func brokerFileName(name string) bool {
	for _, prefix := range []string{".broker-profile-", ".broker-slot-", ".broker-login-", ".broker-projection-"} {
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".json") && wire.ID(strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".json")) {
			return true
		}
	}
	return false
}

// Write fsyncs ciphertext before its atomic rename and fsyncs the directory.
// A durability error is an integrity failure, including after a completed rename.
func (d *Directory) Write(name string, data []byte) (err error) {
	id, err := wire.RandomID()
	if err != nil {
		return err
	}
	temp := string(id) + ".tmp"
	file, err := d.open(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		removeErr := d.root.Remove(temp)
		if removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			err = wire.Error(api.CodeIntegrity, "cannot collect encrypted write staging file")
		}
	}()
	n, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || n != len(data) || syncErr != nil || closeErr != nil {
		return wire.Error(api.CodeIntegrity, "encrypted record write is not durable")
	}
	if err := d.root.Rename(temp, name); err != nil {
		return wire.Error(api.CodeIntegrity, "encrypted record activation failed")
	}
	return d.sync()
}

func (d *Directory) sync() error {
	dir, err := d.root.Open(".")
	if err != nil {
		return wire.Error(api.CodeIntegrity, "cannot sync encrypted record directory")
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil {
		return wire.Error(api.CodeIntegrity, "encrypted record directory is not durable")
	}
	return nil
}

func (d *Directory) Close() error {
	lockErr := d.lock.Close()
	rootErr := d.root.Close()
	if lockErr != nil || rootErr != nil {
		return wire.Error(api.CodeIntegrity, "cannot close protected secret store")
	}
	return nil
}
