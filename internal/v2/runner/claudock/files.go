package claudock

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

func linked(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Nlink != 1
}

// On failure keep the private temporary bytes for revocation/recovery. It is
// always a library-owned .runnerhome-* regular file in a protected directory.
func replacePrivate(root *os.Root, temporaryDirectory, name string, data []byte, mode fs.FileMode) error {
	if info, err := root.Lstat(name); err == nil {
		if !info.Mode().IsRegular() || linked(info) {
			return ownedError(ErrOwnedType)
		}
	} else if !os.IsNotExist(err) {
		return ownedError(ErrOwnedRead)
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	temporary := filepath.Join(temporaryDirectory, ".runnerhome-"+id)
	if err := createPrivate(root, temporary, data, mode); err != nil {
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		return fmt.Errorf("%w: %w", failure(api.CodeIntegrity, "private publication failed; retain its lease"), ErrPublish)
	}
	directory, err := root.Open(filepath.Dir(name))
	if err != nil {
		return ownedError(ErrOwnedRead)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return ownedError(ErrPublish)
	}
	return nil
}

var ErrPublish = errors.New("private publication did not complete")

// Do not surface PathError/parser messages: they may expose private values.
func openRegular(root *os.Root, name string) (*os.File, fs.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, ownedError(ErrOwnedRead)
	}
	if !before.Mode().IsRegular() {
		return nil, nil, ownedError(ErrOwnedType)
	}
	if linked(before) {
		return nil, nil, ownedError(ErrOwnedLink)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, failure(api.CodeIntegrity, "adapter input could not be opened")
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || linked(after) || !os.SameFile(before, after) {
		f.Close()
		return nil, nil, failure(api.CodeIntegrity, "adapter input changed while opening")
	}
	return f, after, nil
}

func readPrivate(root *os.Root, name string, limit int64) ([]byte, error) {
	return readRegular(root, name, limit, true)
}

func readRegular(root *os.Root, name string, limit int64, private bool) (data []byte, result error) {
	f, before, err := openRegular(root, name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			result = errors.Join(result, ownedError(ErrOwnedRead))
			data = nil
		}
	}()
	if before.Size() > limit {
		return nil, failure(api.CodeIntegrity, "adapter input exceeds the bounded reader")
	}
	if private && before.Mode().Perm()&0077 != 0 {
		return nil, ownedError(ErrOwnedMode)
	}
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(data)) > limit || int64(len(data)) != before.Size() ||
		after.Size() != before.Size() || after.ModTime() != before.ModTime() {
		return nil, failure(api.CodeIntegrity, "private adapter input could not be read completely")
	}
	return data, nil
}

func createPrivate(root *os.Root, name string, data []byte, mode fs.FileMode) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return failure(api.CodeIntegrity, "private adapter file cannot be created; retain the incomplete home")
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
		return failure(api.CodeIntegrity, "private adapter file is incomplete; preserve it for recovery")
	}
	return nil
}
