package orgdiscord

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

const maxBytes = 1024 * 1024

type orgFiles struct {
	path string
	root *os.Root
}

func expandHome(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", refused("cannot resolve the user home directory")
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}

func openOrg(org string) (*orgFiles, error) {
	path, err := expandHome(org)
	if err != nil {
		return nil, err
	}
	path, err = filepath.Abs(path)
	if err == nil {
		path, err = filepath.EvalSymlinks(path)
	}
	if err != nil {
		return nil, refused("org-dir must contain an existing .laneboss directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, refused("org-dir must contain an existing .laneboss directory")
	}
	files := &orgFiles{path: path, root: root}
	if err := files.checkPath(".laneboss"); err != nil {
		root.Close()
		return nil, err
	}
	info, err := root.Stat(".laneboss")
	if err != nil || !info.IsDir() {
		root.Close()
		return nil, refused("org-dir must contain an existing .laneboss directory")
	}
	return files, nil
}

func (files *orgFiles) close() { files.root.Close() }

// Reject links in every configuration component, including dangling links.
// os.Root additionally prevents reads from escaping the pinned root.
func (files *orgFiles) checkPath(relative string) error {
	if !filepath.IsLocal(relative) {
		return refused("org configuration paths must stay inside the org and must not be symbolic links")
	}
	current := ""
	for _, part := range strings.Split(filepath.Clean(relative), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := files.root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return refused("cannot inspect org configuration paths")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return refused("org configuration paths must stay inside the org and must not be symbolic links")
		}
	}
	return nil
}

func readHandle(handle *os.File, label string, private bool) ([]byte, error) {
	info, err := handle.Stat()
	if err != nil {
		return nil, refused("cannot read " + label)
	}
	if !info.Mode().IsRegular() {
		return nil, refused(label + " must be a regular file")
	}
	if private {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Getuid() || info.Mode().Perm()&0o077 != 0 {
			return nil, refused("the org secret store must be owned by this user and have mode 600 or stricter")
		}
	}
	data, err := io.ReadAll(io.LimitReader(handle, maxBytes+1))
	if err != nil {
		return nil, refused("cannot read " + label)
	}
	if len(data) > maxBytes {
		return nil, refused(label + " exceeds 1 MiB")
	}
	return data, nil
}

func (files *orgFiles) read(relative, label string) ([]byte, error) {
	if err := files.checkPath(relative); err != nil {
		return nil, err
	}
	handle, err := files.root.OpenFile(relative, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, refused("cannot read " + label)
	}
	defer handle.Close()
	return readHandle(handle, label, false)
}

func parseTOML(data []byte, label string) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, refused(label + " must be valid UTF-8 TOML")
	}
	var value map[string]any
	if _, err := toml.Decode(string(data), &value); err != nil {
		return nil, refused(label + " must be valid UTF-8 TOML")
	}
	return value, nil
}

func (files *orgFiles) toml(relative, label string) (map[string]any, error) {
	data, err := files.read(relative, label)
	if err != nil {
		return nil, err
	}
	return parseTOML(data, label)
}

func tomlString(value string) string { encoded, _ := json.Marshal(value); return string(encoded) }

func (files *orgFiles) write(relative string, data []byte) error {
	if err := files.checkPath(relative); err != nil {
		return err
	}
	if _, err := files.root.Lstat(relative); err == nil {
		old, err := files.read(relative, "org channel configuration")
		if err != nil {
			return err
		}
		if bytes.Equal(old, data) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return refused("cannot inspect org channel configuration")
	}
	parent := filepath.Dir(relative)
	current := ""
	for _, part := range strings.Split(parent, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := files.root.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return refused("cannot create org channel configuration directory")
		}
		if err := files.checkPath(current); err != nil {
			return err
		}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return refused("cannot create org channel configuration temporary file")
	}
	temporary := filepath.Join(parent, ".tmp-"+hex.EncodeToString(random[:]))
	handle, err := files.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return refused("cannot write org channel configuration")
	}
	defer files.root.Remove(temporary)
	_, writeErr := handle.Write(data)
	if writeErr == nil {
		writeErr = handle.Sync()
	}
	closeErr := handle.Close()
	if writeErr != nil || closeErr != nil {
		return refused("cannot write org channel configuration")
	}
	if err := files.checkPath(relative); err != nil {
		return err
	}
	// Go 1.24 lacks Root.Rename. Both paths are checked before atomic rename.
	// Another process of this account racing directory moves is outside the
	// launcher's isolation model, as it is for the Python implementation.
	if err := os.Rename(filepath.Join(files.path, temporary), filepath.Join(files.path, relative)); err != nil {
		return refused("cannot replace org channel configuration")
	}
	return nil
}

func (files *orgFiles) lock() (*os.File, error) {
	if err := files.checkPath(".laneboss"); err != nil {
		return nil, err
	}
	handle, err := files.root.OpenFile(".laneboss", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, refused("cannot lock org channel configuration")
	}
	if err := syscall.Flock(int(handle.Fd()), syscall.LOCK_EX); err == nil {
		return handle, nil
	}
	handle.Close()
	if err := files.checkPath(".laneboss/.lock"); err != nil {
		return nil, err
	}
	handle, err = files.root.OpenFile(".laneboss/.lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, refused("cannot lock org channel configuration")
	}
	info, err := handle.Stat()
	if err != nil || !info.Mode().IsRegular() {
		handle.Close()
		return nil, refused("org channel lock must be a regular file")
	}
	if err := syscall.Flock(int(handle.Fd()), syscall.LOCK_EX); err != nil {
		handle.Close()
		return nil, refused("cannot lock org channel configuration")
	}
	return handle, nil
}
