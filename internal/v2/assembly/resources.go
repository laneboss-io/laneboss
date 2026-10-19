package assembly

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/store"
)

// The real host owns this store and closes its dependent resources after its
// workers drain. Failed composition uses the same close path.
type ownedState struct {
	// Preserve the concrete store's private enrollment, launch recovery and
	// dispatch ports. Embedding a narrower interface silently hides those ports.
	*store.Service
	closers ownedClosers
}

func (s *ownedState) Close() error { return s.closers.Close() }

type ownedClosers struct {
	store     io.Closer
	resources []io.Closer
	once      sync.Once
	closeErr  error
}

func (s *ownedClosers) Close() error {
	s.once.Do(func() {
		for index := len(s.resources) - 1; index >= 0; index-- {
			s.closeErr = errors.Join(s.closeErr, s.resources[index].Close())
		}
		s.closeErr = errors.Join(s.closeErr, s.store.Close())
	})
	return s.closeErr
}

func installedSecrets(ctx context.Context, installed Installation, clock api.Clock) (_ *native.Service, resultErr error) {
	if err := privateDirectory(installed.SecretDirectory, installed.ServiceUID); err != nil {
		return nil, installedCheckFailure("native secret directory", err)
	}
	entries, err := os.ReadDir(installed.SecretDirectory)
	if err != nil {
		return nil, installError("secret directory cannot be read")
	}
	for _, entry := range entries {
		if entry.Name() != "keys" && entry.Name() != "records" {
			return nil, installError("secret directory layout differs")
		}
	}
	// Key enrollment and ciphertext records have distinct private directories.
	// Native.Unlock enumerates only encrypted record files in its directory.
	records := filepath.Join(installed.SecretDirectory, "records")
	backend, err := native.New(native.Dependencies{Config: installed.Config,
		Directory: records, KeyHandle: installed.SecretKeyHandle, Clock: clock})
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, backend.Close())
		}
	}()
	keys := filepath.Join(installed.SecretDirectory, "keys")
	if err := privateDirectory(keys, installed.ServiceUID); err != nil {
		return nil, installedCheckFailure("native key directory", err)
	}
	metadata, err := readServiceFile(filepath.Join(keys, "enrollment.json"), installed.ServiceUID, 4096)
	if err != nil {
		return nil, installedCheckFailure("native key enrollment", err)
	}
	var enrollment struct {
		Schema    string `json:"schema"`
		Handle    api.ID `json:"handle"`
		Algorithm string `json:"algorithm"`
		KeyFile   string `json:"key_file"`
	}
	if err := api.DecodeObject(metadata, &enrollment); err != nil {
		return nil, err
	}
	if enrollment.Schema != "laneboss.native-key.v2" || enrollment.Handle != installed.SecretKeyHandle ||
		enrollment.Algorithm != "aes-256-gcm" || enrollment.KeyFile != string(installed.SecretKeyHandle)+".key" ||
		filepath.Base(enrollment.KeyFile) != enrollment.KeyFile {
		return nil, installError("native key enrollment differs")
	}
	key, err := readServiceFile(filepath.Join(keys, enrollment.KeyFile), installed.ServiceUID, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	sum := sha256.Sum256(key)
	if len(key) != 32 || enrollment.Handle != api.ID("key-"+hex.EncodeToString(sum[:])[:32]) {
		return nil, installError("native key pin differs")
	}
	if err := backend.Unlock(ctx, enrollment.Handle, bytes.NewReader(key)); err != nil {
		return nil, err
	}
	return backend, nil
}

func readServiceFile(path string, uid uint32, limit int64) (result []byte, resultErr error) {
	if err := protectedParents(filepath.Dir(path), uid); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || !owned(before, uid) || before.Mode().Perm() != 0600 ||
		before.Size() < 1 || before.Size() > limit {
		return nil, installError("unsafe private installed input")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, installError("private installed input has links")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, installError("private installed input cannot open")
	}
	defer func() {
		if err := file.Close(); err != nil {
			clear(result)
			result = nil
			resultErr = installError("private installed input close failed")
		}
	}()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) ||
		!owned(after, uid) || after.Mode().Perm() != 0600 {
		return nil, installError("private installed input changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != before.Size() {
		clear(data)
		return nil, installError("private installed input read failed")
	}
	current, err := file.Stat()
	if err != nil || !os.SameFile(before, current) || current.Size() != before.Size() ||
		!current.ModTime().Equal(before.ModTime()) || !owned(current, uid) || current.Mode().Perm() != 0600 {
		clear(data)
		return nil, installError("private input changed during read")
	}
	return data, nil
}
