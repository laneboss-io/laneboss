//go:build linux

package assembly

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/native"
)

// Exercise the actual installed constructor with test-owned protected inputs.
// This installs no unit, enrolls no human and makes no root-installation claim.
func TestInstalledRestartIsUnlocked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("installed constructor component test requires an unprivileged test UID")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(home, ".lb-v2-it2-restart-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(base, "keys")
	if err := os.Mkdir(keys, 0700); err != nil {
		t.Fatal(err)
	}
	key, value := make([]byte, 32), make([]byte, 83)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	defer clear(value)
	sum := sha256.Sum256(key)
	handle := api.ID("key-" + hex.EncodeToString(sum[:])[:32])
	keyPath := filepath.Join(keys, string(handle)+".key")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	enrollment, err := json.Marshal(map[string]string{"schema": "laneboss.native-key.v2", "handle": string(handle), "algorithm": "aes-256-gcm", "key_file": string(handle) + ".key"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "enrollment.json"), enrollment, 0600); err != nil {
		t.Fatal(err)
	}
	installed := Installation{Config: "restart-component", ServiceUID: uint32(os.Geteuid()), SecretDirectory: base, SecretKeyHandle: handle}
	first, err := installedSecrets(context.Background(), installed, wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	info, storeErr := first.Store(context.Background(), api.SecretInfo{Name: "restart-canary", Version: "one"}, api.SecretMaterial{Bytes: value})
	if err := errors.Join(storeErr, first.Close()); err != nil {
		t.Fatal(err)
	}
	restarted, err := installedSecrets(context.Background(), installed, wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	grant := api.SecretGrant{ID: "restart-grant", Name: info.Name, Version: info.Version, SourceHandle: info.SourceHandle, Delivery: "env", Target: "TASK_TOKEN", ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}
	actual, fetchErr := restarted.Fetch(context.Background(), grant)
	equal := bytes.Equal(actual.Bytes, value)
	clear(actual.Bytes)
	if err := errors.Join(fetchErr, restarted.Close()); err != nil || !equal {
		t.Fatal("ordinary installed restart failed to reload its protected key", err)
	}
	// The locked cell must deliberately omit the protected unlock handoff.
	locked, err := native.New(native.Dependencies{Config: installed.Config, Directory: filepath.Join(base, "records"), KeyHandle: handle, Clock: wallClock{}})
	if err != nil {
		t.Fatal(err)
	}
	actual, fetchErr = locked.Fetch(context.Background(), grant)
	if len(actual.Bytes) != 0 {
		clear(actual.Bytes)
		t.Fatal("unopened native backend returned material")
	}
	var typed *api.Error
	if !errors.As(fetchErr, &typed) || typed.Code != api.CodePrerequisite {
		t.Fatal("locked control did not reach its protected unlock prerequisite", fetchErr)
	}
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
	// A missing installed key refuses construction; it is not an unlocked or
	// recovered success and must not be reported as the locked running service.
	if err := os.Rename(keyPath, keyPath+".held"); err != nil {
		t.Fatal(err)
	}
	missing, err := installedSecrets(context.Background(), installed, wallClock{})
	if missing != nil {
		missing.Close()
		t.Fatal("missing installed key returned a backend")
	}
	if err == nil {
		t.Fatal("missing protected key was accepted by installed construction")
	}
}
