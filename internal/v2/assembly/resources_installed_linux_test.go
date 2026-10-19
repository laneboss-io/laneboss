//go:build linux && laneboss_installed

package assembly

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func keyFixture(t *testing.T) (Installation, string, []byte) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("installed native key tests require the disposable root Linux test step and its private test root")
	}
	// The Linux test supervisor provisions this private root outside HOME.
	root, set := os.LookupEnv("LANEBOSS_SERVE_TEST_ROOT")
	if !set || !filepath.IsAbs(root) || filepath.Clean(root) != root || !strings.HasPrefix(root, "/opt/lb-v2-serve-") {
		t.Fatal("private Linux test root is required")
	}
	if err := privateDirectory(root, uint32(os.Geteuid())); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(root, "key-")
	if err != nil {
		t.Fatal(err)
	}
	// Retain fixture inputs for collection with the disposable test machine.
	keys := filepath.Join(directory, "keys")
	if err := os.Mkdir(keys, 0700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key) })
	sum := sha256.Sum256(key)
	handle := api.ID("key-" + hex.EncodeToString(sum[:])[:32])
	path := filepath.Join(keys, string(handle)+".key")
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(map[string]string{"schema": "laneboss.native-key.v2",
		"handle": string(handle), "algorithm": "aes-256-gcm", "key_file": string(handle) + ".key"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "enrollment.json"), metadata, 0600); err != nil {
		t.Fatal(err)
	}
	return Installation{Config: "serve-key", ServiceUID: uint32(os.Geteuid()),
		SecretDirectory: directory, SecretKeyHandle: handle}, path, key
}

func TestInstalledNativeKeyUnlocksBackend(t *testing.T) {
	installed, _, _ := keyFixture(t)
	for iteration := 0; iteration < 2; iteration++ {
		backend, err := installedSecrets(context.Background(), installed, wallClock{})
		if err != nil {
			t.Fatal("installed unlock failed", err)
		}
		material := make([]byte, 19+iteration)
		if _, err := rand.Read(material); err != nil {
			t.Fatal(err)
		}
		source := api.ID(fmt.Sprintf("source-%d", iteration))
		info := api.SecretInfo{Name: "CASE_SECRET", Version: fmt.Sprintf("v%d", iteration+1), SourceHandle: source,
			KeyID: installed.SecretKeyHandle}
		if _, err := backend.Store(context.Background(), info, api.SecretMaterial{Bytes: material}); err != nil {
			backend.Close()
			t.Fatal("installed key was not unlocked", err)
		}
		ciphertext, err := os.ReadFile(filepath.Join(installed.SecretDirectory, "records", string(source)+".json"))
		if err != nil || bytes.Contains(ciphertext, material) || bytes.Contains(ciphertext, []byte(base64.StdEncoding.EncodeToString(material))) {
			backend.Close()
			t.Fatal("native store did not seal input")
		}
		fetched, err := backend.Fetch(context.Background(), api.SecretGrant{ID: "grant",
			SourceHandle: source, Name: info.Name, Version: info.Version, Delivery: "env", Target: "TASK_TOKEN",
			ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano))})
		matches := err == nil && bytes.Equal(fetched.Bytes, material)
		clear(fetched.Bytes)
		clear(material)
		if !matches {
			backend.Close()
			t.Fatal("installed key could not decrypt")
		}
		if err := backend.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInstalledNativeKeyRejectsDrift(t *testing.T) {
	for _, kind := range []string{"changed", "mode", "link", "enrollment", "unknown file"} {
		t.Run(kind, func(t *testing.T) {
			installed, path, key := keyFixture(t)
			switch kind {
			case "changed":
				changed := append([]byte(nil), key...)
				changed[0] ^= 1
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
				clear(changed)
			case "mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := os.Link(path, path+".copy"); err != nil {
					t.Fatal(err)
				}
			case "enrollment":
				installed.SecretKeyHandle = "different-key"
			case "unknown file":
				if err := os.WriteFile(filepath.Join(installed.SecretDirectory, "old.json"), []byte("old"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			backend, err := installedSecrets(context.Background(), installed, wallClock{})
			if err == nil || backend != nil {
				t.Fatal("unsafe native key was accepted")
			}
			retained, readErr := os.ReadFile(path)
			if readErr != nil || len(retained) != 32 {
				t.Fatal("refused native key was removed")
			}
			clear(retained)
		})
	}
}
