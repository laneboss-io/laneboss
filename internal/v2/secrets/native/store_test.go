package native_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
)

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal("synthetic randomness unavailable")
	}
	return data
}

func requireCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("expected error code %s", code)
	}
}

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

func newStore(t *testing.T, directory string, key []byte) *native.Service {
	t.Helper()
	s, err := native.New(native.Dependencies{Directory: directory, Config: "secret-case", KeyHandle: "key-a", Clock: &testClock{now: time.Now().UTC()}})
	if err != nil {
		t.Fatal("cannot initialize native store")
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error("native store close failed")
		}
	})
	if key != nil {
		if err := s.Unlock(context.Background(), "key-a", bytes.NewReader(key)); err != nil {
			t.Fatal("cannot unlock synthetic native key")
		}
	}
	return s
}

func grantFor(info api.SecretInfo) api.SecretGrant {
	return api.SecretGrant{ID: "grant-a", SourceHandle: info.SourceHandle, Name: info.Name,
		Version: info.Version, Delivery: "env", Target: "TASK_TOKEN",
		ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))}
}

func put(t *testing.T, s *native.Service, value []byte, version string) api.SecretInfo {
	t.Helper()
	info, err := s.Store(context.Background(), api.SecretInfo{Name: "canary", Version: version}, api.SecretMaterial{Bytes: value})
	if err != nil {
		t.Fatal("synthetic enrollment failed")
	}
	return info
}

func readRecord(t *testing.T, directory string, info api.SecretInfo) (string, map[string]json.RawMessage) {
	t.Helper()
	name := filepath.Join(directory, string(info.SourceHandle)+".json")
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal("cannot read synthetic encrypted record")
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal("encrypted record is not JSON")
	}
	return name, record
}

func writeRecord(t *testing.T, name string, record map[string]json.RawMessage) {
	t.Helper()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal("cannot encode tampered synthetic record")
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal("cannot write tampered synthetic record")
	}
}

func TestEncryptedRoundTrip(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(testdir.New(t), "records")
	key, value := randomBytes(t, 32), randomBytes(t, 112)
	s := newStore(t, directory, nil)
	_, err := s.Store(ctx, api.SecretInfo{Name: "canary", Version: "one"}, api.SecretMaterial{Bytes: value})
	requireCode(t, err, api.CodePrerequisite)
	if err := s.Unlock(ctx, "key-a", bytes.NewReader(key)); err != nil {
		t.Fatal("cannot unlock synthetic key")
	}
	info := put(t, s, value, "one")
	got, err := s.Fetch(ctx, grantFor(info))
	if err != nil || !bytes.Equal(got.Bytes, value) {
		t.Fatal("secret round trip differs")
	}
	clear(got.Bytes)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal("cannot inspect encrypted-record files")
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal("cannot inspect encrypted-record bytes")
		}
		for _, hidden := range [][]byte{value, key, []byte(base64.StdEncoding.EncodeToString(value)),
			[]byte(base64.StdEncoding.EncodeToString(key))} {
			if bytes.Contains(data, hidden) {
				t.Fatal("plaintext synthetic value or key leaked to disk")
			}
		}
	}
	// Independently decrypt the persisted standard AES-GCM format. The observer
	// constructs AAD through a sorted map, without calling the implementation.
	_, record := readRecord(t, directory, info)
	var nonce, ciphertext []byte
	if err := json.Unmarshal(record["nonce"], &nonce); err != nil {
		t.Fatal("invalid persisted nonce")
	}
	if err := json.Unmarshal(record["ciphertext"], &ciphertext); err != nil {
		t.Fatal("invalid persisted ciphertext")
	}
	aad, err := json.Marshal(map[string]any{"config": "secret-case", "name": info.Name,
		"version": info.Version, "key_id": info.KeyID, "source_handle": info.SourceHandle,
		"revoked": false, "schema": "laneboss.secret-record.v2"})
	if err != nil {
		t.Fatal("cannot encode independent AAD")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("independent AES setup failed")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("independent GCM setup failed")
	}
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil || !bytes.Equal(plain, value) {
		t.Fatal("stored ciphertext failed independent decryption")
	}
	clear(plain)
	encoded, err := json.Marshal(api.SecretMaterial{Bytes: value})
	if err != nil || !bytes.Equal(encoded, []byte("{}")) {
		t.Fatal("secret material must never serialize")
	}
}

func TestRestartRecovery(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(testdir.New(t), "records")
	key, backupKey, value := randomBytes(t, 32), randomBytes(t, 32), randomBytes(t, 96)
	s := newStore(t, directory, key)
	info := put(t, s, value, "one")
	_, err := s.SealRecovery(ctx, "key-a", bytes.NewReader(key))
	requireCode(t, err, api.CodeInvalid)
	backup, err := s.SealRecovery(ctx, "key-a", bytes.NewReader(backupKey))
	if err != nil || bytes.Contains(backup, key) || bytes.Contains(backup, backupKey) {
		t.Fatal("recovery backup failed or exposed a key")
	}
	if err := s.Close(); err != nil {
		t.Fatal("cannot close first store")
	}
	restarted := newStore(t, directory, nil)
	_, err = restarted.Fetch(ctx, grantFor(info))
	requireCode(t, err, api.CodePrerequisite)
	err = restarted.Unlock(ctx, "key-a", bytes.NewReader(randomBytes(t, 32)))
	requireCode(t, err, api.CodeIntegrity)
	err = restarted.Recover(ctx, bytes.NewReader(backup), bytes.NewReader(randomBytes(t, 32)))
	requireCode(t, err, api.CodeIntegrity)
	_, err = restarted.Fetch(ctx, grantFor(info))
	requireCode(t, err, api.CodePrerequisite)
	if err := restarted.Recover(ctx, bytes.NewReader(backup), bytes.NewReader(backupKey)); err != nil {
		t.Fatal("valid protected recovery failed")
	}
	got, err := restarted.Fetch(ctx, grantFor(info))
	if err != nil || !bytes.Equal(got.Bytes, value) {
		t.Fatal("recovered secret differs")
	}
	clear(got.Bytes)
	restarted.Lock()
	_, err = restarted.Fetch(ctx, grantFor(info))
	requireCode(t, err, api.CodePrerequisite)
}

func TestRecordTamper(t *testing.T) {
	changes := []string{"config", "name", "version", "key_id", "source_handle", "revoked", "nonce", "ciphertext"}
	for _, change := range changes {
		t.Run(change, func(t *testing.T) {
			directory := filepath.Join(testdir.New(t), "records")
			key := randomBytes(t, 32)
			s := newStore(t, directory, key)
			if err := s.Unlock(context.Background(), "key-b", bytes.NewReader(key)); err != nil {
				t.Fatal("cannot unlock alternate key ID control")
			}
			value := randomBytes(t, 80)
			info := put(t, s, value, "one")
			name, record := readRecord(t, directory, info)
			switch change {
			case "config":
				record[change] = json.RawMessage(`"other-case"`)
			case "nonce", "ciphertext":
				var data []byte
				if err := json.Unmarshal(record[change], &data); err != nil {
					t.Fatal("cannot parse synthetic ciphertext")
				}
				data[0] ^= 1
				encoded, err := json.Marshal(data)
				if err != nil {
					t.Fatal("cannot encode synthetic ciphertext")
				}
				record[change] = encoded
			default:
				var meta map[string]json.RawMessage
				if err := json.Unmarshal(record["info"], &meta); err != nil {
					t.Fatal("cannot parse synthetic record metadata")
				}
				meta[change] = json.RawMessage(`"changed"`)
				if change == "key_id" {
					meta[change] = json.RawMessage(`"key-b"`)
				}
				if change == "revoked" {
					meta[change] = json.RawMessage("true")
				}
				encoded, err := json.Marshal(meta)
				if err != nil {
					t.Fatal("cannot encode synthetic metadata")
				}
				record["info"] = encoded
			}
			writeRecord(t, name, record)
			grant := grantFor(info)
			switch change {
			case "name":
				grant.Name = "changed"
			case "version":
				grant.Version = "changed"
			case "source_handle":
				moved := filepath.Join(directory, "changed.json")
				if err := os.Rename(name, moved); err != nil {
					t.Fatal("cannot move altered source-handle control")
				}
				grant.SourceHandle = "changed"
			}
			got, err := s.Fetch(context.Background(), grant)
			requireCode(t, err, api.CodeIntegrity)
			if len(got.Bytes) != 0 {
				t.Fatal("tampered record disclosed material")
			}
		})
	}
}

func TestImmutableAndRevoke(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(testdir.New(t), "records")
	s := newStore(t, directory, randomBytes(t, 32))
	value := randomBytes(t, 72)
	info := put(t, s, value, "one")
	path := filepath.Join(directory, string(info.SourceHandle)+".json")
	beforeRetry, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot retain exact-retry ciphertext control")
	}
	if got, err := s.Store(ctx, info, api.SecretMaterial{Bytes: value}); err != nil || got != info {
		t.Fatal("exact store retry differs")
	}
	afterRetry, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(beforeRetry, afterRetry) {
		t.Fatal("exact backend retry rewrote ciphertext")
	}
	_, err = s.Store(ctx, info, api.SecretMaterial{Bytes: randomBytes(t, 72)})
	requireCode(t, err, api.CodeConflict)
	_, err = s.Store(ctx, api.SecretInfo{Name: info.Name, Version: info.Version}, api.SecretMaterial{Bytes: value})
	requireCode(t, err, api.CodeConflict)
	newInfo := put(t, s, randomBytes(t, 72), "two")
	_, first := readRecord(t, directory, info)
	_, second := readRecord(t, directory, newInfo)
	if bytes.Equal(first["nonce"], second["nonce"]) {
		t.Fatal("record versions reused an encryption nonce")
	}
	wrong := info
	wrong.Version = "stale"
	requireCode(t, s.Revoke(ctx, wrong), api.CodeConflict)
	if err := s.Revoke(ctx, info); err != nil {
		t.Fatal("source revocation failed")
	}
	if err := s.Revoke(ctx, info); err != nil {
		t.Fatal("source revocation retry failed")
	}
	got, err := s.Fetch(ctx, grantFor(info))
	requireCode(t, err, api.CodeForbidden)
	if len(got.Bytes) != 0 {
		t.Fatal("revoked source disclosed bytes")
	}
	_, revoked := readRecord(t, directory, info)
	if bytes.Equal(first["nonce"], revoked["nonce"]) {
		t.Fatal("revocation reused a record nonce")
	}
}

func TestConcurrentWriters(t *testing.T) {
	directory := filepath.Join(testdir.New(t), "records")
	key := randomBytes(t, 32)
	one, two := newStore(t, directory, key), newStore(t, directory, key)
	value := randomBytes(t, 80)
	var group sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		group.Go(func() {
			selected := one
			if i%2 == 1 {
				selected = two
			}
			_, err := selected.Store(context.Background(), api.SecretInfo{Name: "raced", Version: "one"}, api.SecretMaterial{Bytes: value})
			results <- err
		})
	}
	group.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			requireCode(t, err, api.CodeConflict)
		}
	}
	if succeeded != 1 {
		t.Fatal("concurrent writers did not serialize the immutable version")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 3 {
		t.Fatal("concurrent store retained unexpected files")
	}
	check, err := os.ReadFile(filepath.Join(directory, ".key-key-a.json"))
	if err != nil || !bytes.Contains(check, []byte(`"laneboss.secret-key-check.v2"`)) {
		t.Fatal("concurrent store lost its sealed key enrollment")
	}
}

func TestEmptyKeyEnrollment(t *testing.T) {
	directory := filepath.Join(testdir.New(t), "records")
	key := randomBytes(t, 32)
	s := newStore(t, directory, key)
	data, err := os.ReadFile(filepath.Join(directory, ".key-key-a.json"))
	if err != nil {
		t.Fatal("empty store did not persist sealed key enrollment")
	}
	var record struct {
		Schema     string `json:"schema"`
		Config     string `json:"config"`
		KeyID      api.ID `json:"key_id"`
		Nonce      []byte `json:"nonce"`
		Ciphertext []byte `json:"ciphertext"`
	}
	if err := json.Unmarshal(data, &record); err != nil || record.Schema != "laneboss.secret-key-check.v2" ||
		record.Config != "secret-case" || record.KeyID != "key-a" || len(record.Nonce) != 12 || len(record.Ciphertext) != 16 {
		t.Fatal("sealed key enrollment has invalid identity or bounds")
	}
	aad, err := json.Marshal(map[string]any{"schema": record.Schema, "config": record.Config, "key_id": record.KeyID})
	if err != nil {
		t.Fatal("cannot encode independent key-check AAD")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("cannot initialize independent key-check AES")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("cannot initialize independent key-check GCM")
	}
	plain, err := aead.Open(nil, record.Nonce, record.Ciphertext, aad)
	if err != nil || len(plain) != 0 {
		t.Fatal("key enrollment failed independent authentication")
	}
	clear(plain)
	if err := s.Close(); err != nil {
		t.Fatal("cannot restart empty enrolled store")
	}
	restarted := newStore(t, directory, nil)
	requireCode(t, restarted.Unlock(context.Background(), "key-a", bytes.NewReader(randomBytes(t, 32))), api.CodeIntegrity)
	unchanged, err := os.ReadFile(filepath.Join(directory, ".key-key-a.json"))
	if err != nil || !bytes.Equal(data, unchanged) {
		t.Fatal("wrong key replaced sealed enrollment")
	}
	if err := restarted.Unlock(context.Background(), "key-a", bytes.NewReader(key)); err != nil {
		t.Fatal("correct empty-store key was refused")
	}
}

func TestNativeClock(t *testing.T) {
	clock := &testClock{now: time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)}
	directory := filepath.Join(testdir.New(t), "records")
	s, err := native.New(native.Dependencies{Directory: directory, Config: "secret-case", KeyHandle: "key-a", Clock: clock})
	if err != nil {
		t.Fatal("cannot initialize clocked store")
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error("cannot close clocked store")
		}
	})
	if err := s.Unlock(context.Background(), "key-a", bytes.NewReader(randomBytes(t, 32))); err != nil {
		t.Fatal("cannot unlock clocked store")
	}
	value := randomBytes(t, 71)
	info := put(t, s, value, "one")
	grant := grantFor(info)
	grant.ExpiresAt = api.Timestamp(clock.now.Add(time.Minute).Format(time.RFC3339Nano))
	got, err := s.Fetch(context.Background(), grant)
	if err != nil || !bytes.Equal(got.Bytes, value) {
		t.Fatal("native injected clock did not allow live grant")
	}
	clear(got.Bytes)
	clock.now = clock.now.Add(time.Minute)
	_, err = s.Fetch(context.Background(), grant)
	requireCode(t, err, api.CodeForbidden)
}

func TestNativeRequiresClock(t *testing.T) {
	directory := filepath.Join(testdir.New(t), "records")
	s, err := native.New(native.Dependencies{Directory: directory, Config: "secret-case", KeyHandle: "key-a"})
	if s != nil {
		if closeErr := s.Close(); closeErr != nil {
			t.Fatal("cannot close unclocked store")
		}
	}
	requireCode(t, err, api.CodePrerequisite)
}

func TestRevocationOperationAAD(t *testing.T) {
	directory := filepath.Join(testdir.New(t), "records")
	s := newStore(t, directory, randomBytes(t, 32))
	info := put(t, s, randomBytes(t, 88), "one")
	err := s.WithMutation(context.Background(), "operation-a", func(backend api.SecretBackend, infos []api.SecretInfo) error {
		if len(infos) != 1 || infos[0] != info {
			t.Fatal("protected mutation lost authenticated metadata")
		}
		return backend.Revoke(context.Background(), info)
	})
	if err != nil {
		t.Fatal("cannot create operation-bound tombstone")
	}
	path, record := readRecord(t, directory, info)
	if !bytes.Equal(record["revocation_id"], []byte(`"operation-a"`)) {
		t.Fatal("tombstone omitted its original operation identity")
	}
	record["revocation_id"] = json.RawMessage(`"operation-b"`)
	writeRecord(t, path, record)
	_, err = s.Fetch(context.Background(), grantFor(info))
	requireCode(t, err, api.CodeIntegrity)
}

func TestMutationScopeEnd(t *testing.T) {
	s := newStore(t, filepath.Join(testdir.New(t), "records"), randomBytes(t, 32))
	var retained api.SecretBackend
	if err := s.WithMutation(context.Background(), "operation-a", func(backend api.SecretBackend, infos []api.SecretInfo) error {
		if len(infos) != 0 {
			t.Fatal("new mutation scope unexpectedly contained a record")
		}
		retained = backend
		return nil
	}); err != nil {
		t.Fatal("cannot open protected mutation scope")
	}
	_, err := retained.Store(context.Background(), api.SecretInfo{Name: "canary", Version: "one"}, api.SecretMaterial{Bytes: randomBytes(t, 84)})
	requireCode(t, err, api.CodeForbidden)
}

func TestUnsafeFilesRefuse(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			directory := filepath.Join(testdir.New(t), "records")
			s := newStore(t, directory, randomBytes(t, 32))
			info := put(t, s, randomBytes(t, 64), "one")
			name := filepath.Join(directory, string(info.SourceHandle)+".json")
			switch kind {
			case "symlink":
				outside := filepath.Join(testdir.New(t), "outside")
				if err := os.WriteFile(outside, randomBytes(t, 80), 0600); err != nil {
					t.Fatal("cannot create harmless outside control")
				}
				if err := os.Remove(name); err != nil {
					t.Fatal("cannot replace synthetic record")
				}
				if err := os.Symlink(outside, name); err != nil {
					t.Fatal("cannot create synthetic symlink")
				}
			case "hardlink":
				if err := os.Link(name, filepath.Join(directory, "alias.json")); err != nil {
					t.Fatal("cannot create synthetic hardlink")
				}
			case "public":
				if err := os.Chmod(name, 0644); err != nil {
					t.Fatal("cannot set synthetic public mode")
				}
			}
			got, err := s.Fetch(context.Background(), grantFor(info))
			requireCode(t, err, api.CodeIntegrity)
			if len(got.Bytes) != 0 {
				t.Fatal("unsafe record returned material")
			}
		})
	}
}

func TestRecoveryTamper(t *testing.T) {
	for _, field := range []string{"config", "key_id", "nonce", "ciphertext"} {
		t.Run(field, func(t *testing.T) {
			ctx := context.Background()
			directory := filepath.Join(testdir.New(t), "records")
			key, recoveryKey := randomBytes(t, 32), randomBytes(t, 32)
			s := newStore(t, directory, key)
			info := put(t, s, randomBytes(t, 80), "one")
			backup, err := s.SealRecovery(ctx, "key-a", bytes.NewReader(recoveryKey))
			if err != nil {
				t.Fatal("cannot seal recovery control")
			}
			var object map[string]json.RawMessage
			if err := json.Unmarshal(backup, &object); err != nil {
				t.Fatal("cannot decode recovery control")
			}
			if field == "config" || field == "key_id" {
				object[field] = json.RawMessage(`"other"`)
			} else {
				var data []byte
				if err := json.Unmarshal(object[field], &data); err != nil {
					t.Fatal("cannot decode recovery ciphertext control")
				}
				data[0] ^= 1
				object[field], err = json.Marshal(data)
				if err != nil {
					t.Fatal("cannot encode recovery ciphertext control")
				}
			}
			changed, err := json.Marshal(object)
			if err != nil {
				t.Fatal("cannot encode altered recovery control")
			}
			s.Lock()
			requireCode(t, s.Recover(ctx, bytes.NewReader(changed), bytes.NewReader(recoveryKey)), api.CodeIntegrity)
			_, err = s.Fetch(ctx, grantFor(info))
			requireCode(t, err, api.CodePrerequisite)
		})
	}
}

func TestVersionedKeys(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(testdir.New(t), "records")
	firstKey, secondKey := randomBytes(t, 32), randomBytes(t, 32)
	firstValue, secondValue := randomBytes(t, 68), randomBytes(t, 68)
	s := newStore(t, directory, firstKey)
	first := put(t, s, firstValue, "one")
	if err := s.Close(); err != nil {
		t.Fatal("cannot close first key version")
	}
	rotated, err := native.New(native.Dependencies{Directory: directory, Config: "secret-case", KeyHandle: "key-b", Clock: &testClock{now: time.Now().UTC()}})
	if err != nil {
		t.Fatal("cannot open next key generation")
	}
	t.Cleanup(func() {
		if err := rotated.Close(); err != nil {
			t.Error("cannot close next key generation")
		}
	})
	if err := rotated.Unlock(ctx, "key-a", bytes.NewReader(firstKey)); err != nil {
		t.Fatal("cannot unlock previous key generation")
	}
	if err := rotated.Unlock(ctx, "key-b", bytes.NewReader(secondKey)); err != nil {
		t.Fatal("cannot unlock current key generation")
	}
	second := put(t, rotated, secondValue, "two")
	if first.KeyID == second.KeyID || second.KeyID != "key-b" {
		t.Fatal("new record did not use the current protected key")
	}
	for _, sample := range []struct {
		info  api.SecretInfo
		value []byte
	}{{first, firstValue}, {second, secondValue}} {
		got, err := rotated.Fetch(ctx, grantFor(sample.info))
		if err != nil || !bytes.Equal(got.Bytes, sample.value) {
			t.Fatal("key-versioned record differs")
		}
		clear(got.Bytes)
	}
}

func TestOrphanCiphertext(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(testdir.New(t), "records")
	key, value := randomBytes(t, 32), randomBytes(t, 77)
	s := newStore(t, directory, key)
	info := put(t, s, value, "one")
	if err := s.Close(); err != nil {
		t.Fatal("cannot close before crash staging control")
	}
	orphan := filepath.Join(directory, "interrupted.tmp")
	partial := randomBytes(t, 91)
	if err := os.WriteFile(orphan, partial, 0600); err != nil {
		t.Fatal("cannot create incomplete ciphertext staging control")
	}
	restarted := newStore(t, directory, key)
	got, err := restarted.Fetch(ctx, grantFor(info))
	if err != nil || !bytes.Equal(got.Bytes, value) {
		t.Fatal("incomplete staging replaced or hid the committed record")
	}
	clear(got.Bytes)
	kept, err := os.ReadFile(orphan)
	if err != nil || !bytes.Equal(kept, partial) {
		t.Fatal("incomplete ciphertext evidence was changed")
	}
}

func TestGrantMismatch(t *testing.T) {
	s := newStore(t, filepath.Join(testdir.New(t), "records"), randomBytes(t, 32))
	info := put(t, s, randomBytes(t, 99), "one")
	grant := grantFor(info)
	grant.Name = "ungranted"
	_, err := s.Fetch(context.Background(), grant)
	requireCode(t, err, api.CodeForbidden)
	grant = grantFor(info)
	grant.Version = "other"
	_, err = s.Fetch(context.Background(), grant)
	requireCode(t, err, api.CodeForbidden)
	grant = grantFor(info)
	grant.ExpiresAt = api.Timestamp(time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano))
	_, err = s.Fetch(context.Background(), grant)
	requireCode(t, err, api.CodeForbidden)
}

func TestTypedNilKeyInputs(t *testing.T) {
	defer func() {
		if recover() != nil {
			t.Error("missing key channel panicked instead of returning a typed error")
		}
	}()
	ctx := context.Background()
	s := newStore(t, filepath.Join(testdir.New(t), "records"), nil)
	var absent *bytes.Reader
	requireCode(t, s.Unlock(ctx, "key-a", absent), api.CodeInvalid)
	_, err := s.SealRecovery(ctx, "key-a", absent)
	requireCode(t, err, api.CodeInvalid)
	requireCode(t, s.Recover(ctx, absent, absent), api.CodeInvalid)
}

func TestDirectoryModeDrift(t *testing.T) {
	directory := filepath.Join(testdir.New(t), "records")
	s := newStore(t, directory, randomBytes(t, 32))
	value := randomBytes(t, 81)
	info := put(t, s, value, "one")
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal("cannot set directory privacy control")
	}
	got, err := s.Fetch(context.Background(), grantFor(info))
	requireCode(t, err, api.CodeIntegrity)
	if len(got.Bytes) != 0 {
		t.Fatal("unsafe directory released material")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal("cannot restore directory privacy control")
	}
	got, err = s.Fetch(context.Background(), grantFor(info))
	if err != nil || !bytes.Equal(got.Bytes, value) {
		t.Fatal("restored private directory did not recover")
	}
	clear(got.Bytes)
}

func TestLockIdentityDrift(t *testing.T) {
	directory := filepath.Join(testdir.New(t), "records")
	s := newStore(t, directory, randomBytes(t, 32))
	value := randomBytes(t, 85)
	info := put(t, s, value, "one")
	lock, saved := filepath.Join(directory, ".lock"), filepath.Join(directory, "saved-lock")
	if err := os.Rename(lock, saved); err != nil {
		t.Fatal("cannot retain lock identity control")
	}
	if err := os.WriteFile(lock, nil, 0600); err != nil {
		t.Fatal("cannot create replacement lock control")
	}
	got, err := s.Fetch(context.Background(), grantFor(info))
	requireCode(t, err, api.CodeIntegrity)
	if len(got.Bytes) != 0 {
		t.Fatal("replaced lock released material")
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal("cannot collect replacement lock control")
	}
	if err := os.Rename(saved, lock); err != nil {
		t.Fatal("cannot restore original lock identity")
	}
	got, err = s.Fetch(context.Background(), grantFor(info))
	if err != nil || !bytes.Equal(got.Bytes, value) {
		t.Fatal("restored lock identity did not recover")
	}
	clear(got.Bytes)
}
