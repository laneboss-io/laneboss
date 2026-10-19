package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
)

func random(t *testing.T, n int) []byte {
	t.Helper()
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNativeJournal(t *testing.T) {
	root := testdir.New(t)
	directory, keyPath := filepath.Join(root, "records"), filepath.Join(root, "key")
	key, material := random(t, 32), random(t, 96)
	defer clear(key)
	defer clear(material)
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	backend, err := native.New(native.Dependencies{Config: "journal-test", Directory: directory, KeyHandle: "journal-key", Clock: realClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if err := backend.Unlock(context.Background(), "journal-key", bytes.NewReader(key)); err != nil {
		t.Fatal(err)
	}
	profileID, loginID, slotID := api.ID("journal-profile"), api.ID("journal-login"), api.ID("journal-slot")
	var lease bstate.RefreshLease
	err = backend.WithBroker(context.Background(), func(j bstate.Journal) error {
		if err := j.Write("profile", profileID, bstate.Profile{ID: profileID, Config: "journal-test", LoginID: loginID, Generation: 3,
			Models: []string{"journal-model"}, VendorVersions: []string{"1.0.0"}, RefreshFields: []string{}}); err != nil {
			return err
		}
		if err := j.Write("login", loginID, bstate.Login{ID: loginID, SlotID: slotID, RefreshSlotID: slotID, Material: material}); err != nil {
			return err
		}
		if err := j.Write("slot", slotID, bstate.Slot{ID: slotID, Config: "journal-test", ProfileID: profileID,
			LoginID: loginID, ProjectionID: "journal-projection", Target: api.LifeRef{LifeID: "journal-life", Run: 2}, Material: material, Returned: []byte{}}); err != nil {
			return err
		}
		var err error
		lease, err = j.AcquireRefreshLease(loginID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	in := input{Mode: "journal", Config: "journal-test", Directory: directory, Key: "journal-key",
		KeyFD: inputFD(t, keyPath), Profiles: []api.ID{profileID}, Slots: []api.ID{slotID}}
	out, err := observe(context.Background(), in)
	if err != nil {
		t.Fatal("native journal rejected its retained encrypted fixture", err)
	}
	if err != nil || len(out.Profiles) != 1 || !out.Profiles[0].RefreshLocked {
		t.Fatal("native journal ignored the actual held refresh lock")
	}
	if len(out.Slots) != 1 || out.Slots[0].MaterialSHA != hash(material) || out.Slots[0].ProjectionID != "journal-projection" {
		t.Fatal("native journal ignored the actual encrypted slot")
	}
	raw, err := json.Marshal(out)
	if err != nil || bytes.Contains(raw, material) || bytes.Contains(raw, key) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(material))) {
		t.Fatal("native journal disclosed its protected input")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	in.KeyFD = inputFD(t, keyPath)
	out, err = observe(context.Background(), in)
	if err != nil || len(out.Profiles) != 1 || out.Profiles[0].RefreshLocked {
		t.Fatal("native journal invented a refresh lock after its actual close")
	}
}

func inputFD(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fd // observe owns and closes this exact descriptor.
}

func TestNativeHeadless(t *testing.T) {
	root := testdir.New(t)
	directory, keyPath := filepath.Join(root, "records"), filepath.Join(root, "key")
	key, material := random(t, 32), random(t, 96)
	defer clear(key)
	defer clear(material)
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	backend, err := native.New(native.Dependencies{Config: "headless-test", Directory: directory, KeyHandle: "headless-key", Clock: realClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if err := backend.Unlock(context.Background(), "headless-key", bytes.NewReader(key)); err != nil {
		t.Fatal(err)
	}
	info, err := backend.Store(context.Background(), api.SecretInfo{Name: "other-source", Version: "v1"}, api.SecretMaterial{Bytes: material})
	if err != nil {
		t.Fatal(err)
	}
	expiry := api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
	enrolled := bstate.Profile{Schema: "laneboss.credential-profile.v2", ID: "headless-profile", Config: "headless-test", LoginID: "headless-login", Generation: 1,
		Driver: api.DriverClaudock, Mode: "claudock-headless", Models: []string{"headless-model"}, VendorVersions: []string{"1.0.0"}, RefreshFields: []string{},
		Provider: "native-unit", ExpiresAt: expiry, Runtime: api.Executable{ID: "unit-runtime", Version: "1.0.0", SHA256: api.Digest(hash(random(t, 64)))},
		Evidence: api.BlobRef{ID: "unit-evidence", Class: "credential_evidence", Bytes: 64, SHA256: api.Digest(hash(random(t, 64)))},
		Source: api.SecretGrant{ID: "headless-source", Name: info.Name, Version: info.Version, SourceHandle: info.SourceHandle,
			Delivery: "file", Target: "headless-login.json", ExpiresAt: expiry}}
	write := func() error {
		return backend.WithBroker(context.Background(), func(j bstate.Journal) error {
			return j.Write("profile", enrolled.ID, enrolled)
		})
	}
	if err := write(); err != nil {
		t.Fatal(err)
	}
	in := input{Mode: "journal", Config: "headless-test", Directory: directory, Key: "headless-key", KeyFD: inputFD(t, keyPath), Profiles: []api.ID{enrolled.ID}}
	out, err := observe(context.Background(), in)
	if err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
			t.Fatal("native headless fixture failed before the login boundary", err)
		}
		t.Fatal("native headless profile required a nonexistent login")
	}
	if len(out.Profiles) != 1 || out.Profiles[0].Source != enrolled.Source || out.Profiles[0].LoginPresent || out.Profiles[0].Mode != enrolled.Mode {
		t.Fatal("native headless metadata differs from its protected enrollment")
	}
	enrolled.Mode = "codex-file"
	enrolled.Driver, enrolled.AccountSHA256 = api.DriverCodex, api.Digest(hash(random(t, 64)))
	if err := write(); err != nil {
		t.Fatal(err)
	}
	in.KeyFD = inputFD(t, keyPath)
	_, err = observe(context.Background(), in)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
		t.Fatal("native file profile accepted a missing canonical login")
	}
}

func TestNativeRecovery(t *testing.T) {
	root := testdir.New(t)
	directory := filepath.Join(root, "records")
	key, recovery, material := random(t, 32), random(t, 32), random(t, 96)
	defer clear(key)
	defer clear(recovery)
	defer clear(material)
	keyPath, recoveryPath := filepath.Join(root, "key"), filepath.Join(root, "recovery")
	for path, data := range map[string][]byte{keyPath: key, recoveryPath: recovery} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	backend, err := native.New(native.Dependencies{Config: "native-test", Directory: directory, KeyHandle: "native-key", Clock: realClock{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Unlock(context.Background(), "native-key", bytes.NewReader(key)); err != nil {
		t.Fatal(err)
	}
	info, err := backend.Store(context.Background(), api.SecretInfo{Name: "canary", Version: "v1"}, api.SecretMaterial{Bytes: material})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	grant := api.SecretGrant{ID: "native-grant", SourceHandle: info.SourceHandle, Name: info.Name, Version: info.Version,
		Delivery: "env", Target: "TASK_TOKEN", ExpiresAt: api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))}
	in := input{Mode: "locked", Config: "native-test", Directory: directory, Key: "native-key", Grants: []api.SecretGrant{grant}, KeyFD: inputFD(t, keyPath)}
	out, err := observe(context.Background(), in)
	unix.Close(in.KeyFD) // Locked mode must not consume the supplied key reader.
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || len(out.Digests) != 0 {
		t.Fatal("native restart consumed a key without protected unlock")
	}
	in.Mode, in.KeyFD, in.RecoveryFD = "backup", inputFD(t, keyPath), inputFD(t, recoveryPath)
	backup, err := observe(context.Background(), in)
	if err != nil || len(backup.Backup) == 0 {
		t.Fatal("native backup did not use the actual enrolled key", err)
	}
	backupPath := filepath.Join(root, "backup")
	if err := os.WriteFile(backupPath, backup.Backup, 0600); err != nil {
		t.Fatal(err)
	}
	in.Mode, in.KeyFD, in.BackupFD, in.RecoveryFD = "recover", 0, inputFD(t, backupPath), inputFD(t, recoveryPath)
	out, err = observe(context.Background(), in)
	if err != nil || out.Digests[info.SourceHandle] != hash(material) {
		t.Fatal("native recovery lost the actual stored canary", err)
	}
	raw, err := json.Marshal(out)
	if err != nil || bytes.Contains(raw, material) || bytes.Contains(raw, key) || bytes.Contains(raw, recovery) ||
		bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(material))) || bytes.Contains(raw, []byte(hex.EncodeToString(material))) {
		t.Fatal("native observer disclosed protected values")
	}
	path := filepath.Join(directory, string(info.SourceHandle)+".json")
	record, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if json.Unmarshal(record, &envelope) != nil {
		t.Fatal("native record is not retained JSON")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope["ciphertext"].(string))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	envelope["ciphertext"] = base64.StdEncoding.EncodeToString(ciphertext)
	tampered, err := json.Marshal(envelope)
	if err != nil || os.WriteFile(path, tampered, 0600) != nil {
		t.Fatal("cannot retain tampered native control")
	}
	in.Mode, in.KeyFD, in.Profiles = "journal", inputFD(t, keyPath), nil
	_, err = observe(context.Background(), in)
	if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity {
		t.Fatal("native observer accepted a changed GCM tag")
	}
}
