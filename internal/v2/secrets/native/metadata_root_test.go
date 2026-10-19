//go:build linux && laneboss_root_canary && laneboss_gate_integration

package native_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/native"
)

func init() {
	if len(os.Args) != 4 || os.Args[1] != "metadata-owner-canary" {
		return
	}
	if os.Geteuid() == 0 {
		os.Exit(81)
	}
	// The control must be readable by this same real unprivileged process.
	if b, err := os.ReadFile(os.Args[2]); err != nil || len(b) == 0 {
		os.Exit(82)
	}
	file, err := os.Open(os.Args[3])
	if file != nil {
		file.Close()
	}
	if !errors.Is(err, os.ErrPermission) {
		os.Exit(83)
	}
	os.Exit(0)
}

// Native filesystem/UID and restart/recovery canaries use synthetic random
// bytes only. No administrator installation or owner presence is simulated.
func TestMetadataNativeOwnerCanary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("metadata native canary requires disposable Linux root")
	}
	base, err := os.MkdirTemp("/run", "lb-v2-it2-metadata-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	directory := filepath.Join(base, "records")
	key, recoveryKey := randomBytes(t, 32), randomBytes(t, 32)
	defer clear(key)
	defer clear(recoveryKey)
	s := newStore(t, directory, key)
	info := put(t, s, randomBytes(t, 91), "one")
	backup, err := s.SealRecovery(context.Background(), info.KeyID, bytes.NewReader(recoveryKey))
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(base, "probe")
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probe, self, 0555); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(base, "readable-control")
	if err := os.WriteFile(control, []byte("ordinary read control"), 0444); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, probe, "metadata-owner-canary", control, filepath.Join(directory, string(info.SourceHandle)+".json"))
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 61543, Gid: 61543, Groups: []uint32{}}}
	if err := command.Run(); err != nil {
		t.Fatal("native unprivileged metadata boundary or readable control failed", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := native.New(native.Dependencies{Directory: directory, Config: "secret-case", KeyHandle: info.KeyID, Clock: &testClock{now: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := restarted.Close(); err != nil {
			t.Error(err)
		}
	}()
	port := metadataPort(t, restarted)
	called := false
	err = port.WithMetadata(context.Background(), func([]api.SecretInfo) error { called = true; return nil })
	requireCode(t, err, api.CodePrerequisite)
	if called {
		t.Fatal("locked restart released metadata")
	}
	err = restarted.Recover(context.Background(), bytes.NewReader(backup), bytes.NewReader(randomBytes(t, 32)))
	requireCode(t, err, api.CodeIntegrity)
	err = restarted.Recover(context.Background(), bytes.NewReader(backup), bytes.NewReader(recoveryKey))
	if err != nil {
		t.Fatal("protected recovery did not authenticate the actual retained records", err)
	}
	if err := port.WithMetadata(context.Background(), func(infos []api.SecretInfo) error {
		if len(infos) != 1 || infos[0] != info {
			t.Fatal("recovery changed the actual metadata source")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	name, record := readRecord(t, directory, info)
	var encrypted []byte
	if err := json.Unmarshal(record["ciphertext"], &encrypted); err != nil {
		t.Fatal(err)
	}
	encrypted[0] ^= 1
	record["ciphertext"], err = json.Marshal(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	writeRecord(t, name, record)
	called = false
	err = port.WithMetadata(context.Background(), func([]api.SecretInfo) error { called = true; return nil })
	requireCode(t, err, api.CodeIntegrity)
	if called {
		t.Fatal("tampered native record released metadata")
	}
}
