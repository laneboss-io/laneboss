package claudock

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestVendorRecheck(t *testing.T) {
	path := filepath.Join(temporary(t), "claude")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0555)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(65 << 20); err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		t.Fatal(err)
	}
	pin := api.Executable{ID: "claude", Version: ClaudeVersion, SHA256: api.Digest(hex.EncodeToString(hash.Sum(nil)))}
	if err := verifyExecutable(path, pin); err != nil {
		t.Fatal("65 MiB launch recheck failed", err)
	}
	if _, err := f.WriteAt([]byte{1}, 0); err != nil {
		t.Fatal(err)
	}
	if err := verifyExecutable(path, pin); err == nil {
		t.Fatal("launch recheck accepted a changed byte")
	}
	if _, err := f.WriteAt([]byte{0}, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Chmod(0775); err != nil {
		t.Fatal(err)
	}
	if err := verifyExecutable(path, pin); err == nil {
		t.Fatal("launch recheck accepted a changed mode")
	}
	if err := f.Chmod(0555); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate((512 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	hash.Reset()
	if _, err := io.Copy(hash, f); err != nil {
		t.Fatal(err)
	}
	pin.SHA256 = api.Digest(hex.EncodeToString(hash.Sum(nil)))
	if err := verifyExecutable(path, pin); err == nil {
		t.Fatal("launch recheck accepted more than 512 MiB")
	}
}

func TestVendorMode(t *testing.T) {
	f := runnerReady(t, nil)
	deps := f.service.deps
	for _, path := range []string{deps.ExecutablePath, deps.ClaudePath} {
		if err := os.Chmod(path, 0555); err != nil {
			t.Fatal(err)
		}
	}
	deps.RuntimePath = "/runtime/claudock"
	if _, err := New(deps); err != nil {
		t.Fatal("valid immutable projection failed", err)
	}
	if err := os.Chmod(deps.ClaudePath, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(deps); err == nil {
		t.Fatal("projected vendor mode change accepted")
	}
}
