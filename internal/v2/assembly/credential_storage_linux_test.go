//go:build linux

package assembly

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"laneboss.io/laneboss/internal/v2/secrets/private"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCredentialStorageOwnsLock(t *testing.T) {
	ctx := context.Background()
	s := &credentialComponentSession{secretDirectory: testdir.New(t)}
	defer s.Close()
	call := func(method string, input credentialStorageInput) (any, error) {
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		return s.storage(ctx, method, raw)
	}
	if _, err := call("lock", credentialStorageInput{}); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(s.secretDirectory, "records/.lock")
	before, err := os.Stat(lock)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 64)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if _, err := call("write", credentialStorageInput{Name: ".lock", Data: data}); err == nil {
		t.Fatal("acceptance: ciphertext port replaced its live native storage lock")
	}
	after, err := os.Stat(lock)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("acceptance: refused ciphertext write replaced the canonical lock", err)
	}
	if _, err := call("write", credentialStorageInput{Name: "source.json", Data: data}); err != nil {
		t.Fatal(err)
	}
	value, err := call("read", credentialStorageInput{Name: "source.json", Max: int64(len(data))})
	if err != nil || string(value.([]byte)) != string(data) {
		t.Fatal("acceptance: encrypted storage lost actual retained bytes", err)
	}
	second, err := private.Open(filepath.Join(s.secretDirectory, "records"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	bounded, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := second.Lock(bounded); err == nil {
		second.Unlock()
		t.Fatal("acceptance: ciphertext port lost cross-process canonical lock exclusion")
	}
	if _, err := call("unlock", credentialStorageInput{}); err != nil {
		t.Fatal(err)
	}
	bounded2, cancel2 := context.WithTimeout(ctx, time.Second)
	defer cancel2()
	if err := second.Lock(bounded2); err != nil {
		t.Fatal("acceptance: original ciphertext owner did not release its kernel lock", err)
	}
	if err := second.Unlock(); err != nil {
		t.Fatal(err)
	}
}
