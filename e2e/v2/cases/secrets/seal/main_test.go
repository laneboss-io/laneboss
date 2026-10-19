package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestSealedInputs(t *testing.T) {
	root := t.TempDir()
	material := make([]byte, 96)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "material")
	if err := os.WriteFile(file, material, 0600); err != nil {
		t.Fatal(err)
	}
	request := input{Config: "seal-test", Name: "random", Version: "v1", Material: file,
		Key: api.SecretKey{ID: "live-key", Algorithm: "X25519-HKDF-SHA256-AES-256-GCM",
			PublicKey: private.PublicKey().Bytes(), ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}}
	path := filepath.Join(root, "input.json")
	write := func() {
		t.Helper()
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	first, err := produce(path)
	if err != nil {
		t.Fatal("fresh installed key did not seal", err)
	}
	second, err := produce(path)
	if err != nil || bytes.Equal(first.Nonce, second.Nonce) || bytes.Equal(first.EphemeralPublicKey, second.EphemeralPublicKey) {
		t.Fatal("sealed inputs reused ephemeral material")
	}
	public, err := ecdh.X25519().NewPublicKey(first.EphemeralPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := private.ECDH(public)
	if err != nil {
		t.Fatal(err)
	}
	// Independently encode the frozen AAD; do not call the producer's helper.
	aad := []byte(`{"config":"seal-test","key_id":"live-key","name":"random","version":"v1"}`)
	salt := sha256.Sum256(aad)
	key, err := hkdf.Key(sha256.New, shared, salt[:], "laneboss.secret-stage.v2", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := aead.Open(nil, first.Nonce, first.Ciphertext, aad)
	if err != nil || !bytes.Equal(opened, material) {
		t.Fatal("independent decryption lost exact random bytes")
	}
	first.Ciphertext[len(first.Ciphertext)-1] ^= 1
	if _, err := aead.Open(nil, first.Nonce, first.Ciphertext, aad); err == nil {
		t.Fatal("actual modified GCM tag authenticated")
	}
	request.Key.ExpiresAt = api.Timestamp(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
	write()
	if _, err := produce(path); err == nil {
		t.Fatal("expired upload key sealed")
	}
	request.Key.ExpiresAt = api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	write()
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := produce(path); err == nil {
		t.Fatal("public material input sealed")
	}
}
