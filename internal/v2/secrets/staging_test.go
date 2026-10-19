package secrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func stageFixture(t *testing.T) (*ecdh.PrivateKey, api.SecretKey, []byte) {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot create synthetic upload key")
	}
	value := make([]byte, 83)
	if _, err := rand.Read(value); err != nil {
		t.Fatal("cannot create synthetic canary")
	}
	key := api.SecretKey{ID: "upload-a", Algorithm: StageAlgorithm, PublicKey: private.PublicKey().Bytes(),
		ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano))}
	return private, key, value
}

func stageCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("expected stage error code %s", code)
	}
}

func TestSealedUpload(t *testing.T) {
	private, key, value := stageFixture(t)
	request, err := SealStage("stage-case", key, "canary", "one", api.SecretMaterial{Bytes: value})
	if err != nil || bytes.Contains(request.Ciphertext, value) {
		t.Fatal("canary sealing failed or disclosed plaintext")
	}
	opened, err := openStage("stage-case", private, request)
	if err != nil || !bytes.Equal(opened.Bytes, value) {
		t.Fatal("sealed canary round trip differs")
	}
	clear(opened.Bytes)
	// Interoperate with an independently constructed canonical AAD and KDF,
	// rather than using the same encode/decode helper as both sides of the test.
	aad, err := json.Marshal(map[string]any{"name": request.Name, "version": request.Version,
		"key_id": request.KeyID, "config": "stage-case"})
	if err != nil {
		t.Fatal("independent AAD encoding failed")
	}
	public, err := ecdh.X25519().NewPublicKey(request.EphemeralPublicKey)
	if err != nil {
		t.Fatal("independent public key parsing failed")
	}
	shared, err := private.ECDH(public)
	if err != nil {
		t.Fatal("independent X25519 failed")
	}
	defer clear(shared)
	salt := sha256.Sum256(aad)
	derived, err := hkdf.Key(sha256.New, shared, salt[:], "laneboss.secret-stage.v2", 32)
	if err != nil {
		t.Fatal("independent HKDF failed")
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		t.Fatal("independent AES setup failed")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("independent GCM setup failed")
	}
	plain, err := aead.Open(nil, request.Nonce, request.Ciphertext, aad)
	if err != nil || !bytes.Equal(plain, value) {
		t.Fatal("sealed upload failed independent decryption")
	}
	clear(plain)
	second, err := SealStage("stage-case", key, "canary", "one", api.SecretMaterial{Bytes: value})
	if err != nil || bytes.Equal(second.Nonce, request.Nonce) ||
		bytes.Equal(second.EphemeralPublicKey, request.EphemeralPublicKey) {
		t.Fatal("sealed uploads reused randomness")
	}
}

func TestStageTamper(t *testing.T) {
	for _, field := range []string{"config", "key", "name", "version", "nonce", "ciphertext", "public"} {
		t.Run(field, func(t *testing.T) {
			private, key, value := stageFixture(t)
			request, err := SealStage("stage-case", key, "canary", "one", api.SecretMaterial{Bytes: value})
			if err != nil {
				t.Fatal("cannot seal tamper control")
			}
			config := "stage-case"
			switch field {
			case "config":
				config = "other-case"
			case "key":
				request.KeyID = "other-key"
			case "name":
				request.Name = "other-name"
			case "version":
				request.Version = "two"
			case "nonce":
				request.Nonce[0] ^= 1
			case "ciphertext":
				request.Ciphertext[len(request.Ciphertext)-1] ^= 1
			case "public":
				clear(request.EphemeralPublicKey)
			}
			got, err := openStage(config, private, request)
			stageCode(t, err, api.CodeIntegrity)
			if len(got.Bytes) != 0 {
				t.Fatal("tampered upload returned plaintext")
			}
		})
	}
}

func TestStageBounds(t *testing.T) {
	private, key, value := stageFixture(t)
	expired := key
	expired.ExpiresAt = api.Timestamp(time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano))
	_, err := SealStage("stage-case", expired, "canary", "one", api.SecretMaterial{Bytes: value})
	stageCode(t, err, api.CodeForbidden)
	_, err = SealStage("stage-case", key, "canary", "one", api.SecretMaterial{Bytes: make([]byte, wire.MaxMaterial)})
	stageCode(t, err, api.CodeInvalid)
	maximum := make([]byte, wire.MaxMaterial-16)
	if _, err := rand.Read(maximum); err != nil {
		t.Fatal("cannot create maximum synthetic canary")
	}
	request, err := SealStage("stage-case", key, "canary", "one", api.SecretMaterial{Bytes: maximum})
	if err != nil || len(request.Ciphertext) != wire.MaxMaterial {
		t.Fatal("maximum sealed upload was rejected")
	}
	opened, err := openStage("stage-case", private, request)
	if err != nil || !bytes.Equal(opened.Bytes, maximum) {
		t.Fatal("maximum sealed upload differs")
	}
	clear(opened.Bytes)
	request.Nonce = nil
	_, err = openStage("stage-case", private, request)
	stageCode(t, err, api.CodeInvalid)
	_, err = StageAAD("stage-case", key.ID, "../outside", "one")
	stageCode(t, err, api.CodeInvalid)
}
