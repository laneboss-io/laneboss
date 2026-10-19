package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

const StageAlgorithm = "X25519-HKDF-SHA256-AES-256-GCM"
const stageInfo = "laneboss.secret-stage.v2"

// StageAAD implements the frozen JCS object. The metadata grammar is ASCII,
// excludes JSON escapes, and the keys are in canonical lexicographic order.
func StageAAD(config string, keyID api.ID, name, version string) ([]byte, error) {
	if !wire.ID(config) || !wire.ID(string(keyID)) || !wire.Name(name) || !wire.Name(version) {
		return nil, wire.Error(api.CodeInvalid, "invalid sealed-upload metadata")
	}
	return []byte(`{"config":"` + config + `","key_id":"` + string(keyID) +
		`","name":"` + name + `","version":"` + version + `"}`), nil
}

func stageCipher(shared, aad []byte) (cipher.AEAD, error) {
	salt := sha256.Sum256(aad)
	key, err := hkdf.Key(sha256.New, shared, salt[:], stageInfo, 32)
	if err != nil {
		return nil, wire.Error(api.CodeIntegrity, "sealed-upload key derivation failed")
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, wire.Error(api.CodeIntegrity, "sealed-upload encryption key is invalid")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, wire.Error(api.CodeUnavailable, "sealed-upload AES-GCM is unavailable")
	}
	return aead, nil
}

// SealStage is the client-side encrypted-upload primitive. It never transmits
// plaintext or copies it to a generic blob; callers retain the supplied bytes.
func SealStage(config string, key api.SecretKey, name, version string, material api.SecretMaterial, clocks ...api.Clock) (api.SecretStageRequest, error) {
	var result api.SecretStageRequest
	var clock api.Clock = stageWallClock{}
	if len(clocks) > 1 || len(clocks) == 1 && wire.Nil(clocks[0]) {
		return result, wire.Error(api.CodePrerequisite, "sealed-upload clock is unavailable")
	}
	if len(clocks) == 1 {
		clock = clocks[0]
	}
	if key.Algorithm != StageAlgorithm || len(key.PublicKey) != 32 ||
		len(material.Bytes) == 0 || len(material.Bytes) > wire.MaxMaterial-16 {
		return result, wire.Error(api.CodeInvalid, "invalid sealed-upload key or material size")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(key.ExpiresAt))
	if err != nil || !clock.Now().Before(expires) || !strings.HasSuffix(string(key.ExpiresAt), "Z") {
		return result, wire.Error(api.CodeForbidden, "sealed-upload key expired or has invalid expiry")
	}
	aad, err := StageAAD(config, key.ID, name, version)
	if err != nil {
		return result, err
	}
	public, err := ecdh.X25519().NewPublicKey(key.PublicKey)
	if err != nil {
		return result, wire.Error(api.CodeInvalid, "invalid sealed-upload public key")
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return result, wire.Error(api.CodeUnavailable, "sealed-upload randomness is unavailable")
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return result, wire.Error(api.CodeInvalid, "sealed-upload key agreement failed")
	}
	defer clear(shared)
	aead, err := stageCipher(shared, aad)
	if err != nil {
		return result, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return result, wire.Error(api.CodeUnavailable, "sealed-upload nonce generation failed")
	}
	return api.SecretStageRequest{KeyID: key.ID, Name: name, Version: version,
		EphemeralPublicKey: private.PublicKey().Bytes(), Nonce: nonce,
		Ciphertext: aead.Seal(nil, nonce, material.Bytes, aad)}, nil
}

type stageWallClock struct{}

func (stageWallClock) Now() time.Time { return time.Now().UTC() }

func validateStage(request api.SecretStageRequest) error {
	if !wire.ID(string(request.KeyID)) || !wire.Name(request.Name) || !wire.Name(request.Version) ||
		len(request.EphemeralPublicKey) != 32 || len(request.Nonce) != 12 ||
		len(request.Ciphertext) <= 16 || len(request.Ciphertext) > wire.MaxMaterial {
		return wire.Error(api.CodeInvalid, "invalid encrypted secret staging request")
	}
	return nil
}

// openStage is called only by the credential worker after operation-bound
// authorization. Merely staging an upload never causes decryption.
func openStage(config string, private *ecdh.PrivateKey, request api.SecretStageRequest) (api.SecretMaterial, error) {
	var result api.SecretMaterial
	if err := validateStage(request); err != nil {
		return result, err
	}
	if private == nil || private.Curve() != ecdh.X25519() {
		return result, wire.Error(api.CodePrerequisite, "protected upload key is unavailable")
	}
	aad, err := StageAAD(config, request.KeyID, request.Name, request.Version)
	if err != nil {
		return result, err
	}
	public, err := ecdh.X25519().NewPublicKey(request.EphemeralPublicKey)
	if err != nil {
		return result, wire.Error(api.CodeInvalid, "invalid ephemeral upload key")
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return result, wire.Error(api.CodeIntegrity, "sealed-upload key agreement failed")
	}
	defer clear(shared)
	aead, err := stageCipher(shared, aad)
	if err != nil {
		return result, err
	}
	plain, err := aead.Open(nil, request.Nonce, request.Ciphertext, aad)
	if err != nil {
		return result, wire.Error(api.CodeIntegrity, "sealed-upload authentication failed")
	}
	return api.SecretMaterial{Bytes: plain}, nil
}
