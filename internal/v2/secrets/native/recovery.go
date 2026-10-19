package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"io"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

const recoverySchema = "laneboss.secret-recovery.v2"

type recovery struct {
	Schema     string `json:"schema"`
	Config     string `json:"config"`
	KeyID      api.ID `json:"key_id"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func recoveryAAD(r recovery) []byte {
	// Each interpolated field has already passed the strict ASCII metadata grammar.
	return []byte(`{"config":"` + r.Config + `","key_id":"` + string(r.KeyID) +
		`","schema":"` + r.Schema + `"}`)
}

func readRecoveryKey(protected io.Reader) ([]byte, error) {
	if wire.Nil(protected) {
		return nil, wire.Error(api.CodeInvalid, "protected recovery key is required")
	}
	key, err := io.ReadAll(io.LimitReader(protected, 33))
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, wire.Error(api.CodeInvalid, "recovery key must contain exactly 32 bytes")
	}
	return key, nil
}

// SealRecovery returns an encrypted backup, never plaintext key bytes. The
// administrator must retain it separately from encrypted records and keep its
// independent recovery key in the protected provisioning system. These concrete
// administrative methods are not RPCs and do not grant human authorization.
func (s *Service) SealRecovery(ctx context.Context, id api.ID, protected io.Reader) ([]byte, error) {
	if err := wire.Context(ctx); err != nil {
		return nil, err
	}
	if !wire.ID(string(id)) {
		return nil, wire.Error(api.CodeInvalid, "an exact recovery key handle is required")
	}
	key, err := readRecoveryKey(protected)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx, false); err != nil {
		return nil, err
	}
	if len(s.keys[id]) != 32 {
		return nil, wire.Error(api.CodePrerequisite, "recovery requires an unlocked record key")
	}
	if subtle.ConstantTimeCompare(key, s.keys[id]) == 1 {
		return nil, wire.Error(api.CodeInvalid, "recovery key must be independent of the record key")
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	r := recovery{Schema: recoverySchema, Config: s.deps.Config, KeyID: id,
		Nonce: make([]byte, aead.NonceSize())}
	if _, err := rand.Read(r.Nonce); err != nil {
		return nil, wire.Error(api.CodeUnavailable, "secure recovery nonce generation failed")
	}
	r.Ciphertext = aead.Seal(nil, r.Nonce, s.keys[id], recoveryAAD(r))
	data, err := json.Marshal(r)
	if err != nil {
		return nil, wire.Error(api.CodeIntegrity, "cannot encode encrypted recovery backup")
	}
	return data, nil
}

// Recover authenticates both the backup and the stored records before exposing
// a key to Fetch. There is no automatic recovery key discovery or plaintext mode.
func (s *Service) Recover(ctx context.Context, encrypted, protected io.Reader) error {
	if err := wire.Context(ctx); err != nil {
		return err
	}
	if wire.Nil(encrypted) {
		return wire.Error(api.CodeInvalid, "encrypted recovery backup is required")
	}
	data, err := io.ReadAll(io.LimitReader(encrypted, 2049))
	if err != nil || len(data) > 2048 {
		return wire.Error(api.CodeInvalid, "invalid recovery backup size")
	}
	var r recovery
	if err := wire.Decode(data, &r, 2048); err != nil {
		return wire.Error(api.CodeIntegrity, "invalid encrypted recovery backup")
	}
	if r.Schema != recoverySchema || r.Config != s.deps.Config ||
		!wire.ID(string(r.KeyID)) || len(r.Nonce) != 12 || len(r.Ciphertext) != 48 {
		return wire.Error(api.CodeIntegrity, "recovery backup identity or bounds differ")
	}
	key, err := readRecoveryKey(protected)
	if err != nil {
		return err
	}
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return err
	}
	plain, err := aead.Open(nil, r.Nonce, r.Ciphertext, recoveryAAD(r))
	if err != nil {
		return wire.Error(api.CodeIntegrity, "recovery backup authentication failed")
	}
	defer clear(plain)
	return s.Unlock(ctx, r.KeyID, bytes.NewReader(plain))
}
