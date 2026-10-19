package native

import (
	"crypto/rand"
	"encoding/json"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

const keyCheckSchema = "laneboss.secret-key-check.v2"

type keyCheck struct {
	Schema     string `json:"schema"`
	Config     string `json:"config"`
	KeyID      api.ID `json:"key_id"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func keyCheckAAD(r keyCheck) []byte {
	return []byte(`{"config":"` + r.Config + `","key_id":"` + string(r.KeyID) + `","schema":"` + r.Schema + `"}`)
}

// checkKey runs under the directory lock. Enrollment writes only an AES-GCM
// authentication tag for empty plaintext, never the key or a key hash.
func (s *Service) checkKey(id api.ID, key []byte) error {
	name := ".key-" + string(id) + ".json"
	aead, err := gcm(key)
	if err != nil {
		return err
	}
	data, err := s.directory.Read(name, 2048)
	var typed *api.Error
	if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
		r := keyCheck{Schema: keyCheckSchema, Config: s.deps.Config, KeyID: id, Nonce: make([]byte, aead.NonceSize())}
		if _, err := rand.Read(r.Nonce); err != nil {
			return wire.Error(api.CodeUnavailable, "secure key-check nonce generation failed")
		}
		r.Ciphertext = aead.Seal(nil, r.Nonce, nil, keyCheckAAD(r))
		data, err := json.Marshal(r)
		if err != nil {
			return wire.Error(api.CodeIntegrity, "cannot encode encrypted key check")
		}
		return s.directory.Write(name, data)
	}
	if err != nil {
		return err
	}
	var r keyCheck
	if err := wire.Decode(data, &r, 2048); err != nil || r.Schema != keyCheckSchema ||
		r.Config != s.deps.Config || r.KeyID != id || len(r.Nonce) != aead.NonceSize() || len(r.Ciphertext) != aead.Overhead() {
		return wire.Error(api.CodeIntegrity, "encrypted key-check identity or bounds differ")
	}
	plain, err := aead.Open(nil, r.Nonce, r.Ciphertext, keyCheckAAD(r))
	defer clear(plain)
	if err != nil || len(plain) != 0 {
		return wire.Error(api.CodeIntegrity, "encrypted key-check authentication failed")
	}
	return nil
}
