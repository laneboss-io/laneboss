// Package native stores service-owned secrets as authenticated ciphertext.
// It has no environment, keychain, plaintext-key-file or network fallback.
package native

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/private"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

const recordSchema = "laneboss.secret-record.v2"

type Dependencies struct {
	Directory string
	KeyHandle api.ID
	Clock     api.Clock
	// Config is required for authenticated-data domain separation. Key bytes
	// arrive later through Unlock, from the installed protected provisioning path.
	Config string
}

type Service struct {
	deps      Dependencies
	mu        sync.Mutex
	directory Storage
	keys      map[api.ID][]byte
	closed    bool
}

var _ api.SecretBackend = (*Service)(nil)

type record struct {
	Schema       string         `json:"schema"`
	Config       string         `json:"config"`
	Info         api.SecretInfo `json:"info"`
	RevocationID api.ID         `json:"revocation_id,omitempty"`
	Nonce        []byte         `json:"nonce"`
	Ciphertext   []byte         `json:"ciphertext"`
}

func New(deps Dependencies) (*Service, error) {
	if wire.Nil(deps.Clock) {
		return nil, wire.Error(api.CodePrerequisite, "native store requires its installed clock")
	}
	if !wire.ID(deps.Config) || !wire.ID(string(deps.KeyHandle)) {
		return nil, wire.Error(api.CodePrerequisite, "native store requires a configuration and key handle")
	}
	directory, err := private.Open(deps.Directory)
	if err != nil {
		return nil, err
	}
	return NewWithStorage(deps, localStorage{directory})
}

// Unlock accepts exactly 32 bytes through a trusted protected channel. It does
// not persist them. Reopening a Service always starts locked. All existing
// records for the key must authenticate before it becomes available.
func (s *Service) Unlock(ctx context.Context, id api.ID, protected io.Reader) error {
	if err := wire.Context(ctx); err != nil {
		return err
	}
	if wire.Nil(protected) || !wire.ID(string(id)) {
		return wire.Error(api.CodeInvalid, "protected key input is required")
	}
	key, err := io.ReadAll(io.LimitReader(protected, 33))
	if err != nil || len(key) != 32 {
		clear(key)
		return wire.Error(api.CodeInvalid, "protected AES key must contain exactly 32 bytes")
	}
	defer clear(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx, false); err != nil {
		return err
	}
	if err := s.directory.Lock(ctx); err != nil {
		return err
	}
	return s.withUnlock(func() error {
		names, err := s.directory.Names()
		if err != nil {
			return err
		}
		for _, name := range names {
			r, err := s.read(name)
			if err != nil {
				return err
			}
			if r.Info.KeyID == id {
				plain, err := open(key, r)
				clear(plain)
				if err != nil {
					return err
				}
			}
		}
		if err := s.checkKey(id, key); err != nil {
			return err
		}
		clear(s.keys[id])
		s.keys[id] = append([]byte(nil), key...)
		return nil
	})
}

func (s *Service) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, key := range s.keys {
		clear(key)
		delete(s.keys, id)
	}
}

func (s *Service) ready(ctx context.Context, unlocked bool) error {
	if err := wire.Context(ctx); err != nil {
		return err
	}
	if s.closed {
		return wire.Error(api.CodeUnavailable, "native store is closed")
	}
	if unlocked && len(s.keys[s.deps.KeyHandle]) != 32 {
		return wire.Error(api.CodePrerequisite, "native store needs protected key unlock")
	}
	return nil
}

func (s *Service) withUnlock(fn func() error) (err error) {
	defer func() {
		if unlockErr := s.directory.Unlock(); unlockErr != nil {
			err = unlockErr
		}
	}()
	return fn()
}

func validInfo(info api.SecretInfo) bool {
	return wire.Name(info.Name) && wire.Name(info.Version) &&
		wire.ID(string(info.SourceHandle)) && wire.ID(string(info.KeyID))
}

func (s *Service) read(name string) (record, error) {
	var r record
	if !strings.HasSuffix(name, ".json") || !wire.ID(strings.TrimSuffix(name, ".json")) {
		return r, wire.Error(api.CodeIntegrity, "unexpected object in encrypted record directory")
	}
	data, err := s.directory.Read(name, 128*1024)
	if err != nil {
		return r, err
	}
	if err := wire.Decode(data, &r, 128*1024); err != nil {
		return r, wire.Error(api.CodeIntegrity, "invalid encrypted secret record")
	}
	if r.Schema != recordSchema || r.Config != s.deps.Config || !validInfo(r.Info) ||
		string(r.Info.SourceHandle)+".json" != name || len(r.Nonce) != 12 ||
		len(r.Ciphertext) < 16 || len(r.Ciphertext) > wire.MaxMaterial+16 {
		return record{}, wire.Error(api.CodeIntegrity, "encrypted record identity or bounds differ")
	}
	if r.RevocationID != "" && (!r.Info.Revoked || !wire.ID(string(r.RevocationID))) {
		return record{}, wire.Error(api.CodeIntegrity, "encrypted revocation identity differs")
	}
	return r, nil
}

// aad has lexicographically ordered keys and an ASCII-only metadata grammar,
// so encoding/json produces the required unambiguous canonical representation.
func aad(r record) []byte {
	revoked := "false"
	if r.Info.Revoked {
		revoked = "true"
	}
	revocation := ""
	if r.RevocationID != "" {
		revocation = `,"revocation_id":"` + string(r.RevocationID) + `"`
	}
	return []byte(`{"config":"` + r.Config + `","key_id":"` + string(r.Info.KeyID) +
		`","name":"` + r.Info.Name + `"` + revocation + `,"revoked":` + revoked +
		`,"schema":"` + r.Schema + `","source_handle":"` + string(r.Info.SourceHandle) +
		`","version":"` + r.Info.Version + `"}`)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, wire.Error(api.CodePrerequisite, "protected AES key is unavailable")
	}
	result, err := cipher.NewGCM(block)
	if err != nil {
		return nil, wire.Error(api.CodeUnavailable, "AES-GCM is unavailable")
	}
	return result, nil
}

func seal(key []byte, r *record, plain []byte) error {
	aead, err := gcm(key)
	if err != nil {
		return err
	}
	r.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(r.Nonce); err != nil {
		return wire.Error(api.CodeUnavailable, "secure nonce generation failed")
	}
	r.Ciphertext = aead.Seal(nil, r.Nonce, plain, aad(*r))
	return nil
}

func open(key []byte, r record) ([]byte, error) {
	if len(key) != 32 {
		return nil, wire.Error(api.CodePrerequisite, "record key needs protected unlock")
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, r.Nonce, r.Ciphertext, aad(r))
	if err != nil {
		return nil, wire.Error(api.CodeIntegrity, "encrypted secret authentication failed")
	}
	return plain, nil
}

func (s *Service) Fetch(ctx context.Context, grant api.SecretGrant) (api.SecretMaterial, error) {
	var result api.SecretMaterial
	if !wire.Name(grant.Name) || !wire.Name(grant.Version) ||
		!wire.ID(string(grant.SourceHandle)) || !wire.ID(string(grant.ID)) {
		return result, wire.Error(api.CodeInvalid, "an exact named secret grant is required")
	}
	expiry, err := time.Parse(time.RFC3339Nano, string(grant.ExpiresAt))
	if err != nil || !strings.HasSuffix(string(grant.ExpiresAt), "Z") || !s.deps.Clock.Now().Before(expiry) {
		return result, wire.Error(api.CodeForbidden, "secret grant has expired or has invalid expiry")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx, false); err != nil {
		return result, err
	}
	if err := s.directory.Lock(ctx); err != nil {
		return result, err
	}
	err = s.withUnlock(func() error {
		r, err := s.read(string(grant.SourceHandle) + ".json")
		if err != nil {
			return err
		}
		if r.Info.Name != grant.Name || r.Info.Version != grant.Version {
			return wire.Error(api.CodeForbidden, "secret grant does not match the enrolled source")
		}
		plain, err := open(s.keys[r.Info.KeyID], r)
		if err != nil {
			return err
		}
		if r.Info.Revoked {
			clear(plain)
			return wire.Error(api.CodeForbidden, "secret source is revoked")
		}
		result.Bytes = plain
		return nil
	})
	if err != nil {
		clear(result.Bytes)
		return api.SecretMaterial{}, err
	}
	return result, nil
}

func (s *Service) Store(ctx context.Context, info api.SecretInfo, material api.SecretMaterial) (api.SecretInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx, false); err != nil {
		return api.SecretInfo{}, err
	}
	if err := s.directory.Lock(ctx); err != nil {
		return api.SecretInfo{}, err
	}
	var stored api.SecretInfo
	err := s.withUnlock(func() (err error) {
		stored, err = s.storeLocked(ctx, info, material)
		return err
	})
	if err != nil {
		return api.SecretInfo{}, err
	}
	return stored, nil
}

func (s *Service) storeLocked(ctx context.Context, info api.SecretInfo, material api.SecretMaterial) (api.SecretInfo, error) {
	if !wire.Name(info.Name) || !wire.Name(info.Version) || info.Revoked ||
		len(material.Bytes) == 0 || len(material.Bytes) > wire.MaxMaterial {
		return api.SecretInfo{}, wire.Error(api.CodeInvalid, "invalid secret enrollment metadata or size")
	}
	if info.SourceHandle == "" {
		id, err := wire.RandomID()
		if err != nil {
			return api.SecretInfo{}, err
		}
		info.SourceHandle = id
	}
	if info.KeyID == "" {
		info.KeyID = s.deps.KeyHandle
	}
	if !validInfo(info) || info.KeyID != s.deps.KeyHandle {
		return api.SecretInfo{}, wire.Error(api.CodeInvalid, "invalid secret source or active key handle")
	}
	if err := s.ready(ctx, true); err != nil {
		return api.SecretInfo{}, err
	}
	err := func() error {
		names, err := s.directory.Names()
		if err != nil {
			return err
		}
		for _, name := range names {
			r, err := s.read(name)
			if err != nil {
				return err
			}
			if r.Info.SourceHandle == info.SourceHandle ||
				r.Info.Name == info.Name && r.Info.Version == info.Version {
				var plain []byte
				if r.Info == info || len(s.keys[r.Info.KeyID]) == 32 {
					plain, err = open(s.keys[r.Info.KeyID], r)
					if err != nil {
						return err
					}
				}
				equal := r.Info == info && subtle.ConstantTimeCompare(plain, material.Bytes) == 1
				clear(plain)
				if equal {
					return nil
				}
				return wire.Error(api.CodeConflict, "secret source and versions are immutable")
			}
		}
		r := record{Schema: recordSchema, Config: s.deps.Config, Info: info}
		if err := seal(s.keys[info.KeyID], &r, material.Bytes); err != nil {
			return err
		}
		data, err := json.Marshal(r)
		if err != nil {
			return wire.Error(api.CodeIntegrity, "cannot encode encrypted record")
		}
		return s.directory.Write(string(info.SourceHandle)+".json", data)
	}()
	if err != nil {
		return api.SecretInfo{}, err
	}
	return info, nil
}

func (s *Service) Revoke(ctx context.Context, info api.SecretInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx, false); err != nil {
		return err
	}
	if err := s.directory.Lock(ctx); err != nil {
		return err
	}
	return s.withUnlock(func() error { return s.revokeLocked(ctx, info, "") })
}

func (s *Service) revokeLocked(ctx context.Context, info api.SecretInfo, operation api.ID) error {
	if !validInfo(info) {
		return wire.Error(api.CodeInvalid, "revocation requires the exact enrolled source")
	}
	if err := s.ready(ctx, false); err != nil {
		return err
	}
	return func() error {
		r, err := s.read(string(info.SourceHandle) + ".json")
		if err != nil {
			return err
		}
		if r.Info.Name != info.Name || r.Info.Version != info.Version || r.Info.KeyID != info.KeyID {
			return wire.Error(api.CodeConflict, "revocation source version changed")
		}
		plain, err := open(s.keys[r.Info.KeyID], r)
		clear(plain)
		if err != nil {
			return err
		}
		if r.Info.Revoked {
			if operation != "" && r.RevocationID != operation {
				return wire.Error(api.CodeConflict, "secret revocation needs its original operation reconciliation")
			}
			return nil
		}
		r.Info.Revoked = true
		r.RevocationID = operation
		if err := seal(s.keys[r.Info.KeyID], &r, nil); err != nil {
			return err
		}
		data, err := json.Marshal(r)
		if err != nil {
			return wire.Error(api.CodeIntegrity, "cannot encode revoked secret record")
		}
		return s.directory.Write(string(info.SourceHandle)+".json", data)
	}()
}

func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for id, key := range s.keys {
		clear(key)
		delete(s.keys, id)
	}
	return s.directory.Close()
}
