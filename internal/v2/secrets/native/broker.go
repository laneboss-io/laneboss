package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"strconv"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type brokerRecord struct {
	Generation api.Generation `json:"generation"`
	Schema     string         `json:"schema"`
	Config     string         `json:"config"`
	Kind       string         `json:"kind"`
	ID         api.ID         `json:"id"`
	KeyID      api.ID         `json:"key_id"`
	Nonce      []byte         `json:"nonce"`
	Ciphertext []byte         `json:"ciphertext"`
}

func brokerAAD(r brokerRecord) []byte {
	return []byte(`{"config":"` + r.Config + `","generation":` + strconv.FormatUint(uint64(r.Generation), 10) + `,"id":"` + string(r.ID) + `","key_id":"` + string(r.KeyID) + `","kind":"` + r.Kind + `","schema":"` + r.Schema + `"}`)
}

type brokerView struct {
	service *Service
	ctx     context.Context
	mu      sync.Mutex
	active  bool
}

func (v *brokerView) end() { v.mu.Lock(); defer v.mu.Unlock(); v.active = false }

func (v *brokerView) AcquireRefreshLease(id api.ID) (bstate.RefreshLease, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.active {
		return nil, wire.Error(api.CodeForbidden, "credential journal scope has ended")
	}
	if err := wire.Context(v.ctx); err != nil {
		return nil, err
	}
	lease, err := v.service.directory.AcquireRefreshLease(id)
	if err != nil {
		return nil, err
	}
	return lease, nil
}

func brokerName(kind string, id api.ID) (string, error) {
	if kind != "profile" && kind != "slot" && kind != "login" && kind != "projection" && kind != "plan_cleanup" && kind != "usage" || !wire.ID(string(id)) {
		return "", wire.Error(api.CodeInvalid, "invalid protected credential journal selector")
	}
	return ".broker-" + kind + "-" + string(id) + ".json", nil
}

func (s *Service) WithBroker(ctx context.Context, fn func(bstate.Journal) error) error {
	return s.withBroker(ctx, false, fn)
}

func (s *Service) WithBrokerDurable(ctx context.Context, fn func(bstate.Journal) error) error {
	return s.withBroker(ctx, true, fn)
}

func (s *Service) withBroker(ctx context.Context, durable bool, fn func(bstate.Journal) error) error {
	if fn == nil {
		return wire.Error(api.CodeInvalid, "credential journal callback is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx, true); err != nil {
		return err
	}
	if err := s.directory.Lock(ctx); err != nil {
		return err
	}
	journalCtx := ctx
	if durable {
		var cancel context.CancelFunc
		journalCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
		defer cancel()
	}
	return s.withUnlock(func() error { v := &brokerView{service: s, ctx: journalCtx, active: true}; defer v.end(); return fn(v) })
}

func (v *brokerView) Read(kind string, id api.ID, destination any) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.active {
		return wire.Error(api.CodeForbidden, "credential journal scope has ended")
	}
	if err := wire.Context(v.ctx); err != nil {
		return err
	}
	name, err := brokerName(kind, id)
	if err != nil {
		return err
	}
	data, err := v.service.directory.Read(name, 256*1024)
	if err != nil {
		return err
	}
	var r brokerRecord
	if err := wire.Decode(data, &r, 256*1024); err != nil || r.Generation == 0 || r.Generation > 1<<53-1 || r.Schema != "laneboss.credential-state.v2" || r.Config != v.service.deps.Config || r.Kind != kind || r.ID != id || !wire.ID(string(r.KeyID)) || len(r.Nonce) != 12 || len(r.Ciphertext) < 16 {
		return wire.Error(api.CodeIntegrity, "protected credential record identity differs")
	}
	if len(v.service.keys[r.KeyID]) != 32 {
		return wire.Error(api.CodePrerequisite, "credential journal key requires protected unlock")
	}
	aead, err := gcm(v.service.keys[r.KeyID])
	if err != nil {
		return err
	}
	plain, err := aead.Open(nil, r.Nonce, r.Ciphertext, brokerAAD(r))
	if err != nil {
		return wire.Error(api.CodeIntegrity, "protected credential record authentication failed")
	}
	defer clear(plain)
	if len(plain) > 192*1024 {
		return wire.Error(api.CodeIntegrity, "protected credential payload exceeds its bound")
	}
	if kind == "projection" || kind == "plan_cleanup" || kind == "usage" {
		// The authenticated projection payload contains Go-only API unions
		// with explicit null pointers/slices. Public request shape decoding
		// intentionally rejects those; do not weaken that public decoder.
		decoder := json.NewDecoder(bytes.NewReader(plain))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(destination); err != nil {
			return wire.Error(api.CodeIntegrity, "invalid protected projection payload")
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return wire.Error(api.CodeIntegrity, "protected projection payload has trailing data")
		}
	} else if err := api.DecodeObject(plain, destination); err != nil {
		return wire.Error(api.CodeIntegrity, "invalid protected credential payload")
	}
	return nil
}

func (v *brokerView) Write(kind string, id api.ID, value any) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.active {
		return wire.Error(api.CodeForbidden, "credential journal scope has ended")
	}
	if err := wire.Context(v.ctx); err != nil {
		return err
	}
	name, err := brokerName(kind, id)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(value)
	if err != nil || len(plain) > 192*1024 {
		return wire.Error(api.CodeInvalid, "protected credential payload exceeds its bound")
	}
	defer clear(plain)
	generation := api.Generation(1)
	prior, readErr := v.service.directory.Read(name, 256*1024)
	if readErr == nil {
		var previous brokerRecord
		if wire.Decode(prior, &previous, 256*1024) != nil || len(previous.Nonce) != 12 || len(previous.Ciphertext) < 16 || !wire.ID(string(previous.KeyID)) || previous.Schema != "laneboss.credential-state.v2" || previous.Config != v.service.deps.Config || previous.Kind != kind || previous.ID != id || previous.Generation == 0 || previous.Generation >= 1<<53-1 {
			return wire.Error(api.CodeIntegrity, "credential journal generation requires protected reconciliation")
		}
		if len(v.service.keys[previous.KeyID]) != 32 {
			return wire.Error(api.CodePrerequisite, "credential journal previous generation needs protected unlock")
		}
		cipher, err := gcm(v.service.keys[previous.KeyID])
		if err != nil {
			return err
		}
		opened, err := cipher.Open(nil, previous.Nonce, previous.Ciphertext, brokerAAD(previous))
		clear(opened)
		if err != nil {
			return wire.Error(api.CodeIntegrity, "credential journal previous generation failed authentication")
		}
		generation = previous.Generation + 1
	} else if typed, ok := readErr.(*api.Error); !ok || typed.Code != api.CodeNotFound {
		return readErr
	}
	aead, err := gcm(v.service.keys[v.service.deps.KeyHandle])
	if err != nil {
		return err
	}
	r := brokerRecord{Generation: generation, Schema: "laneboss.credential-state.v2", Config: v.service.deps.Config, Kind: kind, ID: id, KeyID: v.service.deps.KeyHandle, Nonce: make([]byte, aead.NonceSize())}
	if _, err := rand.Read(r.Nonce); err != nil {
		return wire.Error(api.CodeUnavailable, "credential nonce generation failed")
	}
	r.Ciphertext = aead.Seal(nil, r.Nonce, plain, brokerAAD(r))
	data, err := json.Marshal(r)
	if err != nil {
		return wire.Error(api.CodeIntegrity, "cannot encode protected credential record")
	}
	return v.service.directory.Write(name, data)
}

func (v *brokerView) Fetch(ctx context.Context, grant api.SecretGrant) (api.SecretMaterial, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.active {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "credential journal scope has ended")
	}
	if err := wire.Context(v.ctx); err != nil {
		return api.SecretMaterial{}, err
	}
	if err := v.service.ready(ctx, false); err != nil {
		return api.SecretMaterial{}, err
	}
	expires, err := time.Parse(time.RFC3339Nano, string(grant.ExpiresAt))
	if !wire.ID(string(grant.ID)) || !wire.ID(string(grant.SourceHandle)) || !wire.Name(grant.Name) || !wire.Name(grant.Version) || err != nil || !v.service.deps.Clock.Now().Before(expires) {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "credential source grant is invalid or expired")
	}
	r, err := v.service.read(string(grant.SourceHandle) + ".json")
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if r.Info.Name != grant.Name || r.Info.Version != grant.Version {
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "credential source differs from its exact grant")
	}
	plain, err := open(v.service.keys[r.Info.KeyID], r)
	if err != nil {
		return api.SecretMaterial{}, err
	}
	if r.Info.Revoked {
		clear(plain)
		return api.SecretMaterial{}, wire.Error(api.CodeForbidden, "credential source is revoked")
	}
	return api.SecretMaterial{Bytes: plain}, nil
}
