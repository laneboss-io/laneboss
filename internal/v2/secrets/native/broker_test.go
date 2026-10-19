package native_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
)

func TestEncryptedBrokerJournal(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(testdir.New(t), "records")
	key, value := randomBytes(t, 32), randomBytes(t, 111)
	s := newStore(t, directory, key)
	slot := bstate.Slot{Schema: "laneboss.credential-slot.v2", Config: "secret-case", ID: "slot-a", Kind: "task", Material: value, Returned: []byte{}}
	if err := s.WithBroker(ctx, func(j bstate.Journal) error { return j.Write("slot", slot.ID, slot) }); err != nil {
		t.Fatal("cannot write encrypted broker slot")
	}
	data, err := os.ReadFile(filepath.Join(directory, ".broker-slot-slot-a.json"))
	if err != nil {
		t.Fatal("cannot read encrypted broker envelope")
	}
	var envelope struct {
		Generation api.Generation `json:"generation"`
		Schema     string         `json:"schema"`
		Config     string         `json:"config"`
		Kind       string         `json:"kind"`
		ID         api.ID         `json:"id"`
		KeyID      api.ID         `json:"key_id"`
		Nonce      []byte         `json:"nonce"`
		Ciphertext []byte         `json:"ciphertext"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.Kind != "slot" {
		t.Fatal("broker envelope has an invalid shape")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("cannot construct independent broker cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("cannot construct independent broker authentication")
	}
	aad, err := json.Marshal(map[string]any{"config": "secret-case", "generation": envelope.Generation, "id": "slot-a", "key_id": "key-a", "kind": "slot", "schema": "laneboss.credential-state.v2"})
	if err != nil {
		t.Fatal("cannot encode independent broker AAD")
	}
	plain, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		t.Fatal("broker ciphertext failed independent AAD authentication")
	}
	defer clear(plain)
	var actual bstate.Slot
	if api.DecodeObject(plain, &actual) != nil || !bytes.Equal(actual.Material, value) {
		t.Fatal("broker ciphertext did not contain the actual selected material")
	}
	clear(actual.Material)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal("cannot inspect broker disk scope")
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal("cannot inspect broker file bytes")
		}
		if bytes.Contains(data, value) || bytes.Contains(data, key) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(value))) {
			t.Fatal("broker material or key escaped its encrypted envelope")
		}
	}
	if err := s.WithMutation(ctx, "metadata-operation", func(_ api.SecretBackend, metadata []api.SecretInfo) error {
		if len(metadata) != 0 {
			t.Fatal("protected broker records leaked into ordinary metadata")
		}
		return nil
	}); err != nil {
		t.Fatal("broker records broke regular metadata enumeration")
	}
	if err := s.Close(); err != nil {
		t.Fatal("cannot close broker restart control")
	}
	restarted := newStore(t, directory, nil)
	requireCode(t, restarted.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("slot", slot.ID, &actual) }), api.CodePrerequisite)
	if err := restarted.Unlock(ctx, "key-a", bytes.NewReader(key)); err != nil {
		t.Fatal("cannot unlock retained broker journal")
	}
	if err := restarted.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("slot", slot.ID, &actual) }); err != nil || !bytes.Equal(actual.Material, value) {
		t.Fatal("broker restart lost its exact protected material")
	}
	clear(actual.Material)
}

func TestBrokerAADTransplant(t *testing.T) {
	for _, fault := range []string{"id", "kind", "key", "tag", "generation"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			directory := filepath.Join(testdir.New(t), "records")
			key := randomBytes(t, 32)
			s := newStore(t, directory, key)
			slot := bstate.Slot{ID: "slot-a", Material: randomBytes(t, 51), Returned: []byte{}}
			if err := s.WithBroker(ctx, func(j bstate.Journal) error { return j.Write("slot", slot.ID, slot) }); err != nil {
				t.Fatal("cannot write broker transplant control")
			}
			path := filepath.Join(directory, ".broker-slot-slot-a.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("cannot read broker transplant envelope")
			}
			var envelope map[string]json.RawMessage
			if json.Unmarshal(data, &envelope) != nil {
				t.Fatal("cannot decode broker transplant envelope")
			}
			kind, id := "slot", api.ID("slot-a")
			switch fault {
			case "generation":
				envelope["generation"] = json.RawMessage(`2`)
			case "id":
				id = "slot-b"
				envelope["id"] = json.RawMessage(`"slot-b"`)
				path = filepath.Join(directory, ".broker-slot-slot-b.json")
			case "kind":
				kind = "login"
				envelope["kind"] = json.RawMessage(`"login"`)
				path = filepath.Join(directory, ".broker-login-slot-a.json")
			case "key":
				if err := s.Unlock(ctx, "key-b", bytes.NewReader(key)); err != nil {
					t.Fatal("cannot enroll the alternate protected key ID")
				}
				envelope["key_id"] = json.RawMessage(`"key-b"`)
			case "tag":
				var ciphertext []byte
				if json.Unmarshal(envelope["ciphertext"], &ciphertext) != nil || len(ciphertext) == 0 {
					t.Fatal("cannot decode broker tag control")
				}
				ciphertext[len(ciphertext)-1] ^= 1
				envelope["ciphertext"], err = json.Marshal(ciphertext)
				if err != nil {
					t.Fatal("cannot encode broker tag control")
				}
			}
			data, err = json.Marshal(envelope)
			if err != nil || os.WriteFile(path, data, 0600) != nil {
				t.Fatal("cannot retain broker transplant control")
			}
			var actual bstate.Slot
			requireCode(t, s.WithBroker(ctx, func(j bstate.Journal) error { return j.Read(kind, id, &actual) }), api.CodeIntegrity)
		})
	}
}

func TestBrokerViewLifetime(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, filepath.Join(testdir.New(t), "records"), randomBytes(t, 32))
	var saved bstate.Journal
	slot := bstate.Slot{ID: "slot-a", Material: randomBytes(t, 37), Returned: []byte{}}
	if err := s.WithBroker(ctx, func(j bstate.Journal) error { saved = j; return j.Write("slot", slot.ID, slot) }); err != nil {
		t.Fatal("cannot establish broker callback lifetime control")
	}
	var actual bstate.Slot
	requireCode(t, saved.Read("slot", slot.ID, &actual), api.CodeForbidden)
	requireCode(t, saved.Write("slot", "slot-b", slot), api.CodeForbidden)
	_, err := saved.Fetch(ctx, api.SecretGrant{})
	requireCode(t, err, api.CodeForbidden)
	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := s.WithBroker(cancelled, func(j bstate.Journal) error {
		cancel()
		requireCode(t, j.Write("slot", "cancelled-slot", slot), api.CodeCancelled)
		return nil
	}); err != nil {
		t.Fatal("cannot inspect cancelled broker callback")
	}
}

func TestBrokerNonceFresh(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(testdir.New(t), "records")
	s := newStore(t, directory, randomBytes(t, 32))
	slot := bstate.Slot{ID: "slot-a", Material: randomBytes(t, 47), Returned: []byte{}}
	var nonces [][]byte
	for _, id := range []api.ID{"slot-a", "slot-b"} {
		if err := s.WithBroker(ctx, func(j bstate.Journal) error { return j.Write("slot", id, slot) }); err != nil {
			t.Fatal("cannot write fresh-nonce control")
		}
		data, err := os.ReadFile(filepath.Join(directory, ".broker-slot-"+string(id)+".json"))
		if err != nil {
			t.Fatal("cannot read fresh-nonce control")
		}
		var envelope struct {
			Nonce []byte `json:"nonce"`
		}
		if json.Unmarshal(data, &envelope) != nil || len(envelope.Nonce) != 12 {
			t.Fatal("broker nonce has an invalid shape")
		}
		nonces = append(nonces, envelope.Nonce)
	}
	if bytes.Equal(nonces[0], nonces[1]) {
		t.Fatal("broker writes reused an encryption nonce")
	}
}

func TestBrokerPrivateEnumeration(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(testdir.New(t), "records")
	s := newStore(t, directory, randomBytes(t, 32))
	slot := bstate.Slot{ID: "slot-a", Material: randomBytes(t, 47), Returned: []byte{}}
	if err := s.WithBroker(ctx, func(j bstate.Journal) error { return j.Write("slot", slot.ID, slot) }); err != nil {
		t.Fatal("cannot write broker privacy control")
	}
	if err := os.Chmod(filepath.Join(directory, ".broker-slot-slot-a.json"), 0644); err != nil {
		t.Fatal("cannot change broker privacy control")
	}
	called := false
	err := s.WithMutation(ctx, "privacy-operation", func(_ api.SecretBackend, metadata []api.SecretInfo) error {
		called = true
		if len(metadata) != 0 {
			t.Fatal("broker privacy control exposed ordinary source metadata")
		}
		return nil
	})
	requireCode(t, err, api.CodeIntegrity)
	if called {
		t.Fatal("unsafe broker metadata reached a protected mutation callback")
	}
}
