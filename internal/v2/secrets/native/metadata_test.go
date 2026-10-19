package native_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
)

type metadataReader interface {
	WithMetadata(context.Context, func([]api.SecretInfo) error) error
}

func metadataPort(t *testing.T, s *native.Service) metadataReader {
	t.Helper()
	p, ok := any(s).(metadataReader)
	if !ok {
		t.Fatal("native metadata read capability is missing")
	}
	return p
}

// Real encrypted records, key authentication and the cross-process directory
// lock are exercised here. No provider or human-presence claim is made.
func TestMetadataRecords(t *testing.T) {
	ctx := context.Background()
	directory := filepath.Join(testdir.New(t), "records")
	key, value := randomBytes(t, 32), randomBytes(t, 97)
	defer clear(key)
	defer clear(value)
	s := newStore(t, directory, key)
	one := put(t, s, value, "one")
	two := put(t, s, randomBytes(t, 83), "two")
	if err := s.Revoke(ctx, two); err != nil {
		t.Fatal(err)
	}
	two.Revoked = true
	before, err := os.ReadFile(filepath.Join(directory, string(one.SourceHandle)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	port := metadataPort(t, s)
	read := func() map[api.ID]api.SecretInfo {
		t.Helper()
		result := map[api.ID]api.SecretInfo{}
		if err := port.WithMetadata(ctx, func(infos []api.SecretInfo) error {
			for _, info := range infos {
				result[info.SourceHandle] = info
			}
			encoded, err := json.Marshal(infos)
			if err != nil || bytes.Contains(encoded, value) {
				t.Fatal("metadata exposed secret material")
			}
			if len(infos) > 0 {
				infos[0].Name = "caller-changed"
			}
			return nil
		}); err != nil {
			t.Fatal("native authenticated metadata read failed", err)
		}
		return result
	}
	want := map[api.ID]api.SecretInfo{one.SourceHandle: one, two.SourceHandle: two}
	if !reflect.DeepEqual(read(), want) || !reflect.DeepEqual(read(), want) {
		t.Fatal("metadata read lost immutable version, revocation or retry identity")
	}
	after, err := os.ReadFile(filepath.Join(directory, string(one.SourceHandle)+".json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("metadata read rewrote the encrypted source")
	}
	s.Lock()
	called := false
	err = port.WithMetadata(ctx, func([]api.SecretInfo) error { called = true; return nil })
	requireCode(t, err, api.CodePrerequisite)
	if called {
		t.Fatal("locked metadata reached its callback")
	}
}

func TestMetadataAuthentication(t *testing.T) {
	for _, fault := range []string{"ciphertext", "foreign-config", "stale-version"} {
		t.Run(fault, func(t *testing.T) {
			directory := filepath.Join(testdir.New(t), "records")
			s := newStore(t, directory, randomBytes(t, 32))
			info := put(t, s, randomBytes(t, 77), "one")
			port := metadataPort(t, s)
			name, record := readRecord(t, directory, info)
			switch fault {
			case "ciphertext":
				var encrypted []byte
				if err := json.Unmarshal(record["ciphertext"], &encrypted); err != nil {
					t.Fatal(err)
				}
				encrypted[0] ^= 1
				record["ciphertext"], _ = json.Marshal(encrypted)
			case "foreign-config":
				record["config"] = json.RawMessage(`"foreign"`)
			case "stale-version":
				info.Version = "retired"
				record["info"], _ = json.Marshal(info)
			}
			writeRecord(t, name, record)
			called := false
			err := port.WithMetadata(context.Background(), func([]api.SecretInfo) error { called = true; return nil })
			requireCode(t, err, api.CodeIntegrity)
			if called {
				t.Fatal("unauthenticated metadata reached its callback")
			}
		})
	}
}
