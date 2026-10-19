package grants

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

// The native backend stores and authenticates real random canaries. Human
// transport and the state transaction remain the existing component fixtures.
type rootSecretStore struct {
	*rootProfileStore
	entered bool
}

func (b *rootSecretStore) WithRootSecrets(ctx context.Context, config string, fn func([]api.SecretInfo, bstate.Journal) error) error {
	port, ok := any(b.native).(interface {
		WithRootSecrets(context.Context, string, func([]api.SecretInfo, bstate.Journal) error) error
	})
	if !ok {
		b.t.Fatal("native protected root secret port is missing")
	}
	return port.WithRootSecrets(ctx, config, func(infos []api.SecretInfo, journal bstate.Journal) error {
		b.entered, b.active = true, true
		defer func() { b.active = false }()
		return fn(infos, journal)
	})
}

func rootSecretCase(t *testing.T) (*fixture, *rootSecretStore, api.RootGrantRequest, api.RootGrantManifest, []byte) {
	t.Helper()
	f, profile, request, input := rootProfileCase(t)
	b := &rootSecretStore{rootProfileStore: profile}
	f.service.deps.Profiles = b
	material := make([]byte, 96)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	for _, delivery := range []string{"env", "file"} {
		info, err := b.native.Store(context.Background(), api.SecretInfo{Name: "task-" + delivery, Version: "v1"}, api.SecretMaterial{Bytes: material})
		if err != nil {
			t.Fatal("cannot enroll actual synthetic secret", err)
		}
		target := "TASK_TOKEN"
		if delivery == "file" {
			target = "task.key"
		}
		input.Secrets = append(input.Secrets, api.SecretGrant{Name: info.Name, Version: info.Version,
			SourceHandle: info.SourceHandle, Delivery: delivery, Target: target, Delegate: true, ExpiresAt: "2030-01-01T01:00:00Z"})
	}
	return f, b, saveProfileInput(t, f, request, input), input, material
}

func TestRootSecretsValid(t *testing.T) {
	for _, only := range []bool{false, true} {
		t.Run(map[bool]string{false: "profiles", true: "secrets-only"}[only], func(t *testing.T) {
			f, b, request, input, material := rootSecretCase(t)
			defer clear(material)
			if only {
				input.Data, input.Profiles = []api.DataGrant{}, []api.ProfileGrant{}
				request = saveProfileInput(t, f, request, input)
			}
			scope := humanScope(t, f, "grants.root", request)
			rootProfileCommit(t, f, b.rootProfileStore, scope)
			commit := f.store.onTransaction
			f.store.onTransaction = func(tx api.Transaction) (api.Commit, error) {
				raw, err := json.Marshal(tx)
				if err != nil || bytes.Contains(raw, material) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(material))) || bytes.Contains(raw, []byte(hex.EncodeToString(material))) {
					t.Fatal("root secret issuance journal disclosed canary bytes")
				}
				return commit(tx)
			}
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			if err != nil || len(result.Secrets) != len(input.Secrets) || f.store.transactions != 1 || !b.entered {
				t.Fatal("root secret issuance did not accept enrolled handles", err)
			}
			if err := manifest.Set(result, f.clock.Now()); err != nil {
				t.Fatal("issued root secrets failed the existing set validator", err)
			}
			for i, member := range result.Secrets {
				if !manifest.ValidID(member.ID) || member.ParentGrantID != "" {
					t.Fatal("root secret did not receive a fresh service-issued ID")
				}
				member.ID = ""
				if !reflect.DeepEqual(member, input.Secrets[i]) {
					t.Fatal("root secret selection widened or changed")
				}
			}
		})
	}
}

func TestRootSecretsRefuse(t *testing.T) {
	for _, name := range []string{"unknown", "foreign", "name", "version", "revoked", "locked", "unwired", "scope", "policy"} {
		t.Run(name, func(t *testing.T) {
			f, b, request, input, material := rootSecretCase(t)
			defer clear(material)
			code := api.CodeForbidden
			switch name {
			case "unknown":
				input.Secrets[0].SourceHandle = "unknown-handle"
			case "foreign":
				// An actual different protected enrollment cannot make its random
				// source handle visible to this configuration.
				_, _, _, other, otherMaterial := rootSecretCase(t)
				defer clear(otherMaterial)
				input.Secrets[0].SourceHandle = other.Secrets[0].SourceHandle
			case "name":
				input.Secrets[0].Name = "other-name"
			case "version":
				input.Secrets[0].Version = "other-version"
			case "revoked":
				g := input.Secrets[0]
				if err := b.native.Revoke(context.Background(), api.SecretInfo{Name: g.Name, Version: g.Version, SourceHandle: g.SourceHandle, KeyID: "test-key"}); err != nil {
					t.Fatal(err)
				}
			case "locked":
				b.native.Lock()
				code = api.CodePrerequisite
			case "unwired":
				f.service.deps.Profiles = nil
				code = api.CodePrerequisite
			}
			if name == "scope" || name == "policy" {
				input.Profiles = []api.ProfileGrant{}
			}
			request = saveProfileInput(t, f, request, input)
			scope := humanScope(t, f, "grants.root", request)
			rootProfileCommit(t, f, b.rootProfileStore, scope)
			if name == "scope" || name == "policy" {
				f.store.onBlobObject = input.Data[0].SourceObjectID
				f.store.onBlob = func() {
					if name == "scope" {
						scope.Connection.(*humanConnection).peer.alive = false
					} else {
						f.store.policy.Generation++
					}
				}
				if name == "policy" {
					code = api.CodeConflict
				}
			}
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != code || result.ID != "" || f.store.transactions != 0 {
				t.Fatal("root secret selection escaped its protected boundary", err)
			}
			raw, marshalErr := json.Marshal(typed)
			if marshalErr != nil || bytes.Contains(raw, material) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(material))) || bytes.Contains(raw, []byte(hex.EncodeToString(material))) {
				t.Fatal("root secret refusal disclosed canary bytes")
			}
		})
	}
}

func TestRootSecretsConfig(t *testing.T) {
	_, backend, _, _, material := rootSecretCase(t)
	defer clear(material)
	called := false
	err := backend.WithRootSecrets(context.Background(), "other-enrollment", func([]api.SecretInfo, bstate.Journal) error {
		called = true
		return nil
	})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || called {
		t.Fatal("root secret reader accepted another enrollment configuration")
	}
}
