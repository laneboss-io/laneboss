package grants

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
)

// Real encrypted metadata IO; enrollment authority and human transport are
// declared unit fixtures. No vendor credential, profile lease or login exists.
type rootProfileStore struct {
	t       *testing.T
	native  *native.Service
	active  bool
	reads   []api.ID
	onEnter func()
}

type rootProfileView struct {
	bstate.Journal
	store *rootProfileStore
}

func (v *rootProfileView) Read(kind string, id api.ID, target any) error {
	if kind != "profile" || !v.store.active {
		v.store.t.Fatal("root resolution read outside the protected profile journal")
	}
	v.store.reads = append(v.store.reads, id)
	return v.Journal.Read(kind, id, target)
}

func (v *rootProfileView) Write(string, api.ID, any) error {
	v.store.t.Fatal("root resolution wrote a credential or lease record")
	return errors.New("unexpected credential journal write")
}

func (v *rootProfileView) Fetch(context.Context, api.SecretGrant) (api.SecretMaterial, error) {
	v.store.t.Fatal("root resolution fetched vendor credential material")
	return api.SecretMaterial{}, errors.New("unexpected credential fetch")
}

func (v *rootProfileView) AcquireRefreshLease(api.ID) (bstate.RefreshLease, error) {
	v.store.t.Fatal("root resolution acquired a credential refresh lease")
	return nil, errors.New("unexpected credential lease")
}

func (b *rootProfileStore) WithBroker(ctx context.Context, fn func(bstate.Journal) error) error {
	if b.onEnter != nil {
		b.onEnter()
	}
	return b.native.WithBroker(ctx, func(journal bstate.Journal) error {
		b.active = true
		defer func() { b.active = false }()
		return fn(&rootProfileView{Journal: journal, store: b})
	})
}

func rootProfileCase(t *testing.T) (*fixture, *rootProfileStore, api.RootGrantRequest, api.RootGrantManifest) {
	t.Helper()
	f := newFixture(t)
	directory := filepath.Join(testdir.New(t), "records")
	backend, err := native.New(native.Dependencies{Directory: directory, Config: f.scope.Config, KeyHandle: "test-key", Clock: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Error(err)
		}
	})
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := backend.Unlock(context.Background(), "test-key", bytes.NewReader(key)); err != nil {
		t.Fatal(err)
	}
	clear(key)
	b := &rootProfileStore{t: t, native: backend}
	f.service.deps.Profiles = b
	request := rootFixture(t, f)
	var input api.RootGrantManifest
	if err := api.DecodeObject(f.store.blobs[request.Manifest.ID], &input); err != nil {
		t.Fatal(err)
	}
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		grant := api.ProfileGrant{ProfileID: api.ID("profile-" + string(driver)), Driver: driver, Provider: "fixture-provider", Delegate: true, ExpiresAt: "2030-01-01T01:00:00Z"}
		profile := bstate.Profile{Schema: "laneboss.credential-profile.v2", Config: f.scope.Config,
			ID: grant.ProfileID, LoginID: api.ID("login-" + string(driver)), Generation: 1, Driver: driver, Provider: grant.Provider,
			Mode: "helper", Models: []string{"fixture-model"}, VendorVersions: []string{"fixture-version"}, RefreshFields: []string{},
			Runtime:  api.Executable{ID: api.ID("runtime-" + string(driver)), SHA256: manifest.Hash([]byte("pinned runtime")), Version: "fixture-version"},
			Evidence: api.BlobRef{ID: "enrollment-evidence", Class: "credential_evidence", Bytes: 10, SHA256: manifest.Hash([]byte("enrollment"))},
			Source: api.SecretGrant{ID: "source-grant", SourceHandle: "source-handle", Name: "profile-key", Version: "v1",
				Delivery: "file", Target: "login.json", ExpiresAt: "2030-01-01T04:00:00Z"}, ExpiresAt: "2030-01-01T04:00:00Z"}
		if err := backend.WithBroker(context.Background(), func(j bstate.Journal) error { return j.Write("profile", profile.ID, profile) }); err != nil {
			t.Fatal(err)
		}
		input.Profiles = append(input.Profiles, grant)
	}
	request = saveProfileInput(t, f, request, input)
	return f, b, request, input
}

func saveProfileInput(t *testing.T, f *fixture, request api.RootGrantRequest, input api.RootGrantManifest) api.RootGrantRequest {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	f.store.blobs[request.Manifest.ID] = raw
	request.Manifest.Bytes, request.Manifest.SHA256 = int64(len(raw)), manifest.Hash(raw)
	f.store.retain(request.Manifest)
	return request
}

func rootProfileCommit(t *testing.T, f *fixture, b *rootProfileStore, scope api.Scope) {
	t.Helper()
	f.store.onTransaction = func(tx api.Transaction) (api.Commit, error) {
		if !b.active || len(tx.Writes.Grants) != 1 || len(tx.Writes.WorkerLeases) != 0 || len(tx.Effects) != 0 {
			t.Fatal("root profiles escaped the enrollment lock or invented a lease")
		}
		if len(tx.Guards) != 1 || tx.Guards[0].Proof == nil || tx.Guards[0].Proof.Proof != *scope.Request.Proof ||
			!bytes.Equal(tx.RawRequest, scope.Frame.Bytes()) {
			t.Fatal("profile issuance lost the exact human proof or input")
		}
		if err := api.ValidateTransactionShape(tx); err != nil {
			t.Fatal(err)
		}
		f.store.sets[tx.Writes.Grants[0].ID] = clone(t, tx.Writes.Grants[0])
		return api.Commit{Reply: tx.Reply, Operation: api.Operation{ID: "root-operation", Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}, nil
	}
}

func TestRootProfiles(t *testing.T) {
	for _, name := range []string{"enrolled", "profiles-only", "missing", "foreign", "identity", "driver", "provider", "paid", "expired", "ceiling", "source-expiry", "generation", "excluded", "locked", "unwired"} {
		t.Run(name, func(t *testing.T) {
			f, backend, request, input := rootProfileCase(t)
			positive := name == "enrolled" || name == "profiles-only"
			code := api.CodeForbidden
			if name == "profiles-only" {
				input.Data = []api.DataGrant{}
				request = saveProfileInput(t, f, request, input)
			} else if name == "missing" {
				input.Profiles[0].ProfileID = "unenrolled-profile"
				request = saveProfileInput(t, f, request, input)
				code = api.CodeNotFound
			} else if name == "excluded" {
				f.store.policy.ProfileExclusions = []api.ID{input.Profiles[0].ProfileID}
			} else if name == "unwired" {
				f.service.deps.Profiles = nil
				code = api.CodePrerequisite
			} else if name == "locked" {
				backend.native.Lock()
				code = api.CodePrerequisite
			} else if !positive {
				err := backend.native.WithBroker(context.Background(), func(j bstate.Journal) error {
					var profile bstate.Profile
					if err := j.Read("profile", input.Profiles[0].ProfileID, &profile); err != nil {
						return err
					}
					switch name {
					case "foreign":
						profile.Config = "foreign-config"
					case "identity":
						profile.ID = "different-profile"
					case "driver":
						profile.Driver = api.DriverCodex
					case "provider":
						profile.Provider = "other-provider"
					case "paid":
						profile.Paid = true
					case "expired":
						profile.ExpiresAt = "2029-01-01T00:00:00Z"
					case "ceiling":
						profile.ExpiresAt = "2030-01-01T00:30:00Z"
					case "source-expiry":
						profile.Source.ExpiresAt = "2030-01-01T00:30:00Z"
					case "generation":
						profile.Generation = 0
						code = api.CodeIntegrity
					}
					return j.Write("profile", input.Profiles[0].ProfileID, profile)
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			scope := humanScope(t, f, "grants.root", request)
			rootProfileCommit(t, f, backend, scope)
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			if !positive {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != code || result.ID != "" || f.store.transactions != 0 {
					t.Fatal("root profile selector escaped its enrollment guard", name, err)
				}
				return
			}
			if err != nil {
				t.Fatal("enrolled root profile resolution failed", err)
			}
			if len(result.Profiles) != len(input.Profiles) || len(backend.reads) != len(input.Profiles) || f.store.transactions != 1 {
				t.Fatal("enrolled root profiles were not issued intact")
			}
			if name == "profiles-only" && (len(result.Data) != 0 || result.ExpiresAt != input.Profiles[0].ExpiresAt) {
				t.Fatal("profile-only root lost its exact expiry ceiling")
			}
			ids := map[api.ID]bool{}
			for i, grant := range result.Profiles {
				if !manifest.ValidID(grant.ID) || ids[grant.ID] || grant.ParentGrantID != "" {
					t.Fatal("root profile member IDs were not freshly issued")
				}
				ids[grant.ID] = true
				grant.ID = ""
				if !reflect.DeepEqual(grant, input.Profiles[i]) || backend.reads[i] != grant.ProfileID {
					t.Fatal("root profile selection changed or bypassed the protected record")
				}
			}
			if !reflect.DeepEqual(result, f.store.sets[result.ID]) {
				t.Fatal("root profiles were not returned from the durable reply")
			}
		})
	}
}

func TestRootProfileOrder(t *testing.T) {
	for _, name := range []string{"proof", "manifest", "policy", "changed-policy"} {
		t.Run(name, func(t *testing.T) {
			f, backend, request, _ := rootProfileCase(t)
			scope := humanScope(t, f, "grants.root", request)
			code := api.CodeForbidden
			switch name {
			case "proof":
				scope.Request.Proof = nil
			case "manifest":
				f.store.blobs[request.Manifest.ID] = []byte("changed immutable bytes")
				code = api.CodeIntegrity
			case "policy":
				f.store.policy.Generation++
				code = api.CodeConflict
			case "changed-policy":
				backend.onEnter = func() { f.store.policy.Generation++ }
				code = api.CodeConflict
			}
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != code || result.ID != "" || len(backend.reads) != 0 || f.store.transactions != 0 {
				t.Fatal("root profile lookup preceded its authority gates", name, err)
			}
		})
	}
}
