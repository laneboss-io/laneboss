package grants

import (
	"context"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

func editRootProfile(t *testing.T, backend *rootProfileStore, id api.ID, edit func(*bstate.Profile)) {
	t.Helper()
	if err := backend.native.WithBroker(context.Background(), func(j bstate.Journal) error {
		var profile bstate.Profile
		if err := j.Read("profile", id, &profile); err != nil {
			return err
		}
		edit(&profile)
		return j.Write("profile", id, profile)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProfileEvidence(t *testing.T) {
	for _, name := range []string{"valid", "class", "id", "digest", "negative", "oversize"} {
		t.Run(name, func(t *testing.T) {
			f, backend, request, input := rootProfileCase(t)
			editRootProfile(t, backend, input.Profiles[0].ProfileID, func(profile *bstate.Profile) {
				switch name {
				case "class":
					profile.Evidence.Class = "artifact"
				case "id":
					profile.Evidence.ID = "invalid/profile"
				case "digest":
					profile.Evidence.SHA256 = "bad-digest"
				case "negative":
					profile.Evidence.Bytes = -1
				case "oversize":
					profile.Evidence.Bytes = api.MaxObjectBytes + 1
				}
			})
			scope := humanScope(t, f, "grants.root", request)
			rootProfileCommit(t, f, backend, scope)
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			if name == "valid" {
				if err != nil || len(result.Profiles) != len(input.Profiles) || f.store.transactions != 1 {
					t.Fatal("credential evidence rejected a valid profile", err)
				}
				return
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || result.ID != "" || f.store.transactions != 0 {
				t.Fatal("root profile accepted malformed evidence", name, err)
			}
		})
	}
}

func TestProfileMeta(t *testing.T) {
	for _, name := range []string{"valid", "provider", "usage-driver", "usage-name", "usage-empty", "usage-long", "adapter-empty", "adapter-long", "runtime-id", "runtime-digest", "runtime-version", "manifest-id", "manifest-digest", "manifest-negative", "manifest-large", "manifest-class"} {
		t.Run(name, func(t *testing.T) {
			f, backend, request, input := rootProfileCase(t)
			index := 0
			if name == "usage-driver" {
				index = 1 // Keep the Codex selector and record matched.
			}
			if name == "provider" {
				input.Profiles[index].Provider = "invalid provider"
				request = saveProfileInput(t, f, request, input)
			}
			editRootProfile(t, backend, input.Profiles[index].ProfileID, func(profile *bstate.Profile) {
				profile.Provider = input.Profiles[index].Provider
				usageBytes := []byte("usage")
				profile.Usage = &bstate.UsageProfile{VendorProfile: "fixture usage", AdapterVersion: "v1",
					Executable:      api.Executable{ID: "usage-runtime", SHA256: manifest.Hash([]byte("usage runtime")), Version: "v1"},
					RuntimeManifest: api.BlobRef{ID: "usage-manifest", Class: "manifest", Bytes: int64(len(usageBytes)), SHA256: manifest.Hash(usageBytes)}}
				u := profile.Usage
				switch name {
				case "usage-name":
					u.VendorProfile = "invalid\tname"
				case "usage-empty":
					u.VendorProfile = ""
				case "usage-long":
					u.VendorProfile = strings.Repeat("p", 257)
				case "adapter-empty":
					u.AdapterVersion = ""
				case "adapter-long":
					u.AdapterVersion = strings.Repeat("a", 129)
				case "runtime-id":
					u.Executable.ID = "invalid/runtime"
				case "runtime-digest":
					u.Executable.SHA256 = "bad-digest"
				case "runtime-version":
					u.Executable.Version = ""
				case "manifest-id":
					u.RuntimeManifest.ID = "invalid/manifest"
				case "manifest-digest":
					u.RuntimeManifest.SHA256 = "bad-digest"
				case "manifest-negative":
					u.RuntimeManifest.Bytes = -1
				case "manifest-large":
					u.RuntimeManifest.Bytes = api.MaxObjectBytes + 1
				case "manifest-class":
					u.RuntimeManifest.Class = "artifact"
				}
			})
			scope := humanScope(t, f, "grants.root", request)
			rootProfileCommit(t, f, backend, scope)
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			if name == "valid" {
				if err != nil || len(result.Profiles) != len(input.Profiles) || f.store.transactions != 1 {
					t.Fatal("valid usage enrollment did not issue profiles", err)
				}
				return
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || result.ID != "" || f.store.transactions != 0 {
				t.Fatal("root profile accepted malformed metadata", name, err)
			}
		})
	}
}
