package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/native"
)

// Only the planner/native-channel facts are component fixtures. Publication,
// evidence reads, InstallProfile and encrypted profile IO are the real code.
type initialProfileFixture struct {
	*secrets.Service
	api.HumanVerifier
	api.CredentialProjectionIdentity
	runtime api.Executable
	failure error
	calls   int
}

func (f *initialProfileFixture) PlanStandInProfiles(_ context.Context, m InitialManifest, root api.RootGrantManifest) ([]bstate.Profile, error) {
	profiles := make([]bstate.Profile, 0, len(root.Profiles))
	for _, grant := range root.Profiles {
		profiles = append(profiles, bstate.Profile{Schema: "laneboss.credential-profile.v2", Config: m.Config,
			ID: grant.ProfileID, LoginID: api.ID(string(grant.ProfileID) + "-login"), Generation: 1,
			Driver: grant.Driver, Provider: grant.Provider, Runtime: f.runtime, Mode: "helper",
			Models: []string{f.runtime.Version}, VendorVersions: []string{f.runtime.Version}, RefreshFields: []string{},
			Source: api.SecretGrant{ID: "standin-source", SourceHandle: "unavailable-handle", Name: "unavailable", Version: "v1",
				Delivery: "file", Target: "unavailable.json", ExpiresAt: grant.ExpiresAt}, ExpiresAt: grant.ExpiresAt})
	}
	return profiles, nil
}

func (f *initialProfileFixture) InstallProfile(ctx context.Context, profile bstate.Profile) error {
	f.calls++
	if f.failure != nil {
		return f.failure
	}
	return f.Service.InstallProfile(ctx, profile)
}

func initialProfileCase(t *testing.T) (initialBundle, *initialTestStore, *initialProfileFixture, *native.Service, enrollmentClock) {
	t.Helper()
	b := initialFixture(t)
	b.profiles.Profiles = append(b.profiles.Profiles, api.ProfileGrant{ProfileID: "second-profile", Driver: api.DriverClaudock,
		Provider: "component-provider", ExpiresAt: b.profiles.Profiles[0].ExpiresAt})
	replaceInitialDoc(t, &b, &b.manifest.Profiles, b.profiles)
	store := &initialTestStore{path: filepath.Join(privateTestDir(t), "state.json")}
	clock := enrollmentClock{now: time.Now().UTC()}
	backend, err := native.New(native.Dependencies{Config: b.manifest.Config, Directory: filepath.Join(privateTestDir(t), "records"), KeyHandle: "component-key", Clock: clock})
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
	if err := backend.Unlock(context.Background(), "component-key", bytes.NewReader(key)); err != nil {
		t.Fatal(err)
	}
	clear(key)
	f := &initialProfileFixture{runtime: b.sources.Renderer}
	f.Service, err = secrets.New(secrets.Dependencies{Config: b.manifest.Config, Backend: backend, Store: store, Clock: clock, Human: f, ProjectionIdentity: f})
	if err != nil {
		t.Fatal(err)
	}
	b.enrollment = f
	return b, store, f, backend, clock
}

func TestInitialProfileEnrollment(t *testing.T) {
	b, store, f, backend, clock := initialProfileCase(t)
	ctx, channel := initialTestContext(t)
	if _, err := commitInitial(ctx, b, store, clock, channel); err != nil {
		t.Fatal(err)
	}
	if f.calls != len(b.profiles.Profiles) {
		t.Fatal("native publication did not invoke protected profile enrollment")
	}
	disk, err := store.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(disk.Objects) != len(b.objects)+2+len(b.profiles.Profiles) {
		t.Fatal("publication did not retain every service-produced profile observation")
	}
	for _, grant := range b.profiles.Profiles {
		var profile bstate.Profile
		if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("profile", grant.ProfileID, &profile) }); err != nil {
			t.Fatal(err)
		}
		if profile.ID != grant.ProfileID || profile.Driver != grant.Driver || profile.Provider != grant.Provider || profile.Runtime != f.runtime || profile.ExpiresAt != grant.ExpiresAt {
			t.Fatal("encrypted profile differs from the protected enrollment selector")
		}
		var observation bstate.Observation
		if err := api.DecodeObject(disk.Objects[profile.Evidence.ID], &observation); err != nil {
			t.Fatal(err)
		}
		if observation.Available || observation.ProfileID != profile.ID || observation.CheckedAt != disk.Snapshot.PublishedAt || disk.Metadata[profile.Evidence.ID].ACL.Audience != "service" {
			t.Fatal("stand-in enrollment invented vendor availability or lost its protected evidence")
		}
		grant.ID = "issued-component-member"
		room, err := f.Service.Room(ctx, grant)
		if err != nil || room.Available || room.ProfileID != grant.ProfileID || room.Evidence != profile.Evidence {
			t.Fatal("unavailable stand-in profile was treated as authenticated vendor room", err)
		}
	}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := commitInitial(ctx, b, store, clock, channel); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(store.path)
	if err != nil || !bytes.Equal(before, after) || store.calls != 1 || f.calls != 2*len(b.profiles.Profiles) {
		t.Fatal("profile enrollment replay changed the durable publication")
	}
}

func TestInitialProfileEnrollmentRecovery(t *testing.T) {
	b, store, f, backend, clock := initialProfileCase(t)
	ctx, channel := initialTestContext(t)
	sentinel := errors.New("protected profile installer unavailable")
	f.failure = sentinel
	if _, err := commitInitial(ctx, b, store, clock, channel); !errors.Is(err, sentinel) || channel.initialReceipt != nil || store.calls != 1 {
		t.Fatal("profile installer failure was hidden behind the committed publication", err)
	}
	var missing bstate.Profile
	err := backend.WithBroker(ctx, func(j bstate.Journal) error {
		return j.Read("profile", b.profiles.Profiles[0].ProfileID, &missing)
	})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
		t.Fatal("failed enrollment wrote a profile", err)
	}
	f.failure = nil
	if _, err := commitInitial(ctx, b, store, clock, channel); err != nil || store.calls != 1 || channel.initialReceipt == nil {
		t.Fatal("same protected publication could not finish interrupted profile enrollment", err)
	}
	for _, grant := range b.profiles.Profiles {
		var actual bstate.Profile
		if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("profile", grant.ProfileID, &actual) }); err != nil || actual.ID != grant.ProfileID {
			t.Fatal("recovery omitted an exact encrypted profile", err)
		}
	}
}

type initialEvidenceFault struct {
	*initialTestStore
}

func (s initialEvidenceFault) ObjectMetadata(ctx context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	meta, err := s.initialTestStore.ObjectMetadata(ctx, scope, id)
	if err == nil && meta.Ref.Class == "credential_evidence" {
		meta.ACL.Audience = "human"
	}
	return meta, err
}

func TestInitialProfileEvidenceGuard(t *testing.T) {
	b, store, f, _, clock := initialProfileCase(t)
	ctx, channel := initialTestContext(t)
	_, err := commitInitial(ctx, b, initialEvidenceFault{store}, clock, channel)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || channel.initialReceipt != nil || f.calls != 0 || store.calls != 1 {
		t.Fatal("unprotected profile evidence reached the encrypted installer", err)
	}
}
