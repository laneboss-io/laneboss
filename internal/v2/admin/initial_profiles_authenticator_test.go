//go:build laneboss_partial && laneboss_e2e_authenticator

package admin

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/native"
)

type authenticatedInitialFixture struct {
	*initialProfileFixture
	backend *native.Service
	err     error
	checks  int
}

func (f *authenticatedInitialFixture) PlanStandInProfiles(ctx context.Context, m InitialManifest, root api.RootGrantManifest) ([]bstate.Profile, error) {
	profiles, err := f.initialProfileFixture.PlanStandInProfiles(ctx, m, root)
	for i := range profiles {
		p := &profiles[i]
		p.Source.Name = "e2e-authenticator-" + string(p.ID)
		p.Source.SourceHandle = api.ID("e2e-authenticator-" + string(p.ID))
	}
	return profiles, err
}

func (f *authenticatedInitialFixture) AuthenticateStandInProfile(ctx context.Context, p bstate.Profile) (bool, error) {
	f.checks++
	if f.err != nil {
		return false, f.err
	}
	material := []byte("e2e-authenticator fixture for " + string(p.ID))
	defer clear(material)
	if _, err := f.backend.Store(ctx, api.SecretInfo{SourceHandle: p.Source.SourceHandle, Name: p.Source.Name, Version: p.Source.Version}, api.SecretMaterial{Bytes: material}); err != nil {
		return false, err
	}
	actual, err := f.backend.Fetch(ctx, p.Source)
	defer clear(actual.Bytes)
	return err == nil && bytes.Equal(actual.Bytes, material), err
}

func TestInitialAuthProfilePublish(t *testing.T) {
	b, store, original, backend, clock := initialProfileCase(t)
	f := &authenticatedInitialFixture{initialProfileFixture: original, backend: backend}
	b.enrollment = f
	ctx, channel := initialTestContext(t)
	if _, err := commitInitial(ctx, b, store, clock, channel); err != nil {
		t.Fatal(err)
	}
	disk, err := store.load()
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range b.profiles.Profiles {
		var profile bstate.Profile
		if err := backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("profile", grant.ProfileID, &profile) }); err != nil {
			t.Fatal(err)
		}
		var observation bstate.Observation
		if err := api.DecodeObject(disk.Objects[profile.Evidence.ID], &observation); err != nil {
			t.Fatal(err)
		}
		checked, err := time.Parse(time.RFC3339Nano, string(observation.CheckedAt))
		if err != nil {
			t.Fatal(err)
		}
		expires, err := time.Parse(time.RFC3339Nano, string(observation.ExpiresAt))
		if err != nil || !observation.Available || observation.CheckedAt != disk.Snapshot.PublishedAt || !expires.After(checked) || expires.After(checked.Add(5*time.Minute)) {
			t.Fatal("initial publisher did not retain authenticated room within its real freshness bound", err)
		}
		if disk.Metadata[profile.Evidence.ID].ACL.Audience != "service" || disk.Metadata[profile.Evidence.ID].SourceOperationID != disk.Operation.ID {
			t.Fatal("authenticated room lost the publisher's private ACL or successful producer")
		}
	}
	if f.checks != 2*len(b.profiles.Profiles) {
		t.Fatal("initial publication or readback omitted actual credential authentication")
	}
}

func TestInitialAuthFailureStopsPublish(t *testing.T) {
	b, store, original, backend, clock := initialProfileCase(t)
	sentinel := errors.New("E2E authenticator could not retain its encrypted source")
	f := &authenticatedInitialFixture{initialProfileFixture: original, backend: backend, err: sentinel}
	b.enrollment = f
	ctx, channel := initialTestContext(t)
	if _, err := commitInitial(ctx, b, store, clock, channel); !errors.Is(err, sentinel) || store.calls != 0 || original.calls != 0 || channel.initialReceipt != nil {
		t.Fatal("failed E2E authentication published a success or hid its cause", err)
	}
}
