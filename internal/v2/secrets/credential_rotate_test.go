package secrets

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

type rotationJournal struct {
	profile bstate.Profile
	login   bstate.Login
	log     bytes.Buffer
}

func (j *rotationJournal) WithBroker(_ context.Context, fn func(bstate.Journal) error) error {
	return fn(j)
}

func (j *rotationJournal) Read(kind string, _ api.ID, value any) error {
	switch kind {
	case "profile":
		*value.(*bstate.Profile) = j.profile
	case "login":
		*value.(*bstate.Login) = j.login
	default:
		return errors.New("unknown rotation fixture record")
	}
	return nil
}

func (j *rotationJournal) Write(kind string, _ api.ID, value any) error {
	switch kind {
	case "profile":
		switch typed := value.(type) {
		case bstate.Profile:
			j.profile = typed
		case *bstate.Profile:
			j.profile = *typed
		default:
			return errors.New("invalid rotation profile write")
		}
	case "login":
		switch typed := value.(type) {
		case bstate.Login:
			j.login = typed
			j.login.Material = bytes.Clone(typed.Material)
		case *bstate.Login:
			j.login = *typed
			j.login.Material = bytes.Clone(typed.Material)
		default:
			return errors.New("invalid rotation login write")
		}
	default:
		return errors.New("unknown rotation fixture record")
	}
	return nil
}

func (*rotationJournal) Fetch(context.Context, api.SecretGrant) (api.SecretMaterial, error) {
	return api.SecretMaterial{}, errors.New("rotation fixture does not fetch material")
}

func (*rotationJournal) AcquireRefreshLease(api.ID) (bstate.RefreshLease, error) {
	return nil, errors.New("rotation fixture does not acquire leases")
}

type rotationCodex struct{}

func (rotationCodex) RotateCanonicalLogin(_ context.Context, prior bstate.Login) (bstate.Login, error) {
	prior.Generation++
	prior.Material = []byte("rotated-login")
	prior.Quarantined = false
	return prior, nil
}

type rotationSource struct{}

func (rotationSource) MarkSourceRotated(_ context.Context, prior api.SecretGrant, _ string) (api.SecretGrant, error) {
	prior.Version = "source-two"
	prior.SourceHandle = "source-two"
	return prior, nil
}

func rotationFixture(mode string) (*rotationJournal, CredentialRotationRequest) {
	source := api.SecretGrant{ID: "grant", Name: "credential", SourceHandle: "source-one", Version: "source-one"}
	fixture := &rotationJournal{
		profile: bstate.Profile{Schema: "laneboss.credential-profile.v2", Config: "cfg", ID: "profile", LoginID: "login", Mode: mode, Source: source},
		login:   bstate.Login{ID: "login", Generation: 1, Driver: api.DriverCodex, Provider: "provider", Source: &source, Quarantined: true},
	}
	request := CredentialRotationRequest{Command: CredentialRotateCommand, Mode: mode, ProfileID: "profile", LoginID: "login"}
	if mode == CredentialModeClaudeAPIKey {
		request.SourceHandle = source.SourceHandle
		request.SourceVersion = "source-two"
		fixture.profile.Driver = api.DriverClaudock
		fixture.login.Driver = api.DriverClaudock
	}
	return fixture, request
}

func TestRotateCredentialCodexFile(t *testing.T) {
	fixture, request := rotationFixture(CredentialModeCodexFile)
	var journal bytes.Buffer
	result, err := RotateCredential(context.Background(), "cfg", fixture, request, CredentialRotationHandlers{
		Codex:   rotationCodex{},
		Journal: &journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != CredentialModeCodexFile || !result.QuarantineReleased || result.Generation != 2 {
		t.Fatalf("unexpected rotation result: %+v", result)
	}
	if fixture.login.Quarantined || fixture.login.Generation != 2 || !bytes.Equal(fixture.login.Material, []byte("rotated-login")) {
		t.Fatalf("canonical login was not rotated: %+v", fixture.login)
	}
	if got := journal.String(); got != CredentialRotationJournalLine {
		t.Fatalf("journal=%q, want %q", got, CredentialRotationJournalLine)
	}
}

func TestRotateClaudeAPIKeyMarksSource(t *testing.T) {
	fixture, request := rotationFixture(CredentialModeClaudeAPIKey)
	var journal bytes.Buffer
	result, err := RotateCredential(context.Background(), "cfg", fixture, request, CredentialRotationHandlers{
		Source:  rotationSource{},
		Journal: &journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.SourceMarked || result.SourceVersion != "source-two" || !result.QuarantineReleased {
		t.Fatalf("unexpected source rotation result: %+v", result)
	}
	if fixture.profile.Source.Version != "source-two" || fixture.login.Source == nil || fixture.login.Source.Version != "source-two" || fixture.login.Quarantined {
		t.Fatalf("source rotation was not retained: profile=%+v login=%+v", fixture.profile, fixture.login)
	}
}

func TestRotateRequiresMarkedQuarantine(t *testing.T) {
	fixture, request := rotationFixture(CredentialModeCodexFile)
	fixture.login.Quarantined = false
	_, err := RotateCredential(context.Background(), "cfg", fixture, request, CredentialRotationHandlers{Codex: rotationCodex{}, Journal: io.Discard})
	if err == nil {
		t.Fatal("unmarked credential was rotated")
	}
}
