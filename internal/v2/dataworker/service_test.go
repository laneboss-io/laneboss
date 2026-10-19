package dataworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type workerClock struct{ now time.Time }

func (c workerClock) Now() time.Time { return c.now }

// Required draft.3 ports are deliberately unopened in these wiring tests.
// Any accidental call before a real job protocol exists must fail the test.
type unopenedStore struct{ api.StateStore }
type unopenedHelper struct{ api.HelperControl }

// This fixture intentionally implements Probe only. Any accidental prepare,
// launch or host execution makes a focused test fail instead of fabricating it.
type probeLauncher struct {
	api.Launcher
	capabilities api.IsolationCapabilities
	err          error
	probes       int
}

func (p *probeLauncher) Probe(context.Context) (api.IsolationCapabilities, error) {
	p.probes++
	return p.capabilities, p.err
}

func workerFixture(t *testing.T) (*Service, *probeLauncher, api.GrantSet) {
	t.Helper()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	launcher := &probeLauncher{capabilities: api.IsolationCapabilities{Available: true, Backend: "linux-bwrap-landlock"}}
	service, err := New(Dependencies{Store: &unopenedStore{}, Helper: &unopenedHelper{},
		Launcher: launcher, Clock: workerClock{now}})
	if err != nil {
		t.Fatal(err)
	}
	set := api.GrantSet{ID: "grants", LifeID: "child", SHA256: manifest.Hash([]byte("grants")), Generation: 1,
		PolicyGeneration: 1, ExpiresAt: "2030-01-01T01:00:00Z", Resources: []api.ResourceGrant{},
		Data: []api.DataGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{},
		Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	return service, launcher, set
}

func workerCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func TestWorkerMissingPorts(t *testing.T) {
	s, launcher, grants := workerFixture(t)
	materialized, err := s.Materialize(context.Background(), grants)
	workerCode(t, err, api.CodeNotImplemented)
	if materialized.GrantSetID != "" || launcher.probes != 1 {
		t.Fatal("missing framework produced a materialization receipt")
	}
	ref := api.BlobRef{ID: "candidate", SHA256: manifest.Hash([]byte("candidate")), Bytes: 9, Class: "manifest"}
	request := api.TestChildRequest{Child: api.LifeRef{LifeID: "child", Run: 1}, Candidate: ref, TestPlan: ref,
		Budget: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 4096, Processes: 2, DiskBytes: 4096, Currency: "USD"}}
	op, err := s.TestChild(context.Background(), request, grants)
	workerCode(t, err, api.CodeNotImplemented)
	if op.ID != "" {
		t.Fatal("missing worker created a success-shaped operation")
	}
	archive, err := s.Archive(context.Background(), api.ArchiveRequest{Target: request.Child, ExpectedGeneration: 1})
	workerCode(t, err, api.CodeNotImplemented)
	if archive.ReadBackSHA256 != "" {
		t.Fatal("archive manufactured a read-back digest")
	}
	change, err := s.Render(context.Background(), renderFixture())
	workerCode(t, err, api.CodeNotImplemented)
	if change.ManifestSHA256 != "" {
		t.Fatal("renderer manufactured derived evidence")
	}
}

func renderFixture() api.ChangeRequest {
	ref := api.BlobRef{ID: "ownership", Class: "manifest", Bytes: 2, SHA256: manifest.Hash([]byte("{}"))}
	return api.ChangeRequest{ID: "change", Config: "case-grants", OrgID: "org", BaseGeneration: 1,
		SourceSnapshot:    api.OrgSnapshotRef{OrgID: "org", Generation: 1, ManifestSHA256: manifest.Hash([]byte("sources"))},
		OwnershipManifest: ref, Reason: api.BlobRef{ID: "reason", Class: "report", Bytes: 6, SHA256: manifest.Hash([]byte("reason"))},
		Renderer:  api.Executable{ID: "renderer", SHA256: manifest.Hash([]byte("renderer")), Version: "1"},
		Requester: api.Actor{Kind: "lane", ID: "actor", LifeID: "root", Level: 6}, Files: []api.ResourceDelta{}}
}

func TestRenderSnapshot(t *testing.T) {
	for _, item := range []struct {
		name   string
		mutate func(*api.ChangeRequest)
	}{
		{"config", func(r *api.ChangeRequest) { r.Config = "" }},
		{"org", func(r *api.ChangeRequest) { r.SourceSnapshot.OrgID = "other" }},
		{"generation", func(r *api.ChangeRequest) { r.SourceSnapshot.Generation++ }},
		{"digest", func(r *api.ChangeRequest) { r.SourceSnapshot.ManifestSHA256 = "invalid" }},
		{"renderer", func(r *api.ChangeRequest) { r.Renderer.ID = "" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			s, launcher, _ := workerFixture(t)
			request := renderFixture()
			item.mutate(&request)
			_, err := s.Render(context.Background(), request)
			workerCode(t, err, api.CodeInvalid)
			if launcher.probes != 0 {
				t.Fatal("invalid D6 snapshot reached the launcher")
			}
		})
	}
}

func TestWorkerPrerequisiteFailures(t *testing.T) {
	s, launcher, grants := workerFixture(t)
	launcher.capabilities.Available = false
	_, err := s.Materialize(context.Background(), grants)
	workerCode(t, err, api.CodePrerequisite)
	launcher.err = api.NotImplemented("lb-v2-linux", "linux.Probe")
	_, err = s.Materialize(context.Background(), grants)
	if !errors.Is(err, launcher.err) {
		t.Fatal("platform error was swallowed or replaced")
	}
	grants.Revoked = true
	probes := launcher.probes
	_, err = s.Materialize(context.Background(), grants)
	workerCode(t, err, api.CodeForbidden)
	if launcher.probes != probes {
		t.Fatal("revoked grants reached the launcher")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = RunInternal(ctx, "case-grants", nil)
	workerCode(t, err, api.CodeCancelled)
	err = RunInternal(context.Background(), "case-grants", []string{"--lease", "untrusted"})
	workerCode(t, err, api.CodeInvalid)
}

func TestWorkerConstructor(t *testing.T) {
	_, err := New(Dependencies{})
	workerCode(t, err, api.CodePrerequisite)
	var typedNil *probeLauncher
	_, err = New(Dependencies{Launcher: typedNil, Clock: workerClock{time.Now()}})
	workerCode(t, err, api.CodePrerequisite)
}
