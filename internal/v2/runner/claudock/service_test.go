package claudock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type fixedClock struct{ instant time.Time }

func (c fixedClock) Now() time.Time { return c.instant }

// This harness supplies synthetic dependency receipts only. No vendor process
// is executed and no fixture receipt is installed in a production assembly.
type runnerFixture struct {
	launch      *launchFixtureStore
	service     *Service
	home        *Home
	slot        *Slot
	request     api.RunnerRequest
	capture     api.CaptureRecord
	captureSeq  uint64
	data        []byte
	observation api.ProcessObservation
	findings    []Finding
}

func testExecutable(t *testing.T, name, version string) (api.Executable, string) {
	t.Helper()
	path := filepath.Join(temporary(t), name)
	data := []byte("fixture_" + name)
	put(t, path, data)
	if err := os.Chmod(path, 0500); err != nil {
		t.Fatal(err)
	}
	return api.Executable{ID: api.ID(name), Version: version, SHA256: contentDigest(data)}, path
}

func runnerSetup(t *testing.T) *runnerFixture {
	t.Helper()
	return runnerSetupWith(t, nil)
}

func runnerSetupWith(t *testing.T, configure func(*runnerFixture)) *runnerFixture {
	t.Helper()
	f := runnerReady(t, configure)
	plan, err := f.service.Start(context.Background(), f.request)
	if err != nil {
		t.Fatal("launch fixture could not pass the actual adapter", err)
	}
	f.opened(t, plan)
	return f
}

func runnerReady(t *testing.T, configure func(*runnerFixture)) *runnerFixture {
	t.Helper()
	f := &runnerFixture{home: testHome(t, testRecords(t))}
	f.slot = testSlot(t, f.home)
	if err := f.slot.Install(testCredential(t, "profile-a", "login-a")); err != nil {
		t.Fatal(err)
	}
	wrapper, wrapperPath := testExecutable(t, "claudock", "0.1.0")
	vendor, vendorPath := testExecutable(t, "claude", "2.1.296")
	id, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	f.request = api.RunnerRequest{
		Target: api.LifeRef{LifeID: "life-a", Run: 1}, LogicalTurnID: "turn-a",
		Session: api.Session{ID: "session-a", HistoryID: "history-a", Driver: api.DriverClaudock, VendorID: id,
			VendorVersion: vendor.Version, HomeID: "home-a", LogicalCWD: "/work/main"},
		Prompt: api.BlobRef{ID: "brief-a", SHA256: contentDigest([]byte("kept brief\n")), Bytes: 11, Class: "prompt"},
		Home:   api.PrivateHome{ID: "home-a", WorkspaceID: "workspace-a", HistoryID: "history-a", VendorDirectory: PrivateVendorDirectory},
		Slot: api.CredentialSlot{ID: "slot-a", ProfileID: "profile-a", ProfileGrantID: "grant-a", LeaseID: "lease-a",
			Mode: "claudock-headless", ExpiresAt: "2026-10-15T14:00:00Z"},
		Executable: wrapper, Model: "claude-sonnet-4-6", Effort: "high",
		Budget: api.Budget{WallMS: 60000, MemoryBytes: 1 << 28, Processes: 32, DiskBytes: 1 << 30, Currency: "USD"},
	}
	f.observation = fixtureExit(f.request.Target)
	f.launch = &launchFixtureStore{dir: temporary(t), f: f, t: t}
	f.sourceLaunch(t, "start")
	deps := Dependencies{Executable: wrapper, ExecutablePath: wrapperPath, Claude: vendor, ClaudePath: vendorPath,
		Config: "demo", State: f.launch, Sources: f.launch, Storage: f.launch, Grants: f.launch, Credentials: f.launch, CaptureControl: f.launch,
		UsageWindows: f.launch, UsageWorker: f.launch.usageWorker, UsageProfile: f.launch.usageProfile,
		SelectLaunch: f.launch.selectRun,
		LimitGuard: func(context.Context, api.RunnerRequest, api.CaptureRecord, api.ProcessObservation) error {
			return api.NotImplemented("lb-v2-lifecycle", "fixture whole-run evidence")
		},
		Records: f.home.records, Clock: fixedClock{instant: time.Date(2026, 10, 15, 12, 0, 10, 0, time.UTC)},
		Run:      f.launch.run,
		HomePath: f.launch.homePath,
		Profile:  f.launch.profile,
		VerifyMode: func(ctx context.Context, actualWrapper, actualVendor api.Executable, mode string) error {
			if actualWrapper != wrapper || actualVendor != vendor || mode != "claudock-headless" {
				return api.NotImplemented("lb-v2-claudock", "fixture mode identity")
			}
			return nil
		},
		VerifySlot: func(ctx context.Context, request api.RunnerRequest, required uint32) error {
			var bootstrap struct{ Umask uint32 }
			if err := f.launch.read("bootstrap", &bootstrap); err != nil {
				return err
			}
			if required != 0077 || bootstrap.Umask != required {
				return failure(api.CodeForbidden, "fixture bootstrap lacks private vendor umask")
			}
			var retained api.CredentialSlot
			if err := f.launch.read("slot-"+string(request.Slot.ID), &retained); err != nil {
				return err
			}
			if request.Slot != retained || f.slot.profile != string(request.Slot.ProfileID) || !f.slot.ready || f.slot.poisoned {
				return failure(api.CodeForbidden, "fixture lease is not ready")
			}
			_, err := f.slot.Token()
			return err
		},
		Capture: func(ctx context.Context, id api.ID) (api.CaptureRecord, []byte, error) {
			if id != f.capture.ID {
				return api.CaptureRecord{}, nil, failure(api.CodeNotFound, "fixture capture not found")
			}
			return f.capture, bytes.Clone(f.data), nil
		},
		Observation: func(ctx context.Context, target api.LifeRef) (api.ProcessObservation, error) {
			if target != f.observation.Handle.Target {
				return api.ProcessObservation{}, failure(api.CodeNotFound, "fixture observation not found")
			}
			return f.observation, nil
		},
		ReportHome: func(ctx context.Context, home api.PrivateHome, findings []Finding) error {
			if home != f.request.Home {
				return failure(api.CodeIntegrity, "fixture finding attribution mismatch")
			}
			f.findings = append([]Finding{}, findings...)
			return nil
		},
	}
	f.service, err = New(deps)
	if err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(f)
	}
	return f
}

func (f *runnerFixture) history(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(f.home.path, ".claude/projects/project")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, f.request.Session.VendorID+".jsonl")
	data, err := json.Marshal(map[string]any{"type": "user", "sessionId": f.request.Session.VendorID,
		"cwd": f.request.Session.LogicalCWD, "message": map[string]any{"content": t.Name()}})
	if err != nil {
		t.Fatal(err)
	}
	put(t, path, append(data, '\n'))
	return path
}

func wantCode(t *testing.T, err error, code api.ErrorCode, reasons ...string) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		reason := "unexpected typed result"
		if len(reasons) != 0 {
			reason = reasons[0]
		}
		t.Fatal(reason, err)
	}
}

// Fails on lost stdin BlobRef, shared/global selection, session/model/cwd drift,
// credential values in plans, unbound project settings, or history moved by swap.
func TestPlansKeepPrivateContinuation(t *testing.T) {
	f := runnerSetup(t)
	ctx := context.Background()
	plan, err := f.service.Start(ctx, f.request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Driver != api.DriverClaudock || plan.Prompt != f.request.Prompt || plan.Home != f.request.Home || plan.Session != f.request.Session ||
		plan.CWD != f.request.Session.LogicalCWD || plan.Executable != f.request.Executable || plan.InnerSandbox != "off" {
		t.Fatal("runner plan lost an immutable input")
	}
	want := []string{f.service.deps.ExecutablePath, "run", "claude", "--", "-p", "--permission-mode", "bypassPermissions", "--setting-sources", "",
		"--settings", VendorDirectory + "/settings.json", "--session-id", f.request.Session.VendorID,
		"--model", f.request.Model, "--effort", f.request.Effort, "--output-format", "stream-json", "--verbose"}
	if !reflect.DeepEqual(plan.Argv, want) {
		t.Fatal("Claudock argument structure differs from the pinned contract")
	}
	encoded, err := json.Marshal(plan)
	credential, tokenErr := f.slot.Token()
	if err != nil || tokenErr != nil || bytes.Contains(encoded, credential.token) {
		t.Fatal("runner plan leaked a token", err, tokenErr)
	}
	for _, name := range plan.EnvironmentNames {
		if strings.Contains(name, "=") {
			t.Fatal("environment values were put in the plan")
		}
	}
	if replay, err := f.service.Start(ctx, f.request); err != nil || !reflect.DeepEqual(replay, plan) {
		t.Fatal("identical start did not replay its retained plan", err)
	}
	history := f.history(t)
	before := get(t, history)
	if err := os.Symlink("missing", filepath.Join(f.home.path, "browser-lock")); err != nil {
		t.Fatal(err)
	}
	if err := f.slot.Install(testCredential(t, "profile-b", "login-b")); err != nil {
		t.Fatal(err)
	}
	f.request.Target.Run = 2
	f.request.Slot.ID, f.request.Slot.ProfileID, f.request.Slot.ProfileGrantID, f.request.Slot.LeaseID = "slot-b", "profile-b", "grant-b", "lease-b"
	for index, operation := range []func(context.Context, api.RunnerRequest) (api.RunnerPlan, error){f.service.Resume, f.service.Turn} {
		mode := "resume"
		if index == 1 {
			mode = "turn"
		}
		f.sourceLaunch(t, mode)
		continued, err := operation(ctx, f.request)
		if err != nil {
			t.Fatal(err)
		}
		if continued.Session != plan.Session || continued.Home != plan.Home || continued.CWD != plan.CWD || continued.Slot.ID == plan.Slot.ID {
			t.Fatal("continuation moved history/session/cwd or failed to swap the slot")
		}
		if len(f.findings) != 1 || f.findings[0].Kind != "link" {
			t.Fatal("ordinary tool state was not reported")
		}
		if !bytes.Equal(get(t, history), before) {
			t.Fatal("continuation edited conversation bytes")
		}
		f.opened(t, continued)
		f.request.Target.Run++
	}
}

// H2: even a changed protected run request cannot replace the existing home
// binding. Missing history fails, rather than silently starting a fresh session.
func TestContinuationRejectsDrift(t *testing.T) {
	f := runnerSetup(t)
	if _, err := f.service.Start(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	f.request.Target.Run = 2
	f.sourceLaunch(t, "resume")
	if _, err := f.service.Resume(context.Background(), f.request); err == nil {
		t.Fatal("resume without conversation passed")
	}
	f.history(t)
	original := f.request
	for _, field := range []string{"model", "cwd", "session", "home", "history"} {
		f.request = original
		switch field {
		case "model":
			f.request.Model = "claude-opus-4-6"
		case "cwd":
			f.request.Session.LogicalCWD = "/work/other"
		case "session":
			id, err := newUUID()
			if err != nil {
				t.Fatal(err)
			}
			f.request.Session.VendorID = id
		case "home":
			f.request.Home.ID, f.request.Session.HomeID = "home-other", "home-other"
		case "history":
			// Keep the new request internally consistent so this still tests the
			// protected binding, rather than only the draft.4 shape validator.
			f.request.Home.HistoryID, f.request.Session.HistoryID = "history-other", "history-other"
		}
		f.launch.retainRun(f.request)
		var typed *api.Error
		if _, err := f.service.Resume(context.Background(), f.request); !errors.As(err, &typed) || typed.Code != api.CodeIntegrity {
			t.Fatal("continuation drift lost protected reason", field, err)
		}
	}
	f.request = original
	f.launch.retainRun(original)
	if _, err := f.service.Resume(context.Background(), original); err != nil {
		t.Fatal("unchanged continuation control failed", err)
	}
}

// Fails if either actual executable is selected by basename/version alone, or
// if its changed bytes are not checked again immediately before producing a plan.
func TestPlanChecksBothBinaryDigests(t *testing.T) {
	for _, which := range []string{"wrapper", "vendor"} {
		t.Run(which, func(t *testing.T) {
			f := runnerSetup(t)
			path := f.service.deps.ExecutablePath
			if which == "vendor" {
				path = f.service.deps.ClaudePath
			}
			replaceForTest(t, path, []byte("modified_binary"))
			if err := os.Chmod(path, 0500); err != nil {
				t.Fatal(err)
			}
			_, err := f.service.Start(context.Background(), f.request)
			wantCode(t, err, api.CodeIntegrity, "modified runner binary escaped pinned digest check")
			if !strings.Contains(err.Error(), "digest") {
				t.Fatal("wrong-digest operation was not reached")
			}
		})
	}
}

// No dependency or mode may become a passing empty result. In particular the
// file-login port is not silently relabeled as headless/helper/API support.
func TestMissingProofAndUnsupportedModes(t *testing.T) {
	_, err := New(Dependencies{})
	wantCode(t, err, api.CodeNotImplemented)
	f := runnerSetup(t)
	refusal := api.NotImplemented("lb-v2-secrets", "live mode receipt")
	otherVersion := f.service.deps
	otherVersion.Claude.Version = "unreviewed-version"
	_, err = New(otherVersion)
	wantCode(t, err, api.CodeNotImplemented)
	f.service.deps.VerifyMode = func(ctx context.Context, wrapper, vendor api.Executable, mode string) error { return refusal }
	_, err = f.service.Start(context.Background(), f.request)
	if err != refusal {
		t.Fatal("dependency refusal was changed")
	}
	for _, mode := range []string{"claudock-helper", "claudock-api"} {
		f.request.Slot.Mode = mode
		plan, err := f.service.Start(context.Background(), f.request)
		wantCode(t, err, api.CodeNotImplemented)
		if len(plan.Argv) != 0 {
			t.Fatal("unsupported credential mode produced a plan")
		}
	}
}

// Fails if stale slots, malformed requests, cancelled operations or raw private
// dependency diagnostics are accepted/leaked instead of typed failing results.
func TestPlanValidationAndErrors(t *testing.T) {
	f := runnerSetup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.service.Start(ctx, f.request)
	wantCode(t, err, api.CodeCancelled)
	bad := f.request
	bad.Session.VendorID = "--last"
	_, err = f.service.Start(context.Background(), bad)
	wantCode(t, err, api.CodeInvalid)
	bad = f.request
	bad.Budget.MemoryBytes = 1 << 53
	_, err = f.service.Start(context.Background(), bad)
	wantCode(t, err, api.CodeBudget)
	f.request.Slot.ExpiresAt = "2026-10-15T11:00:00Z"
	_, err = f.service.Start(context.Background(), f.request)
	wantCode(t, err, api.CodeForbidden)
	f.request.Slot.ExpiresAt = "2026-10-15T14:00:00Z"
	f.service.deps.Run = func(ctx context.Context, target api.LifeRef) (api.RunnerRequest, error) {
		return api.RunnerRequest{}, errors.New("synthetic_private_diagnostic")
	}
	_, err = f.service.Start(context.Background(), f.request)
	wantCode(t, err, api.CodeUnavailable)
	if strings.Contains(err.Error(), "synthetic_private_diagnostic") {
		t.Fatal("raw dependency values leaked")
	}
}
