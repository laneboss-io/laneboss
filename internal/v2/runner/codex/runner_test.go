package codex

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func wantCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("wanted typed %s, got %v", code, err)
	}
}

// Fails on invented start UUIDs, --last, lost exact stdin references, shared
// homes, changed model/cwd/history, or a continuation without capture/quiescence.
func TestStartResumeTurn(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	plan, err := f.service.Start(ctx, f.request)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{f.service.deps.Runtime.ExecutablePath, "-c", `cli_auth_credentials_store="file"`, "-c", `sandbox_mode="danger-full-access"`, "-c", `approval_policy="never"`, "-c", `model_reasoning_effort="high"`, "exec", "--json", "--model", f.request.Model, "-"}
	if !slices.Equal(plan.Argv, want) || plan.Prompt != f.request.Prompt || plan.CWD != f.request.Session.LogicalCWD || plan.Home != f.request.Home || plan.Session != f.request.Session || plan.InnerSandbox != "disabled" || !sameNames(plan.EnvironmentNames) {
		t.Fatal("start plan changed exact invocation or binding")
	}
	if err := f.slot.Reserve(f.request); err != nil {
		t.Fatal(err)
	}
	line := []byte(`{"type":"thread.started","thread_id":"` + testVendorID + `"}` + "\n")
	record := f.capture(line, 0)
	session, err := f.service.SessionFromCapture(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	if session.VendorID != testVendorID || session.ID != f.request.Session.ID || session.HistoryID != f.request.Home.HistoryID {
		t.Fatal("actual vendor identity not captured")
	}
	f.store.event(f.request.Target, "runner.session", session)
	if err := f.slot.BindCodexSession(ctx, f.service, record); err != nil {
		t.Fatal(err)
	}
	for index, method := range []func(context.Context, api.RunnerRequest) (api.RunnerPlan, error){f.service.Resume, f.service.Turn} {
		exit := observation(f.request.Target, 0)
		f.store.event(f.request.Target, "lane.ended", api.RunEndEvent{Observation: exit})
		if err := f.slot.Quiesce(exit); err != nil {
			t.Fatal(err)
		}
		f.request.Target.Run++
		f.request.Session = session
		f.request.Slot.ID += "_next"
		f.request.Slot.LeaseID += "_next"
		f.store.lane.Session = session
		f.store.lane.State = "verifying"
		if err := f.slot.Install(f.request.Target, f.request.Slot, credentialFor(t, f.request.Slot.ProfileID, "login_one")); err != nil {
			t.Fatal(err)
		}
		mode := "resume"
		if index == 1 {
			mode = "turn"
		}
		f.prepareLaunch(mode, 3)
		continued, err := method(ctx, f.request)
		if err != nil {
			t.Fatal(err)
		}
		if continued.Session != session || continued.Home != plan.Home || continued.CWD != plan.CWD || continued.Prompt != f.request.Prompt {
			t.Fatal("continuation lost its private binding or input")
		}
		want = append(append([]string{}, plan.Argv[:10]...), "resume", "--json", "--model", f.request.Model, testVendorID, "-")
		if !slices.Equal(continued.Argv, want) || slices.Contains(continued.Argv, "--last") {
			t.Fatal("continuation is not explicit vendor-ID resume")
		}
		if err := f.slot.Reserve(f.request); err != nil {
			t.Fatal(err)
		}
		// The next run's retained binding comes from the same real adapter plan,
		// not a fabricated ready Lane supplied to Start/Resume/Turn.
		f.capture(line, 0)
	}
	if err := f.slot.Quiesce(observation(f.request.Target, 0)); err != nil {
		t.Fatal(err)
	}
}

// Fails if an ordinary unknown command needs permission, environment values are
// inherited, private paths drift, or a caller can mutate a shared name slice.
func TestPrivateEnvironment(t *testing.T) {
	f := newFixture(t)
	t.Setenv("OPENAI_API_KEY", "synthetic_ambient")
	t.Setenv("CODEX_HOME", "/synthetic/owner")
	physical := f.request.Home
	physical.VendorDirectory = filepath.Join(f.home.path, ".codex")
	environment, err := Environment(physical, "/runtime/bin:/usr/bin:/bin")
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, entry := range environment {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatal("invalid environment")
		}
		values[name] = value
	}
	if len(values) != 7 || values["HOME"] != filepath.Dir(physical.VendorDirectory) || values["CODEX_HOME"] != physical.VendorDirectory {
		t.Fatal("private environment paths changed")
	}
	if _, exists := values["OPENAI_API_KEY"]; exists {
		t.Fatal("ambient auth inherited")
	}
	for _, bad := range []string{"", ":/bin", "/bin:", "bin", "/bin:relative"} {
		if _, err := Environment(physical, bad); err == nil {
			t.Fatal("empty/relative search path accepted")
		}
	}
	first := environmentNames()
	first[0] = "changed"
	if sameNames(first) || environmentNames()[0] != "CODEX_HOME" {
		t.Fatal("environment declaration is mutable across plans")
	}
}

// Each drift row changes one real request field. The unchanged control must
// still plan successfully, so rejecting all requests cannot pass this test.
func TestPlanRejectsBindingDrift(t *testing.T) {
	rows := []struct {
		name   string
		change func(*api.RunnerRequest)
		code   api.ErrorCode
	}{
		{"history", func(r *api.RunnerRequest) { r.Home.HistoryID = "another_history" }, api.CodeIntegrity},
		{"session-history", func(r *api.RunnerRequest) { r.Session.HistoryID = "another_history" }, api.CodeIntegrity},
		{"missing-history", func(r *api.RunnerRequest) { r.Session.HistoryID = "" }, api.CodeInvalid},
		{"home", func(r *api.RunnerRequest) { r.Home.ID = "another_home"; r.Session.HomeID = r.Home.ID }, api.CodeIntegrity},
		{"session", func(r *api.RunnerRequest) { r.Session.ID = "another_session" }, api.CodeConflict},
		{"cwd", func(r *api.RunnerRequest) { r.Session.LogicalCWD = "/work/other" }, api.CodeConflict},
		{"model", func(r *api.RunnerRequest) { r.Model = "gpt-6-sol" }, api.CodeConflict},
		{"effort", func(r *api.RunnerRequest) { r.Effort = "low" }, api.CodeConflict},
		{"slot", func(r *api.RunnerRequest) { r.Slot.ID = "borrowed_slot" }, api.CodeForbidden},
		{"profile", func(r *api.RunnerRequest) { r.Slot.ProfileID = "borrowed_profile" }, api.CodeForbidden},
		{"expiry", func(r *api.RunnerRequest) { r.Slot.ExpiresAt = "2025-01-01T00:00:00Z" }, api.CodeForbidden},
		{"pin", func(r *api.RunnerRequest) { r.Executable.SHA256 = hashBytes([]byte("other_binary")) }, api.CodeVersion},
		{"API", func(r *api.RunnerRequest) { r.Slot.Mode = "codex-api" }, api.CodeNotImplemented},
		{"unknown-mode", func(r *api.RunnerRequest) { r.Slot.Mode = "unknown" }, api.CodeInvalid},
		{"other-driver", func(r *api.RunnerRequest) { r.Slot.Mode = "claudock-helper" }, api.CodeForbidden},
		{"budget", func(r *api.RunnerRequest) { r.Budget.WallMS = 0 }, api.CodeBudget},
		{"prompt", func(r *api.RunnerRequest) { r.Prompt.Bytes = 0 }, api.CodeInvalid},
		{"vendor", func(r *api.RunnerRequest) { r.Session.VendorID = testVendorID }, api.CodeConflict},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := newFixture(t)
			bad := f.request
			row.change(&bad)
			_, err := f.service.Start(context.Background(), bad)
			wantCode(t, err, row.code)
			if _, err := f.service.Start(context.Background(), f.request); err != nil {
				t.Fatal("positive control failed", err)
			}
		})
	}
}

// Even matching caller/lane claims cannot replace the history issued to the
// private home. Removing the history comparison permits both plan and reserve.
func TestSessionHistoryBinding(t *testing.T) {
	f := newFixture(t)
	if _, err := f.service.Start(context.Background(), f.request); err != nil {
		t.Fatal("unchanged history control failed", err)
	}
	request := f.request
	request.Session.HistoryID = "another_history"
	f.store.lane.Session = request.Session
	_, err := f.service.Start(context.Background(), request)
	wantCode(t, err, api.CodeIntegrity)
	wantCode(t, f.slot.Reserve(request), api.CodeIntegrity)
}

// Fails if a deleted self-helper, changed binary bytes or writable artifact is
// accepted merely because the executable ID/basename still looks correct.
func TestArtifactPins(t *testing.T) {
	for _, shape := range []string{"absent-helper", "changed-bytes", "writable", "symlink"} {
		t.Run(shape, func(t *testing.T) {
			f := newFixture(t)
			path := f.service.deps.Runtime.ExecutablePath
			code := api.CodeIntegrity
			switch shape {
			case "absent-helper":
				f.service.deps.Runtime.SelfHelperPath = filepath.Join(filepath.Dir(path), "missing")
				code = api.CodePrerequisite
			case "changed-bytes":
				if _, err := f.service.Start(context.Background(), f.request); err != nil {
					t.Fatal("unchanged artifact control failed", err)
				}
				original, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				changed := []byte("changed_vendor_bytes")
				replacement := filepath.Join(filepath.Dir(path), "changed-codex")
				putFile(t, replacement, changed, 0500)
				if err := os.Rename(replacement, path); err != nil {
					t.Fatal(err)
				}
				current, err := os.Lstat(path)
				if err != nil || !current.Mode().IsRegular() || current.Mode().Perm() != 0500 || os.SameFile(original, current) {
					t.Fatal("changed artifact was not replaced by a new read-only executable")
				}
				if string(getFile(t, path)) != string(changed) {
					t.Fatal("replacement artifact bytes differ from the test input")
				}
			case "writable":
				if err := os.Chmod(path, 0702); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				alias := filepath.Join(filepath.Dir(path), "alias")
				if err := os.Symlink(path, alias); err != nil {
					t.Fatal(err)
				}
				f.service.deps.Runtime.ExecutablePath = alias
			}
			_, err := f.service.Start(context.Background(), f.request)
			wantCode(t, err, code)
		})
	}
}

// Fails if absent compatibility/wiring or a real guard refusal is replaced by
// a successful empty plan. A refusal's code, text and recovery remain intact.
func TestMissingWiringAndRefusal(t *testing.T) {
	for _, name := range []string{"receipt", "home", "project", "slot", "planning", "allocation", "sources", "storage", "session"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			switch name {
			case "receipt":
				f.service.deps.Runtime.FileLoginEvidence = api.BlobRef{}
			case "home":
				f.service.deps.ResolveHome = nil
			case "project":
				f.service.deps.CheckProject = nil
			case "slot":
				f.service.deps.VerifySlot = nil
			case "planning":
				f.service.deps.Planning = api.LaunchPlanRequest{}
			case "allocation":
				f.service.deps.AllocationEffectID = ""
			case "sources":
				f.service.deps.Sources = nil
			case "storage":
				f.service.deps.Storage = nil
			case "session":
				f.service.deps.ResolveSession = nil
			}
			plan, err := f.service.Start(context.Background(), f.request)
			wantCode(t, err, api.CodeNotImplemented)
			if !reflect.DeepEqual(plan, api.RunnerPlan{}) {
				t.Fatal("failed dependency returned a partial successful plan")
			}
		})
	}
	f := newFixture(t)
	refusal := &api.Error{Code: api.CodeForbidden, Message: "synthetic guard reason", Instead: "synthetic allowed recovery"}
	f.service.deps.VerifySlot = func(context.Context, api.LifeRef, api.PrivateHome, api.CredentialSlot) error { return refusal }
	_, err := f.service.Start(context.Background(), f.request)
	if err != refusal {
		t.Fatal("guard refusal or recovery text changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = f.service.Start(ctx, f.request)
	wantCode(t, err, api.CodeCancelled)
}

// Fails if the presence of a receipt alone enables a different binary, parser,
// mode/platform, or missing/tampered observation bytes.
func TestCompatibilityBinding(t *testing.T) {
	for _, shape := range []string{"version", "helper", "platform", "observation"} {
		t.Run(shape, func(t *testing.T) {
			f := newFixture(t)
			reference := f.service.deps.Runtime.FileLoginEvidence
			var proof compatibilityProof
			if err := json.Unmarshal(f.store.blobs[reference.ID], &proof); err != nil {
				t.Fatal(err)
			}
			switch shape {
			case "version":
				proof.AdapterVersion = "other-parser"
			case "helper":
				proof.SelfHelper.ID = "other_helper"
			case "platform":
				proof.Platform = "other-platform"
			case "observation":
				proof.Observations[0].SHA256 = hashBytes([]byte("other_observation"))
			}
			data, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			f.service.deps.Runtime.FileLoginEvidence = f.store.keep(data)
			_, err = f.service.Start(context.Background(), f.request)
			if shape == "observation" {
				wantCode(t, err, api.CodeIntegrity)
			} else {
				wantCode(t, err, api.CodeUnsupported)
			}
		})
	}
}

// No Codex supervisor level is enabled by an ordinary file-login proof. Each
// level needs its own retained real spawn/turn/wait compatibility cell.
func TestSupervisorCapabilityGate(t *testing.T) {
	for _, level := range []int{4, 5, 6} {
		f := newFixture(t)
		f.prepareLaunch("start", level)
		_, err := f.service.Start(context.Background(), f.request)
		wantCode(t, err, api.CodeNotImplemented)
		var proof compatibilityProof
		if err := json.Unmarshal(f.store.blobs[f.service.deps.Runtime.FileLoginEvidence.ID], &proof); err != nil {
			t.Fatal(err)
		}
		proof.Kind = "supervisor-" + strconv.Itoa(level)
		data, err := json.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		f.service.deps.Runtime.SupervisorEvidence = map[int]api.BlobRef{level: f.store.keep(data)}
		if _, err := f.service.Start(context.Background(), f.request); err != nil {
			t.Fatal("level-specific synthetic control failed", err)
		}
	}
}

// Only an effort actually present in the pinned receipt is accepted. There is
// no implicit max alias and the exact supported input reaches argv unchanged.
func TestEffortCompatibilityGate(t *testing.T) {
	f := newFixture(t)
	request := f.request
	request.Effort = "max"
	_, err := f.service.Start(context.Background(), request)
	wantCode(t, err, api.CodeUnsupported)
	if _, err := f.service.Start(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
}
