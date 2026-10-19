//go:build linux && laneboss_root_canary

package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

// Actual pinned Claude Code consumes the real adapter's selected arguments,
// private home/settings and credential mode. A loopback provider rejects every
// request with 401; no provider credential or external model request is used.
// The surrounding authority/containment ports are component fixtures.
func TestVendorExitBeforeStop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("run the rejected-vendor component on the unprivileged Linux box")
	}
	vendor := installExitVendor(t)
	for _, mode := range []string{"claude-api-key", "claudock-headless"} {
		t.Run(mode, func(t *testing.T) {
			f, plan, privateHome := apiKeyEnrolledCanary(t, mode, vendor)
			record := f.store.plans[plan.Reservation.ID]
			scope, request := f.claim(t, record)
			lane := f.bindPrepared(t, scope, request, plan)
			f.target = plan.Reservation.Target
			f.launcher.observation = api.ProcessObservation{Handle: api.ProcessHandle{ID: launchIDForTest(), Target: f.target,
				ContainmentID: plan.Lease.ContainmentID, Generation: f.store.bindings[lane.LaunchID].Prepared.ProcessGeneration},
				State: "running", PromptStatus: "written", ObservedAt: "2030-01-02T03:04:05Z"}
			one := uint64(1)
			f.launcher.observation.Survivors = &one
			lane.State, lane.Containment = "running", "running"
			f.store.lanes[lane.LifeID] = lane
			f.fixture.addTo(lane, "run.observed", f.launcher.observation, "service", f.parent)
			credential := []byte("sk-ant-rejected-component-" + string(launchIDForTest()))
			defer clear(credential)
			var calls, selected atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/v1/messages") {
					calls.Add(1)
					actual := r.Header.Get("X-Api-Key")
					if mode == "claudock-headless" {
						actual = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					}
					if bytes.Equal([]byte(actual), credential) {
						selected.Add(1)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				if _, err := io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"rejected component credential"}}`); err != nil {
					t.Error("cannot return the measured local authentication refusal")
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			arguments := append([]string(nil), plan.Runner.Argv[4:]...)
			mapped := false
			for i := 1; i < len(arguments); i++ {
				if arguments[i-1] == "--settings" && arguments[i] == claudock.VendorDirectory+"/settings.json" {
					// This component has no native /home/lane mount. Map only
					// that exact namespace path to the adapter's actual file.
					arguments[i], mapped = filepath.Join(privateHome, ".claude/settings.json"), true
				}
			}
			if !mapped {
				t.Fatal("real adapter plan omitted its pinned generated settings")
			}
			cmd := exec.CommandContext(ctx, vendor, arguments...)
			cmd.Dir = privateHome
			cmd.Env = []string{"HOME=" + privateHome, "PATH=/usr/bin:/bin", "LANG=C", "ANTHROPIC_BASE_URL=" + server.URL,
				"CLAUDE_CODE_DISABLE_" + "NONESSENTIAL_TRAFFIC=1", "DISABLE_AUTOUPDATER=1", "DISABLE_TELEMETRY=1",
				"CLAUDE_CODE_MAX_RETRIES=0", api.ClaudeSlotEnvironment(mode) + "=" + string(credential)}
			prompt := f.store.blobs[plan.Runner.Prompt.ID]
			if len(prompt) == 0 || digestOfBytes(prompt) != plan.Runner.Prompt.SHA256 {
				t.Fatal("rejected vendor lost its actual retained prompt bytes")
			}
			cmd.Stdin = bytes.NewReader(prompt)
			output, runErr := cmd.CombinedOutput()
			defer clear(output)
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(runErr, &exit) || exit.ExitCode() <= 0 || calls.Load() == 0 || calls.Load() != selected.Load() ||
				!bytes.Contains(output, []byte("authentication_error")) && !bytes.Contains(output, []byte("401")) || bytes.Contains(output, credential) {
				// Emit only named fixed diagnostics, never vendor text or input.
				for _, diagnostic := range []string{"bypassPermissions", "Invalid API key", "login", "settings", "session", "permission", "API Error", "ENOENT", "EACCES", "does not exist", "Invalid settings", "Invalid JSON", "unknown option", "not found", "Could not", "must be", "No such file", "setting-sources"} {
					t.Logf("vendor diagnostic %s=%t", diagnostic, bytes.Contains(output, []byte(diagnostic)))
				}
				t.Fatalf("real vendor did not exit on the measured rejected credential: exit_error=%t messages=%d selected=%d deadline=%t", exit != nil, calls.Load(), selected.Load(), ctx.Err() != nil)
			}
			code, zero := exit.ExitCode(), uint64(0)
			retained := filepath.Dir(vendor)
			if err := os.WriteFile(filepath.Join(retained, mode+"-prompt.input"), prompt, 0400); err != nil {
				t.Fatal("cannot retain the actual rejected-vendor prompt", err)
			}
			if err := os.WriteFile(filepath.Join(retained, mode+"-rejection.output"), output, 0600); err != nil {
				t.Fatal("cannot retain measured vendor rejection bytes", err)
			}
			settings, err := os.ReadFile(filepath.Join(privateHome, ".claude/settings.json"))
			if err != nil || os.WriteFile(filepath.Join(retained, mode+"-settings.input"), settings, 0400) != nil {
				t.Fatal("cannot retain actual generated vendor settings", err)
			}
			t.Logf("rejected vendor retained output_sha256=%s settings_sha256=%s", digestOfBytes(output), digestOfBytes(settings))
			f.launcher.observation.State, f.launcher.observation.ExitCode, f.launcher.observation.Survivors = "exited", &code, &zero
			f.launcher.observation.PromptStatus = "completed"
			if _, err := f.service.LaneCheck(context.Background(), f.fixture.scope("lane.check", f.target, f.parent), f.target); err != nil {
				t.Fatal("service did not journal the actual rejected vendor exit", err)
			}
			before := f.store.lanes[lane.LifeID]
			facts, err := f.service.facts(context.Background(), f.scope, before, f.target)
			if err != nil || before.State != "verifying" || facts.end == nil || facts.end.Reason != "exit" || facts.end.Observation.ExitCode == nil || *facts.end.Observation.ExitCode != code {
				t.Fatal("service records did not confirm the naturally ended state before stop", err)
			}
			t.Logf("real vendor before stop: mode=%s state=%s end_reason=%s exit=%d survivors=%d rejected_requests=%d vendor_sha256=%s", mode, before.State, facts.end.Reason, code, *facts.end.Observation.Survivors, calls.Load(), plan.Inputs.Sources.Runtime.SessionExecutable.SHA256)
			reason := f.fixture.blob(launchIDForTest(), "task", []byte("collect rejected vendor run\n"))
			stop := api.StopRequest{Target: f.target, ExpectedGeneration: before.Generation, Reason: reason}
			operation, err := f.service.LaneStop(context.Background(), f.fixture.scope("lane.stop", stop, f.parent), stop)
			if err != nil || operation.Status != "succeeded" {
				t.Fatal("already-ended real vendor stop was refused", err)
			}
			if operation.Stop == nil || operation.Stop.State != before.State || !reflect.DeepEqual(operation.Stop.End, *facts.end) {
				t.Fatal("real vendor stop changed its measured terminal result")
			}
			finishVendorCollection(t, f)
			stopEndedJournal(t, code)
		})
	}
}

// The same ended life continues through the real lifecycle/archive byte checks.
// Archive worker identity and native owned removal remain explicit fixtures.
func finishVendorCollection(t *testing.T, f *launchFixture) {
	t.Helper()
	terminal := terminalFixtureFor(t, f.fixture, f.store)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observed, err := f.service.LaneCheck(ctx, f.fixture.scope("lane.check", f.target, f.parent), f.target)
	if err != nil || requireQuiescence(observed) != nil {
		t.Fatal("rejected vendor could not verify quiescence", err)
	}
	lane := f.store.lanes[f.target.LifeID]
	mark := api.MarkRequest{Target: f.target, ExpectedGeneration: lane.Generation, State: "abandoned",
		Review: api.ReviewReceipt{Checks: []api.BlobRef{}, RefusalResolution: []api.ID{}}}
	if _, err := f.service.LaneMark(ctx, f.fixture.scope("lane.mark", mark, f.parent), mark); err != nil {
		t.Fatal("rejected vendor could not be abandoned", err)
	}
	lane = f.store.lanes[f.target.LifeID]
	var end api.Event
	var decisions []api.Event
	for _, event := range f.store.events {
		if event.LifeID != lane.LifeID || event.Run != lane.Run {
			continue
		}
		if event.Kind == "lane.ended" {
			end = event
		}
		if end.ID != "" && event.Seq > end.Seq && event.Kind == "lane.state" {
			decisions = append(decisions, event)
		}
	}
	baseEpoch := f.store.bindings[lane.LaunchID].Recovery.Handoff.Cause.CancellationEpoch
	t.Logf("terminal archive epoch records: launch=%d after_terminal_stop=%d abandoned=%d", baseEpoch, lane.CancellationEpoch-1, lane.CancellationEpoch)
	if err := admin.ExerciseTerminalArchiveEpoch(baseEpoch, lane, end, decisions); err != nil {
		t.Fatal("same ended vendor life refused native archive epoch comparison", err)
	}
	archiveRequest := api.ArchiveRequest{Target: f.target, ExpectedGeneration: lane.Generation}
	archiveScope := f.fixture.scope("lane.archive", archiveRequest, f.parent)
	terminal.store.receiptAwaited = make(chan struct{}, 1)
	type archived struct {
		receipt api.ArchiveReceipt
		err     error
	}
	done := make(chan archived, 1)
	go func() {
		receipt, err := f.service.LaneArchive(ctx, archiveScope, archiveRequest)
		done <- archived{receipt, err}
	}()
	select {
	case <-terminal.store.receiptAwaited:
	case early := <-done:
		t.Fatal("rejected vendor archive did not await its retained worker", early.err)
	case <-ctx.Done():
		t.Fatal("rejected vendor archive deadline")
	}
	key := api.RequestKey{Method: archiveScope.Request.Method, IdempotencyKey: archiveScope.Request.IdempotencyKey, RequestSHA256: archiveScope.Request.RequestSHA256}
	pending, err := terminal.store.LookupReceipt(ctx, archiveScope, key)
	if err != nil {
		t.Fatal(err)
	}
	want := terminal.finishArchive(t, pending.Operation.ID, "valid")
	result := <-done
	if result.err != nil || result.receipt != want || !terminal.store.archiveReadWitness(false) {
		t.Fatal("rejected vendor archive did not verify actual tar read-back bytes", result.err)
	}
	lane = f.store.lanes[f.target.LifeID]
	clean := api.CleanRequest{Target: f.target, ExpectedGeneration: lane.Generation, ArchiveReceiptID: result.receipt.ID}
	operation, err := f.service.LaneClean(ctx, f.fixture.scope("lane.clean", clean, f.parent), clean)
	if err != nil {
		t.Fatal("rejected vendor clean intent was refused", err)
	}
	var effect api.EffectRecord
	for _, candidate := range f.store.effects {
		if candidate.Effect.OperationID == operation.ID {
			effect = candidate
		}
	}
	if effect.Effect.Context == nil || effect.Effect.Clean == nil {
		t.Fatal("rejected vendor clean has no retained collector effect")
	}
	internal := api.Scope{Config: "example", Actor: effect.Effect.Context.Actor, Source: "outbox", PolicyGeneration: 1}
	lease, err := terminal.store.ClaimEffect(ctx, internal, api.EffectClaimRequest{EffectID: effect.Effect.ID,
		ExpectedGeneration: effect.Generation, ClaimantID: internal.Actor.ID, Deadline: "2030-01-02T03:09:05Z"})
	if err != nil {
		t.Fatal(err)
	}
	collector := &collectorFixture{objects: map[api.ID][]byte{lane.Workspace.ID: append([]byte{}, f.store.blobs[lane.Task.ID]...)},
		owned: map[api.ID]bool{lane.Workspace.ID: true}, dirty: map[api.ID]bool{}, results: map[api.ID]api.CleanEvent{}, observation: observed}
	f.service.deps.Collector = collector
	if _, err := f.service.CollectClean(ctx, internal, lease); err != nil || !f.store.lanes[lane.LifeID].Cleaned || collector.calls != 1 {
		t.Fatal("rejected vendor clean did not retain its collector result", err)
	}
	stop := api.StopRequest{Target: f.target, ExpectedGeneration: lane.Generation, Reason: lane.Task}
	_, err = f.service.LaneStop(ctx, f.fixture.scope("lane.stop", stop, f.parent), stop)
	requireCode(t, err, api.CodeConflict)
	t.Log("same rejected vendor life: quiescent, abandoned, archive read-back verified and cleaned; later stop conflicts")
}

func installExitVendor(t *testing.T) string {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "lb-v2-apikey-vendor-exit-")
	if err != nil {
		t.Fatal(err)
	}
	installer := filepath.Join(home, "install.sh")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	for _, argv := range [][]string{{"/usr/bin/curl", "--fail", "--silent", "--show-error", "--location", "--output", installer, "https://claude.ai/install.sh"}, {"/usr/bin/bash", installer, claudock.ClaudeVersion}} {
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C"}
		if err := cmd.Run(); err != nil {
			t.Fatal("cannot install exact public vendor version", err)
		}
	}
	path, err := filepath.EvalSymlinks(filepath.Join(home, ".local/bin/claude"))
	if err != nil || !strings.HasPrefix(path, home+"/") {
		t.Fatal("vendor installer escaped its disposable home", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || int64(len(data)) > api.MaxVendorBytes {
		t.Fatal("vendor input bytes are absent or exceed the pin bound", err)
	}
	version := exec.CommandContext(ctx, path, "--version")
	version.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C", "CLAUDE_CODE_DISABLE_" + "NONESSENTIAL_TRAFFIC=1"}
	actual, err := version.Output()
	if err != nil || !strings.HasPrefix(string(actual), claudock.ClaudeVersion+" ") {
		t.Fatal("actual vendor version differs from its pin", err)
	}
	input, err := json.Marshal(map[string]any{"version_output": string(actual), "sha256": digestOfBytes(data), "bytes": len(data)})
	if err != nil || os.WriteFile(filepath.Join(home, "vendor-input.json"), input, 0600) != nil {
		t.Fatal("cannot retain measured vendor input", err)
	}
	tester, err := os.ReadFile("/proc/self/exe")
	if err != nil || os.WriteFile(filepath.Join(home, "tester.input"), tester, 0500) != nil {
		t.Fatal("cannot retain the actual rejected-vendor test executable", err)
	}
	t.Logf("rejected vendor inputs: vendor_sha256=%s tester_sha256=%s retained=%s", digestOfBytes(data), digestOfBytes(tester), home)
	return path
}
