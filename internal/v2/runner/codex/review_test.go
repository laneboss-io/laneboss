package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Token rotation keeps the enrolled account; a schema-valid foreign account
// must never be handed back for persistence under the original profile.
func TestRefreshAccountPin(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.home.path, ".codex/auth.json")
	rotated := syntheticAuthFor(t, "rotated", "synthetic_account_login_one")
	putFile(t, path, rotated, 0600)
	if err := f.slot.Quiesce(observation(f.request.Target, 0)); err != nil {
		t.Fatal(err)
	}
	credential, err := receiveRefresh(t, f, rotated)
	if err != nil || !bytes.Equal(credential.payload, rotated) {
		t.Fatal("same-account rotation control failed", err)
	}
	foreign := syntheticAuth(t, "foreign")
	putFile(t, path, foreign, 0600)
	_, err = receiveRefresh(t, f, foreign)
	wantCode(t, err, api.CodeForbidden)
	// Isolate account affinity from the separate full-projection digest gate.
	f.home.record.Slot.AuthSHA256 = hashBytes(foreign)
	wantCode(t, f.slot.Matches(f.request.Target, f.request.Home, f.request.Slot), api.CodeIntegrity)
	_, err = NewCredential(f.request.Slot.ProfileID, "login_one", f.home.record.Slot.AccountSHA256, foreign)
	wantCode(t, err, api.CodeForbidden)
}

// Go's case-insensitive field matching must not publish raw API-mode bytes
// after a differently cased alias overwrites the validator's decoded value.
func TestAuthExactKeys(t *testing.T) {
	input := syntheticAuth(t, "exact")
	pin := hashBytes([]byte("synthetic_account_exact"))
	if _, err := NewCredential("profile_one", "login_one", pin, input); err != nil {
		t.Fatal("exact auth control failed", err)
	}
	bad := bytes.Replace(input, []byte(`"OPENAI_API_KEY":null`),
		[]byte(`"OPENAI_API_KEY":"synthetic_paid","openai_api_key":""`), 1)
	if bytes.Equal(bad, input) {
		t.Fatal("auth alias control did not change the source bytes")
	}
	_, err := NewCredential("profile_one", "login_one", pin, bad)
	wantCode(t, err, api.CodeIntegrity)
}

// A missing required history ID cannot silently decode as its zero value.
func TestRequiredRecordFields(t *testing.T) {
	f := newFixture(t)
	data, err := json.Marshal(f.request.Session)
	if err != nil {
		t.Fatal(err)
	}
	var session api.Session
	if err := decode(data, &session); err != nil || session != f.request.Session {
		t.Fatal("exact session control failed", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "history_id")
	bad, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, decode(bad, &session), api.CodeIntegrity)
}

// Vendor maps permit variable fields but cannot replace Unicode, overflow a
// finite number or lose integer precision while retaining different raw bytes.
func TestVendorJSONScalars(t *testing.T) {
	var value map[string]json.RawMessage
	if err := decodeJSON([]byte(`{"x":"\ud83d\ude00","n":7}`), &value, false); err != nil {
		t.Fatal("valid Unicode/number control failed", err)
	}
	for name, data := range map[string]string{
		"surrogate": `{"x":"\ud800"}`,
		"nonfinite": `{"x":1e999}`,
		"integer":   `{"x":9007199254740992}`,
	} {
		t.Run(name, func(t *testing.T) {
			wantCode(t, decodeJSON([]byte(data), &value, false), api.CodeIntegrity)
		})
	}
}

func threadLine() []byte {
	return []byte(`{"type":"thread.started","thread_id":"` + testVendorID + `"}` + "\n")
}

// Original, service-origin spool events work; imported/observational labels
// cannot establish sessions or other authoritative capture-derived facts.
func TestCaptureOrigin(t *testing.T) {
	for _, source := range []string{"event", "object"} {
		t.Run(source, func(t *testing.T) {
			f := newFixture(t)
			record := f.capture(threadLine(), 0)
			if _, err := f.service.SessionFromCapture(context.Background(), record); err != nil {
				t.Fatal("outside capture control failed", err)
			}
			if source == "event" {
				f.store.events[0].Origin = "legacy_import"
			} else {
				metadata := f.store.metadata[record.Data.ID]
				metadata.Origin = "legacy_import"
				f.store.metadata[record.Data.ID] = metadata
			}
			_, err := f.service.SessionFromCapture(context.Background(), record)
			wantCode(t, err, api.CodeIntegrity)
		})
	}
}

// A primary label cannot promote a record-class object into a capture object.
func TestCaptureClass(t *testing.T) {
	f := newFixture(t)
	record := f.capture(threadLine(), 0)
	if _, err := f.service.SessionFromCapture(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	record.Data = f.store.keepClass(threadLine(), "record")
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	f.store.events[0].Payload = data
	_, err = f.service.SessionFromCapture(context.Background(), record)
	wantCode(t, err, api.CodeIntegrity)
}

// Hashing a prompt prefix is insufficient when the committed object is longer.
func TestPromptMetadata(t *testing.T) {
	f := newFixture(t)
	if _, err := f.service.Start(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	bad := f.request
	bad.Prompt.Bytes = 4
	bad.Prompt.SHA256 = hashBytes(f.store.blobs[bad.Prompt.ID][:4])
	turn := f.store.turns[bad.Target]
	turn.Prompt = &bad.Prompt
	f.store.turns[bad.Target] = turn
	_, err := f.service.Start(context.Background(), bad)
	wantCode(t, err, api.CodeIntegrity)
}

// This is synthetic parser evidence only. A message-only shape is matched
// exactly against retained source; edited/quoted wording cannot become a limit.
func TestMessageLimit(t *testing.T) {
	message := "synthetic source " + t.Name()
	source, err := json.Marshal(map[string]any{"type": "turn.failed", "error": map[string]string{"message": message}})
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []bool{false, true} {
		// Each independent stream has its own retained binding and EOF; never
		// erase a closed stream to make different bytes appear at offset zero.
		f := newFixture(t)
		f.quotaProof()
		var proof compatibilityProof
		if err := decode(f.store.blobs[f.service.deps.Runtime.LimitEvidence.ID], &proof); err != nil {
			t.Fatal(err)
		}
		proof.Limits[0].Capture = f.store.keep(source)
		data, err := json.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		f.service.deps.Runtime.LimitEvidence = f.store.keep(data)
		input := append([]byte{}, source...)
		if changed {
			input = bytes.Replace(input, []byte(message), []byte(message+" changed"), 1)
		}
		record, exit := f.endCapture(append(input, '\n'), 1)
		signal, err := f.service.LimitFromCapture(context.Background(), record, exit)
		if !changed && (err != nil || signal == nil || signal.CaptureID != record.ID) {
			t.Fatal("message-only retained source was not matched", err)
		}
		if changed && (err != nil || signal != nil) {
			t.Fatal("changed message became a sourced limit", err)
		}
	}
}

// A matching provider sample still cannot choose another grant for this run.
func TestLimitGrantBinding(t *testing.T) {
	f := newFixtureInventory(t, true)
	f.quotaProof()
	// Both members were declared before admission. Build the real capture for
	// the selected member, then supply an inconsistent leased-credential event.
	record := f.capture([]byte(`{"type":"turn.failed","error":{"code":"synthetic_quota"}}`+"\n"), 0)
	exit := observation(f.request.Target, 1)
	slot := f.request.Slot
	other := f.store.grants.Profiles[1]
	slot.ProfileGrantID, slot.ProfileID = other.ID, other.ProfileID
	f.store.event(f.request.Target, "credential.leased", api.CredentialEvent{Slot: slot, Outcome: "leased"})
	f.store.event(f.request.Target, "run.observed", exit)
	f.closeCapture(record)
	if _, err := f.service.captured(context.Background(), record, true); err != nil {
		t.Fatal("profile-binding fixture failed before the deciding limit guard", err)
	}
	_, err := f.service.LimitFromCapture(context.Background(), record, exit)
	wantCode(t, err, api.CodeIntegrity)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Message != "Codex limit profile differs from its reserved life grants" {
		t.Fatal("profile-binding fixture reached a different guard", err)
	}
}

// A complete session prefix remains usable while a later line is in flight;
// the same unfinished tail is still incomplete for final limit classification.
func TestSessionPartialTail(t *testing.T) {
	f := newFixture(t)
	data := append(threadLine(), []byte(`{"type":"item.completed","item":`)...)
	record := f.capture(data, 0)
	session, err := f.service.SessionFromCapture(context.Background(), record)
	if err != nil || session.VendorID != testVendorID {
		t.Fatal("complete session prefix was lost at a later split line", err)
	}
	_, err = vendorRecords(data)
	wantCode(t, err, api.CodeUnavailable)
	if _, err := vendorRecords(append(threadLine(), []byte(" \t")...)); err != nil {
		t.Fatal("trailing whitespace became an incomplete record", err)
	}
}

// Large ordinary tool output shares the retained object bound, not the much
// smaller configuration/RPC-frame bound. Actual bytes cross chunk boundaries.
func TestSessionLargeLine(t *testing.T) {
	f := newFixture(t)
	tool, err := json.Marshal(map[string]any{"type": "item.completed", "item": map[string]string{
		"type": "command_execution", "aggregated_output": strings.Repeat("x", maxRecordBytes+17)}})
	if err != nil {
		t.Fatal(err)
	}
	data := append(append(threadLine(), tool...), '\n')
	record := f.capture(data, 0)
	session, err := f.service.SessionFromCapture(context.Background(), record)
	if err != nil || session.VendorID != testVendorID {
		t.Fatal("large ordinary capture line blocked session extraction", err)
	}
}

// Unknown capture IDs cannot bind even if their referenced bytes are valid.
func TestBindCaptureOnly(t *testing.T) {
	f := newFixture(t)
	if err := f.slot.Reserve(f.request); err != nil {
		t.Fatal(err)
	}
	record := f.capture(threadLine(), 0)
	bad := record
	bad.ID = "not_captured"
	wantCode(t, f.slot.BindCodexSession(context.Background(), f.service, bad), api.CodeIntegrity)
	if err := f.slot.BindCodexSession(context.Background(), f.service, record); err != nil {
		t.Fatal("outside capture could not bind", err)
	}
	if err := f.slot.Quiesce(observation(f.request.Target, 0)); err != nil {
		t.Fatal(err)
	}
}

// The unmapped startup helper preserves its local quiescence/mapping checks.
// Fix 9 has no retained-run start mode; these unit controls do not authorize a
// new public retry path through its reservation/plan validators.
func TestStartupRetry(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		name := "unmapped"
		if mapped {
			name = "mapped"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if err := f.slot.Reserve(f.request); err != nil {
				t.Fatal(err)
			}
			exit := observation(f.request.Target, 1)
			f.store.event(f.request.Target, "lane.ended", api.RunEndEvent{Observation: exit})
			if err := f.slot.Quiesce(exit); err != nil {
				t.Fatal(err)
			}
			if mapped {
				session := f.request.Session
				session.VendorID = testVendorID
				f.store.event(f.request.Target, "runner.session", session)
			}
			f.request.Target.Run++
			f.request.Slot.ID = "slot_retry"
			f.request.Slot.LeaseID = "lease_retry"
			f.store.lane.Run = f.request.Target.Run
			if err := f.slot.Install(f.request.Target, f.request.Slot, credentialFor(t, f.request.Slot.ProfileID, "login_one")); err != nil {
				t.Fatal(err)
			}
			err := f.service.startupRetry(context.Background(), f.request)
			if mapped {
				wantCode(t, err, api.CodeConflict)
				return
			}
			if err != nil {
				t.Fatal("quiescent unmapped startup retry was stranded", err)
			}
			if err := f.slot.Reserve(f.request); err != nil {
				t.Fatal("unmapped retry could not reserve its existing private home", err)
			}
			if err := f.slot.Quiesce(observation(f.request.Target, 0)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Even a shaped end event cannot authorize a retry with unknown survivors.
func TestStartupQuiescence(t *testing.T) {
	f := newFixture(t)
	if _, err := f.service.Start(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	exit := observation(f.request.Target, 1)
	exit.Survivors = nil
	f.store.event(f.request.Target, "lane.ended", api.RunEndEvent{Observation: exit})
	f.request.Target.Run = 2
	f.request.Slot.ID = "slot_retry"
	f.request.Slot.LeaseID = "lease_retry"
	f.store.lane.Run = 2
	if err := f.slot.Install(f.request.Target, f.request.Slot, credentialFor(t, f.request.Slot.ProfileID, "login_one")); err != nil {
		t.Fatal(err)
	}
	err := f.service.startupRetry(context.Background(), f.request)
	wantCode(t, err, api.CodeContainmentUnknown)
}

// Both vendor-loaded project files are screened; ordinary hook settings work.
func TestProjectHooks(t *testing.T) {
	root := canonicalTemp(t)
	directory := canonicalTemp(t, filepath.Join(root, ".codex"))
	path := filepath.Join(directory, "hooks.json")
	putFile(t, path, []byte(`{"ordinary_setting":true}`), 0644)
	if err := CheckProjectConfig(root, root); err != nil {
		t.Fatal("ordinary project hooks control failed", err)
	}
	putFile(t, path, []byte(`{"env":{"OPENAI_API_KEY":"synthetic_value"}}`), 0644)
	wantCode(t, CheckProjectConfig(root, root), api.CodeForbidden)
}

// Widening either protected control root is observed after construction.
func TestControlRoots(t *testing.T) {
	for _, which := range []string{"records", "leases"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t)
			path := f.home.records.path
			if which == "leases" {
				path = f.slot.locks.path
			}
			if err := os.Chmod(path, 0755); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.Chmod(path, 0700); err != nil {
					t.Error(err)
				}
			}()
			if which == "records" {
				_, err := f.home.Audit()
				wantCode(t, err, api.CodeIntegrity)
			}
			wantCode(t, f.slot.Matches(f.request.Target, f.request.Home, f.request.Slot), api.CodeIntegrity)
		})
	}
}

func restoreRecordHandle(t *testing.T, records *Records) {
	t.Helper()
	root, err := os.OpenRoot(records.path)
	if err != nil {
		t.Fatal(err)
	}
	records.root = root
}

// A real failed record save cannot make quiescence visible in memory alone.
func TestQuiesceSaveFail(t *testing.T) {
	f := newFixture(t)
	if err := f.slot.Reserve(f.request); err != nil {
		t.Fatal(err)
	}
	if err := f.home.records.root.Close(); err != nil {
		t.Fatal(err)
	}
	err := f.slot.Quiesce(observation(f.request.Target, 0))
	restoreRecordHandle(t, f.home.records)
	if err == nil || !f.home.record.Slot.Active || !f.home.record.Slot.Poisoned || f.home.record.Slot.LastQuiesced.Run != 0 {
		t.Fatal("failed save published quiescence")
	}
	if err := f.slot.Quiesce(observation(f.request.Target, 0)); err != nil {
		t.Fatal(err)
	}
}

// Close the actual records handle after capture's audit but before its bind
// save. The failed publication must restore the prior session and poison reuse.
func TestBindSaveFail(t *testing.T) {
	f := newFixture(t)
	if err := f.slot.Reserve(f.request); err != nil {
		t.Fatal(err)
	}
	if err := f.slot.Quiesce(observation(f.request.Target, 0)); err != nil {
		t.Fatal(err)
	}
	record := f.capture(threadLine(), 0)
	resolve := f.service.deps.ResolveHome
	f.service.deps.ResolveHome = func(ctx context.Context, target api.LifeRef) (api.PrivateHome, error) {
		home, err := resolve(ctx, target)
		if err != nil {
			return home, err
		}
		if err := f.home.records.root.Close(); err != nil {
			return api.PrivateHome{}, err
		}
		return home, nil
	}
	err := f.slot.BindCodexSession(context.Background(), f.service, record)
	restoreRecordHandle(t, f.home.records)
	if err == nil || f.home.record.Session.VendorID != "" || !f.home.record.Slot.Poisoned {
		t.Fatal("failed save published session binding")
	}
}

// A real close failure cannot leave the controller usable after revocation.
func TestRevokeCloseFail(t *testing.T) {
	f := newFixture(t)
	if err := f.slot.logins["login_one"].file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := f.slot.Revoke()
	wantCode(t, err, api.CodeUnavailable)
	if !f.home.record.Slot.Poisoned {
		t.Fatal("failed lease close left the slot usable")
	}
}

// The plan and sealed home state the intended headless mode explicitly. This
// proves construction only; pinned-vendor help and the live write gate are
// separately required before these settings certify a supported runtime.
func TestInnerToolModes(t *testing.T) {
	f := newFixture(t)
	plan, err := f.service.Start(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	settings := map[string]string{}
	counts := map[string]int{}
	for i, argument := range plan.Argv {
		if argument == "-c" && i+1 < len(plan.Argv) {
			key, value, ok := strings.Cut(plan.Argv[i+1], "=")
			if !ok {
				t.Fatal("invalid explicit vendor config argument")
			}
			settings[key], counts[key] = value, counts[key]+1
		}
	}
	if settings["approval_policy"] != `"never"` || counts["approval_policy"] != 1 {
		t.Fatal("plan did not pin noninteractive approval mode")
	}
	if settings["sandbox_mode"] != `"danger-full-access"` || counts["sandbox_mode"] != 1 || plan.InnerSandbox != "disabled" {
		t.Fatal("plan did not leave isolation to the outer boundary")
	}
	configuration := string(getFile(t, filepath.Join(f.home.path, ".codex/config.toml")))
	if !strings.Contains(configuration, "approval_policy = \"never\"\n") {
		t.Fatal("generated home did not pin approval mode")
	}
	if !strings.Contains(configuration, "sandbox_mode = \"danger-full-access\"\n") {
		t.Fatal("generated home did not pin sandbox mode")
	}
}
