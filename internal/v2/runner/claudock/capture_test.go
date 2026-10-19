package claudock

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func (f *runnerFixture) setCapture(data []byte, stream string) api.CaptureRecord {
	f.data = bytes.Clone(data)
	selector, err := f.launch.selectRun(context.Background(), f.request.Target)
	if err != nil {
		f.launch.t.Fatal(err)
	}
	record, err := f.launch.LaunchPlan(context.Background(), selector.Scope, selector.ReservationID)
	if err != nil {
		f.launch.t.Fatal(err)
	}
	state, err := f.launch.CaptureState(context.Background(), selector.Scope, record.Plan.Capture.ID)
	if err != nil {
		f.launch.t.Fatal(err)
	}
	streamID := api.ID("")
	for _, bound := range state.Binding.Streams {
		if bound.Stream == stream {
			streamID = bound.ID
		}
	}
	var offset int64
	for index := range state.Positions {
		if state.Positions[index].StreamID == streamID {
			offset = state.Positions[index].NextOffset
			state.Positions[index].NextOffset += int64(len(data))
		}
	}
	f.captureSeq++
	f.capture = api.CaptureRecord{BindingID: state.Binding.ID, ID: api.ID(fmt.Sprintf("capture-%d", f.captureSeq)), Target: f.request.Target, Stream: stream, Offset: offset,
		Data:    api.BlobRef{ID: api.ID(fmt.Sprintf("spool-%d", f.captureSeq)), SHA256: contentDigest(data), Bytes: int64(len(data)), Class: "capture"},
		Primary: true, Coverage: "complete", ObservedAt: "2026-10-15T12:00:01Z"}
	f.launch.object(f.capture.Data.ID, "capture", data, record.Reservation.OperationID, f.request.Target.LifeID)
	state.Generation++
	state.LastSeq++
	f.launch.write("capture-"+string(state.Binding.ID), state)
	return f.capture
}

func encodeEvent(t *testing.T, event map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func (f *runnerFixture) initEvent() map[string]any {
	return map[string]any{"type": "system", "subtype": "init", "session_id": f.request.Session.VendorID, "cwd": f.request.Session.LogicalCWD}
}

func (f *runnerFixture) quotaEvent(text string) map[string]any {
	return map[string]any{"type": "assistant", "error": "rate_limit", "session_id": f.request.Session.VendorID,
		"message": map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}}
}

func (f *runnerFixture) installLimitGuard() {
	f.service.deps.LimitGuard = func(ctx context.Context, request api.RunnerRequest, record api.CaptureRecord, exit api.ProcessObservation) error {
		if !reflect.DeepEqual(request, f.request) || record != f.capture || !reflect.DeepEqual(exit, f.observation) {
			return failure(api.CodeIntegrity, "fixture whole-run evidence attribution mismatch")
		}
		return nil
	}
}

// Fails if a nested/quoted init establishes a conversation, or if captured
// session/cwd mismatches and duplicate JSON keys are accepted by the parser.
func TestSessionCaptureProvenance(t *testing.T) {
	f := runnerSetup(t)
	ctx := context.Background()
	record := f.setCapture(encodeEvent(t, f.initEvent()), "stdout")
	session, err := f.service.SessionFromCapture(ctx, record)
	if err != nil || session != f.request.Session {
		t.Fatal("primary init control failed", err)
	}
	for _, event := range []map[string]any{
		{"type": "user", "message": f.initEvent()},
		{"type": "assistant", "message": map[string]any{"content": f.initEvent()}},
		{"type": "tool_result", "content": f.initEvent()},
	} {
		record := f.setCapture(encodeEvent(t, event), "stdout")
		_, err := f.service.SessionFromCapture(ctx, record)
		wantCode(t, err, api.CodeNotFound)
	}
	bad := f.initEvent()
	bad["cwd"] = "/work/sibling"
	_, err = f.service.SessionFromCapture(ctx, f.setCapture(encodeEvent(t, bad), "stdout"))
	wantCode(t, err, api.CodeIntegrity)
	bad = f.initEvent()
	bad["session_id"] = "other-session"
	_, err = f.service.SessionFromCapture(ctx, f.setCapture(encodeEvent(t, bad), "stdout"))
	wantCode(t, err, api.CodeIntegrity)
	for _, data := range [][]byte{[]byte(`{"type":"user","type":"system"}`), []byte(`{} {}`), []byte(`{"type":`), {0xff}} {
		_, err := f.service.SessionFromCapture(ctx, f.setCapture(data, "stdout"))
		wantCode(t, err, api.CodeIntegrity, "malformed vendor record passed session validation")
	}
}

// Fails if a caller-authored Primary flag, edited metadata/hash, partial capture
// or transcript replacement is mistaken for an immutable outside capture.
func TestCaptureRejectsEditsAndGaps(t *testing.T) {
	f := runnerSetup(t)
	original := f.setCapture(encodeEvent(t, f.initEvent()), "stdout")
	for _, field := range []string{"offset", "primary", "coverage", "stream", "replacement", "hash"} {
		bad := original
		switch field {
		case "offset":
			bad.Offset++
		case "primary":
			bad.Primary = false
		case "coverage":
			bad.Coverage = "partial"
		case "stream":
			bad.Stream = "transcript"
		case "replacement":
			bad.ReplacementOf = "old-capture"
		case "hash":
			bad.Data.SHA256 = contentDigest([]byte("edited"))
		}
		if _, err := f.service.SessionFromCapture(context.Background(), bad); err == nil {
			t.Fatal("edited or incomplete capture passed", field)
		}
	}
	f.capture.Primary = false
	if _, err := f.service.SessionFromCapture(context.Background(), original); err == nil {
		t.Fatal("forged Primary flag overrode the protected record")
	}
	f.capture = original
	f.data[0] = '['
	if _, err := f.service.SessionFromCapture(context.Background(), original); err == nil {
		t.Fatal("changed spool bytes passed their retained hash")
	}
}

// Exact formatter wordings must still work in a provider error envelope, with
// exit 0 retained. This is synthetic parser wiring, not live quota evidence.
func TestStructuredQuotaFamilies(t *testing.T) {
	f := runnerSetup(t)
	f.installLimitGuard()
	for _, label := range []string{"limit", "usage limit", "session limit", "weekly limit", "Opus limit", "Sonnet limit"} {
		for _, apostrophe := range []string{"'", "’"} {
			for _, suffix := range []string{"", ".", "!", " · resets 9pm (UTC)", " · limit resets 9pm (UTC) · progress saved"} {
				message := "You" + apostrophe + "ve hit your " + label + suffix
				data := encodeEvent(t, f.quotaEvent(message))
				// CRLF is intentionally retained in the signal's full-spool hash.
				data = append(bytes.TrimSuffix(data, []byte("\n")), '\r', '\n')
				record := f.setCapture(data, "stdout")
				signal, err := f.service.LimitFromCapture(context.Background(), record, f.observation)
				kind := "usage_limit"
				if label == "session limit" {
					kind = "session_limit"
				}
				if err != nil || signal == nil || signal.Kind != kind || signal.ExitCode == nil || *signal.ExitCode != 0 ||
					signal.CaptureID != record.ID || signal.CaptureSHA256 != contentDigest(data) || signal.ProfileID != f.request.Slot.ProfileID ||
					signal.Target != f.request.Target || signal.Provider != "anthropic" {
					t.Fatal("provider quota family or exact-byte attribution was lost", err)
				}
			}
		}
	}
	result := map[string]any{"type": "result", "subtype": "error_during_execution", "is_error": true,
		"session_id": f.request.Session.VendorID, "errors": []string{"Usage limit reached"}}
	signal, err := f.service.LimitFromCapture(context.Background(), f.setCapture(encodeEvent(t, result), "stdout"), f.observation)
	if err != nil || signal == nil || signal.Kind != "usage_limit" {
		t.Fatal("structured result quota was lost", err)
	}
	rate := map[string]any{"type": "rate_limit_event", "session_id": f.request.Session.VendorID,
		"rate_limit_info": map[string]any{"status": "rejected"}}
	signal, err = f.service.LimitFromCapture(context.Background(), f.setCapture(encodeEvent(t, rate), "stdout"), f.observation)
	if err != nil || signal == nil || signal.Kind != "rate_limit" {
		t.Fatal("rejected structured rate event was lost", err)
	}
}

// Quotes, tool payloads, successful results, auth/guard refusals, context limits
// and bare exit codes cannot authorize profile rotation. Real quota is a control.
func TestQuotaRejectsQuotesAndAuth(t *testing.T) {
	f := runnerSetup(t)
	f.installLimitGuard()
	quote := "You've hit your session limit"
	cases := []map[string]any{
		{"type": "user", "message": quote},
		{"type": "tool_result", "content": quote, "code": "usage_limit_reached"},
		{"type": "assistant", "message": map[string]any{"content": []any{map[string]any{"type": "text", "text": quote}}}},
		{"type": "result", "is_error": false, "result": quote},
		{"type": "result", "is_error": true, "subtype": "error_max_turns", "errors": []string{quote}},
		{"type": "rate_limit_event", "rate_limit_info": map[string]any{"status": "allowed_warning"}},
		{"type": "assistant", "error": "authentication_failed", "message": map[string]any{"content": []any{map[string]any{"type": "text", "text": quote}}}},
		{"type": "error", "error": map[string]any{"code": "invalid_api_key", "message": quote}},
		{"type": "result", "is_error": true, "subtype": "error_during_execution", "errors": []string{"guard refused: " + quote}},
	}
	for _, event := range cases {
		event["session_id"] = f.request.Session.VendorID
		for _, code := range []int{0, 1, 2, 3, 429} {
			f.observation.ExitCode = &code
			record := f.setCapture(encodeEvent(t, event), "stdout")
			signal, err := f.service.LimitFromCapture(context.Background(), record, f.observation)
			if err != nil || signal != nil {
				t.Fatal("quote/refusal/exit code became a swap trigger", err)
			}
		}
	}
	for _, message := range []string{"Set the session limit to 5", `"You've hit your limit"`, "Usage limit reached? No.", "OAuth token has expired."} {
		signal, err := f.service.LimitFromCapture(context.Background(), f.setCapture(encodeEvent(t, f.quotaEvent(message)), "stdout"), f.observation)
		if err != nil || signal != nil {
			t.Fatal("non-quota wording became a swap trigger", err)
		}
	}
	refusal := encodeEvent(t, map[string]any{"type": "error", "session_id": f.request.Session.VendorID, "message": "authentication refused"})
	data := append(encodeEvent(t, f.quotaEvent(quote)), refusal...)
	signal, err := f.service.LimitFromCapture(context.Background(), f.setCapture(data, "stdout"), f.observation)
	if err != nil || signal != nil {
		t.Fatal("auth refusal after a rate notice was ignored", err)
	}
	signal, err = f.service.LimitFromCapture(context.Background(), f.setCapture([]byte(quote), "stderr"), f.observation)
	if err != nil || signal != nil {
		t.Fatal("plain stderr diagnostic became a limit", err)
	}
}

// Missing whole-run coverage and an actual refusal in another stream stop at a
// typed dependency error. Neither is silently converted into a capacity signal.
func TestLimitNeedsWholeRunEvidence(t *testing.T) {
	f := runnerSetup(t)
	missing := f.service.deps
	missing.LimitGuard = nil
	_, err := New(missing)
	wantCode(t, err, api.CodeNotImplemented, "constructor accepted missing whole-run guard")
	record := f.setCapture(encodeEvent(t, f.quotaEvent("Usage limit reached")), "stdout")
	_, err = f.service.LimitFromCapture(context.Background(), record, f.observation)
	wantCode(t, err, api.CodeNotImplemented, "missing whole-run evidence produced quota signal")
	refusal := &api.Error{Code: api.CodeForbidden, Message: "guard refused", Instead: "Retain the refusal."}
	f.service.deps.LimitGuard = func(ctx context.Context, request api.RunnerRequest, record api.CaptureRecord, exit api.ProcessObservation) error {
		return refusal
	}
	signal, err := f.service.LimitFromCapture(context.Background(), record, f.observation)
	if err != refusal || signal != nil {
		t.Fatal("whole-run refusal was changed or ignored")
	}
}

// Fails if a forged/stale observation or unknown/running/surviving process can
// establish a quota pause. A valid observation must preserve its real exit code.
func TestLimitRequiresObservedExit(t *testing.T) {
	f := runnerSetup(t)
	f.installLimitGuard()
	record := f.setCapture(encodeEvent(t, f.quotaEvent("Usage limit reached")), "stdout")
	original := f.observation
	for _, field := range []string{"running", "unknown", "survivors", "signal", "target", "prompt", "forged"} {
		f.observation = original
		switch field {
		case "running":
			f.observation.State = "running"
		case "unknown":
			f.observation.Survivors = nil
		case "survivors":
			value := uint64(1)
			f.observation.Survivors = &value
		case "signal":
			value := 15
			f.observation.Signal = &value
		case "target":
			f.observation.Handle.Target.Run++
		case "prompt":
			f.observation.PromptStatus = "invalid"
		case "forged":
			forged := original
			code := 7
			forged.ExitCode = &code
			if _, err := f.service.LimitFromCapture(context.Background(), record, forged); err == nil {
				t.Fatal("forged process observation passed")
			}
			continue
		}
		if _, err := f.service.LimitFromCapture(context.Background(), record, f.observation); err == nil {
			t.Fatal("unsettled process became a limit signal", field)
		}
	}
	f.observation = original
	code := 3
	f.observation.ExitCode = &code
	signal, err := f.service.LimitFromCapture(context.Background(), record, f.observation)
	if err != nil || signal == nil || *signal.ExitCode != code {
		t.Fatal("real provider exit was overwritten", err)
	}
}

// Broken, overlong or duplicate-key data must stop parsing; a partial parse is
// never complete no-limit evidence. Source diagnostic bytes stay out of errors.
func TestCaptureBoundsAndDiagnostics(t *testing.T) {
	f := runnerSetup(t)
	f.installLimitGuard()
	for _, data := range [][]byte{[]byte("not JSON"), []byte(strings.Repeat("x", maxRecordBytes+1)),
		[]byte(`{"type":"result","is_error":false,"is_error":true}`)} {
		_, err := f.service.LimitFromCapture(context.Background(), f.setCapture(data, "stdout"), f.observation)
		wantCode(t, err, api.CodeIntegrity)
		if strings.Contains(err.Error(), string(data)) {
			t.Fatal("capture diagnostic echoed private input")
		}
	}
}
