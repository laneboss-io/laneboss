package codex

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Fails on quoted/nested thread IDs, duplicate keys, malformed UTF-8/UUIDs,
// trailing objects and changed prior mappings. A real-shaped top-level control
// must produce the actual ID rather than a constant chosen by the adapter.
func TestCodexSessionEnvelope(t *testing.T) {
	for _, bad := range []string{
		`{"type":"item.completed","item":{"type":"agent_message","text":"thread.started"},"thread_id":"` + testVendorID + `"}`,
		`{"type":"user","message":{"type":"thread.started","thread_id":"` + testVendorID + `"}}`,
		`{"type":"thread.started","thread_id":"--last"}`,
		`{"type":"thread.started","thread_id":"` + testVendorID + `","thread_id":"` + testVendorID + `"}`,
		`{"type":"thread.started","thread_id":null}`,
		`{"type":"thread.started","thread_id":"` + testVendorID + `"} {}`,
		string([]byte{'{', '"', 'x', '"', ':', '"', 255, '"', '}'}),
	} {
		if _, err := codexSession([]byte(bad)); err == nil {
			t.Fatal("untrusted or malformed session event accepted")
		}
	}
	for _, vendor := range []string{testVendorID, "c3795162-150a-4dd1-81cc-837573022827"} {
		value, err := codexSession([]byte(`{"type":"thread.started","thread_id":"` + vendor + `"}`))
		if err != nil || value != vendor {
			t.Fatal("session output ignored actual provider ID", err)
		}
	}
}

// Captures can split JSON anywhere. The service must reconstruct exact ordered
// bytes and refuse a cut/missing prefix, corrupt blob or fabricated provenance.
func TestPrimaryCaptureChunks(t *testing.T) {
	f := newFixture(t)
	f.store.pageSize = 1
	data := []byte(`{"type":"thread.started","thread_id":"` + testVendorID + `"}` + "\n")
	first := f.capture(data[:17], 0)
	_, err := f.service.SessionFromCapture(context.Background(), first)
	wantCode(t, err, api.CodeUnavailable)
	last := f.capture(data[17:], 17)
	session, err := f.service.SessionFromCapture(context.Background(), last)
	if err != nil || session.VendorID != testVendorID {
		t.Fatal("split outside capture could not bind", err)
	}
	for _, shape := range []string{"nonprimary", "transcript", "coverage", "digest", "offset", "replacement", "unknown"} {
		bad := last
		switch shape {
		case "nonprimary":
			bad.Primary = false
		case "transcript":
			bad.Stream = "transcript"
		case "coverage":
			bad.Coverage = "complete"
		case "digest":
			bad.Data.SHA256 = hashBytes([]byte("changed_capture"))
		case "offset":
			bad.Offset++
		case "replacement":
			bad.ReplacementOf = "older_capture"
		case "unknown":
			bad.ID = "not_captured"
		}
		_, err := f.service.SessionFromCapture(context.Background(), bad)
		wantCode(t, err, api.CodeIntegrity)
	}
	f.store.chunkCorrupt = true
	_, err = f.service.SessionFromCapture(context.Background(), last)
	wantCode(t, err, api.CodeIntegrity)
}

// Gaps and replacement markers cannot be hidden by a still-present good ID;
// conflicting provider IDs cannot replace an existing protected mapping.
func TestCaptureGapAndConflict(t *testing.T) {
	for _, shape := range []string{"gap", "conflicting-ids", "bound-other"} {
		t.Run(shape, func(t *testing.T) {
			f := newFixture(t)
			data := []byte(`{"type":"thread.started","thread_id":"` + testVendorID + `"}` + "\n")
			if shape == "conflicting-ids" {
				data = append(data, []byte(`{"type":"thread.started","thread_id":"d1fa015a-6cfe-4f23-8c4e-d713d59d2d1f"}`+"\n")...)
			}
			record := f.capture(data, 0)
			if shape == "gap" {
				f.store.event(f.request.Target, "capture.gap", api.CaptureGap{Target: f.request.Target, Stream: "stdout", StartOffset: 0, Reason: "spool-full"})
			}
			if shape == "bound-other" {
				f.store.lane.Session.VendorID = "d1fa015a-6cfe-4f23-8c4e-d713d59d2d1f"
			}
			_, err := f.service.SessionFromCapture(context.Background(), record)
			wantCode(t, err, api.CodeIntegrity)
		})
	}
}

// A valid vendor ID does not validate the lane projection's home/history. Both
// capture consumers must compare those claims with the authoritative resolver.
func TestCaptureHistoryBinding(t *testing.T) {
	for _, shape := range []string{"history", "home", "workspace", "missing-history"} {
		t.Run(shape, func(t *testing.T) {
			f := newFixture(t)
			data := []byte(`{"type":"thread.started","thread_id":"` + testVendorID + `"}` + "\n")
			record, exit := f.endCapture(data, 0)
			original, err := f.service.SessionFromCapture(context.Background(), record)
			if err != nil || original.HistoryID != f.request.Home.HistoryID {
				t.Fatal("unchanged capture history control failed", err)
			}
			if signal, err := f.service.LimitFromCapture(context.Background(), record, exit); err != nil || signal != nil {
				t.Fatal("unchanged nonlimit capture control failed", err)
			}
			switch shape {
			case "history":
				f.store.lane.Session.HistoryID = "another_history"
			case "home":
				f.store.lane.Session.HomeID = "another_home"
			case "workspace":
				f.store.lane.Workspace.ID = "another_workspace"
			case "missing-history":
				f.store.lane.Session.HistoryID = ""
			}
			_, err = f.service.SessionFromCapture(context.Background(), record)
			wantCode(t, err, api.CodeIntegrity)
			_, err = f.service.LimitFromCapture(context.Background(), record, exit)
			wantCode(t, err, api.CodeIntegrity)
		})
	}
}

// A self-consistent prefix or relabeled reference is not the committed object.
// Removing metadata comparison lets these references pass byte/hash checks.
func TestBlobMetadata(t *testing.T) {
	for _, shape := range []string{"prefix", "class"} {
		t.Run(shape, func(t *testing.T) {
			f := newFixture(t)
			data := []byte("retained bytes with a suffix")
			reference := f.store.keep(data)
			got, err := f.service.readBlob(context.Background(), reference)
			if err != nil || string(got) != string(data) {
				t.Fatal("committed object control failed", err)
			}
			if shape == "prefix" {
				reference.Bytes = 8
				reference.SHA256 = hashBytes(data[:8])
			} else {
				reference.Class = "another-class"
			}
			_, err = f.service.readBlob(context.Background(), reference)
			wantCode(t, err, api.CodeIntegrity)
		})
	}
}

func (f *runnerFixture) quotaProof() {
	f.t.Helper()
	var proof compatibilityProof
	if err := json.Unmarshal(f.store.blobs[f.service.deps.Runtime.FileLoginEvidence.ID], &proof); err != nil {
		f.t.Fatal(err)
	}
	proof.Kind = "structured-errors"
	// A synthetic provider code is intentionally outside the product. The
	// classifier must obtain it from these retained source bytes, not a literal.
	source := f.store.keep([]byte(`{"type":"turn.failed","error":{"code":"synthetic_quota"}}` + "\n"))
	proof.Limits = []limitFixture{{Kind: "usage_limit", Capture: source}}
	data, err := json.Marshal(proof)
	if err != nil {
		f.t.Fatal(err)
	}
	f.service.deps.Runtime.LimitEvidence = f.store.keep(data)
}

func (f *runnerFixture) endCapture(data []byte, code int) (api.CaptureRecord, api.ProcessObservation) {
	record := f.capture(data, 0)
	exit := observation(f.request.Target, code)
	f.store.event(f.request.Target, "credential.leased", api.CredentialEvent{Slot: f.request.Slot, Outcome: "leased"})
	f.store.event(f.request.Target, "run.observed", exit)
	f.closeCapture(record)
	f.seedUsage(exit)
	return record, exit
}

// C1: plain/quoted limit wording, tool output, auth and guard errors, generic
// exits and recovered failures must never produce a profile rotation signal.
func TestLimitRejectsUntrustedText(t *testing.T) {
	for _, data := range []string{
		`{"type":"item.completed","item":{"type":"agent_message","text":"You have hit your usage limit"}}`,
		`{"type":"item.completed","item":{"type":"command_execution","aggregated_output":"synthetic_quota","exit_code":1}}`,
		`{"type":"user","error":{"code":"synthetic_quota"}}`,
		`{"type":"turn.failed","error":{"code":"synthetic_auth_error"}}`,
		`{"type":"turn.failed","error":{"code":"forbidden"}}`,
		`{"type":"turn.completed","usage":{"input_tokens":4}}`,
		`{"type":"turn.failed","error":{"code":"synthetic_quota"}}` + "\n" + `{"type":"turn.completed"}`,
	} {
		f := newFixture(t)
		f.quotaProof()
		record, exit := f.endCapture([]byte(data+"\n"), 1)
		signal, err := f.service.LimitFromCapture(context.Background(), record, exit)
		if err != nil || signal != nil {
			t.Fatal("nonquota or recovered output became a limit", err)
		}
	}
}

// The exact code comes from a source fixture. Missing proof, forged exit,
// survivors or changed source bytes must fail; valid source + actual observation
// produces a signal bound to the actual capture/profile/hash, including exit 0.
func TestLimitSourceAndExitEvidence(t *testing.T) {
	for _, code := range []int{0, 1, 7} {
		f := newFixture(t)
		f.quotaProof()
		record, exit := f.endCapture([]byte(`{"type":"turn.failed","error":{"code":"synthetic_quota"}}`+"\n"), code)
		signal, err := f.service.LimitFromCapture(context.Background(), record, exit)
		if err != nil || signal == nil {
			t.Fatal("sourced structured control failed", err)
		}
		if signal.Target != record.Target || signal.ProfileID != f.request.Slot.ProfileID || signal.CaptureID != record.ID || signal.CaptureSHA256 != record.Data.SHA256 || signal.ExitCode == nil || *signal.ExitCode != code || signal.Kind != "usage_limit" {
			t.Fatal("limit signal lost real evidence or exit status")
		}
		f.service.deps.Runtime.LimitEvidence = api.BlobRef{}
		_, err = f.service.LimitFromCapture(context.Background(), record, exit)
		wantCode(t, err, api.CodeNotImplemented)
		other := exit
		different := 8
		other.ExitCode = &different
		_, err = f.service.LimitFromCapture(context.Background(), record, other)
		wantCode(t, err, api.CodeIntegrity)
		other = exit
		other.Survivors = nil
		_, err = f.service.LimitFromCapture(context.Background(), record, other)
		wantCode(t, err, api.CodeContainmentUnknown)
	}
}

// Unknown plain wording and malformed/oversized records are never converted to
// a guessed structured code. Missing source-format support remains explicit.
func TestUnknownFailureSchema(t *testing.T) {
	f := newFixture(t)
	record, exit := f.endCapture([]byte(`{"type":"turn.failed","error":{"message":"Usage limit reached"}}`+"\n"), 1)
	_, err := f.service.LimitFromCapture(context.Background(), record, exit)
	wantCode(t, err, api.CodeNotImplemented)
	for _, data := range [][]byte{[]byte("Usage limit reached\n"), []byte("{broken}\n"), []byte(strings.Repeat("x", maxRecordBytes+1))} {
		if _, err := vendorRecords(data); err == nil {
			t.Fatal("unparseable output was treated as complete no-limit evidence")
		}
	}
}
