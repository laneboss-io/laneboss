package watchdog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// These port the wave-0 wording/near-miss, exact-byte, exit and privacy
// controls. L1-L4 regression tests below must also fail on the old classifier.
func TestQuotaWordings(t *testing.T) {
	for _, label := range []string{"limit", "usage limit", "session limit", "weekly limit", "Opus limit", "Sonnet limit"} {
		for _, apostrophe := range []string{"'", "’"} {
			for _, suffix := range []string{"", ".", "!", " · resets 9pm (UTC)", " · limit resets 9pm (UTC) · progress saved"} {
				text := "You" + apostrophe + "ve hit your " + label + suffix
				out, err := Classify(api.DriverClaudock, HeadlessText, []byte("\x1b[31m"+text+"\x1b[0m\r\n"), nil, 0)
				kind := UsageLimit
				if label == "session limit" {
					kind = SessionLimit
				}
				if err != nil || !out.Complete || out.Format != HeadlessText || out.ExitCode != 0 || len(out.Signals) != 1 ||
					out.Signals[0].Kind != kind || out.Signals[0].Candidate || out.Signals[0].Structured {
					t.Fatal("sourced text diagnostic changed", err)
				}
			}
		}
	}
	for _, text := range []string{
		"Set the session limit to 5", "No usage limit reached during this run",
		"You've hit your limit for the request size", "Usage limit reached? No.",
		`"You've hit your limit"`, "max turns reached", "context window exceeded",
		"Usage limit reached — grace window active. Checkpoint now.",
	} {
		out, err := Classify(api.DriverClaudock, HeadlessText, []byte(text), nil, 1)
		if err != nil || !out.Complete || len(out.Signals) != 0 || out.ExitCode != 1 {
			t.Fatal("ordinary text became a quota diagnostic", err)
		}
	}
}

func TestStructuredDiagnostics(t *testing.T) {
	cases := []struct {
		name      string
		driver    api.Driver
		line      string
		kind      LimitKind
		candidate bool
	}{
		{"result", api.DriverClaudock, `{"type":"result","is_error":true,"result":"You've hit your session limit · resets 9pm (UTC)"}`, SessionLimit, false},
		{"errors", api.DriverClaudock, `{"type":"result","is_error":true,"errors":["Usage limit reached"]}`, UsageLimit, false},
		{"assistant", api.DriverClaudock, `{"type":"assistant","error":"rate_limit","message":{"content":[{"type":"text","text":"You've hit your weekly limit."}]}}`, UsageLimit, false},
		{"rate", api.DriverClaudock, `{"type":"rate_limit_event","rate_limit_info":{"status":"rejected"}}`, RateLimit, true},
		{"auth", api.DriverClaudock, `{"type":"result","is_error":true,"result":{"code":"token_expired","message":"OAuth token has expired."}}`, AuthExpired, true},
		{"codex-usage", api.DriverCodex, `{"type":"turn.failed","error":{"message":"You've hit your usage limit. Try again later."}}`, UsageLimit, true},
		{"codex-session", api.DriverCodex, `{"type":"turn.failed","error":{"code":"session_limit_reached"}}`, SessionLimit, true},
		{"codex-rate", api.DriverCodex, `{"type":"turn.failed","error":{"code":"rate_limit_exceeded"}}`, RateLimit, true},
		{"codex-auth", api.DriverCodex, `{"type":"error","code":"refresh_token_reused","message":"Your access token could not be refreshed because your refresh token was already used. Please sign in again."}`, AuthExpired, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefix := []byte("\r\n{\"type\":\"turn.started\"}\r\n")
			record := []byte(tc.line + "\r\n")
			data := append(bytes.Clone(prefix), record...)
			original := bytes.Clone(data)
			out, err := Classify(tc.driver, JSONLines, data, nil, 3)
			if err != nil || !out.Complete || out.Format != JSONLines || out.OversizedRecords != 0 || len(out.Signals) != 1 {
				t.Fatal("structured diagnostic was not classified", err)
			}
			signal := out.Signals[0]
			if signal.Kind != tc.kind || signal.Candidate != tc.candidate || !signal.Structured || signal.Stream != "stdout" ||
				signal.Line != 3 || signal.Offset != int64(len(prefix)) || signal.Bytes != len(record) ||
				signal.SHA256 != string(digest(record)) || out.ExitCode != 3 || !bytes.Equal(data, original) {
				t.Fatal("category or exact original byte locator changed")
			}
		})
	}
}

func TestQuotesAndGenericExits(t *testing.T) {
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		for _, line := range []string{
			`{"type":"user","message":"You've hit your limit"}`,
			`{"type":"tool_result","content":"Usage limit reached","code":"usage_limit_reached"}`,
			`{"type":"assistant","message":{"content":[{"type":"text","text":"You've hit your session limit"}]}}`,
			`{"type":"result","is_error":false,"result":"Usage limit reached"}`,
			`{"type":"item.completed","item":{"type":"agent_message","text":"You've hit your usage limit"}}`,
			`{"type":"item.completed","item":{"type":"command_execution","aggregated_output":"Rate limit reached","exit_code":429}}`,
			`{"type":"rate_limit_event","rate_limit_info":{"status":"allowed"}}`,
			`{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning"}}`,
			`{"type":"turn.failed","error":{"code":"context_length_exceeded","message":"maximum context length reached"}}`,
			`{"type":"turn.failed","error":{"code":"invalid_api_key","message":"HTTP 401"}}`,
			`{"type":"error","message":"refused: guard disallows this action"}`,
		} {
			for _, exit := range []int{0, 1, 2, 3, 130, 137, -1} {
				out, err := Classify(driver, JSONLines, []byte(line), nil, exit)
				if err != nil || !out.Complete || len(out.Signals) != 0 || out.ExitCode != exit {
					t.Fatal("ordinary content or generic exit became quota", err)
				}
			}
		}
	}
	// Unproven Codex variants are not promoted by adding a matching test.
	for _, text := range []string{"You have hit your usage limit.", "You have reached your usage limit."} {
		line, err := json.Marshal(map[string]any{"type": "error", "message": text})
		if err != nil {
			t.Fatal(err)
		}
		out, err := Classify(api.DriverCodex, JSONLines, line, nil, 1)
		if err != nil || len(out.Signals) != 0 {
			t.Fatal("unsourced Codex variant was accepted", err)
		}
	}
}

// L1: the old classifier parses both these text streams as provider JSON,
// producing false structured quota or aborting on a pretty-printed brace.
func TestTextNeverStructured(t *testing.T) {
	for _, format := range []OutputFormat{JSONLines, HeadlessText} {
		for _, quoted := range []string{
			`{"type":"result","is_error":true,"result":"Usage limit reached"}`,
			"{\n  \"example\": true\n}\n",
		} {
			var stdout, stderr []byte
			if format == JSONLines {
				stdout = []byte(`{"type":"result","is_error":true,"result":"You've hit your session limit"}`)
				stderr = []byte(quoted)
			} else {
				stdout = []byte(quoted + "\nUsage limit reached\n")
				stderr = []byte(quoted)
			}
			out, err := Classify(api.DriverClaudock, format, stdout, stderr, 0)
			if err != nil || !out.Complete || out.Format != format || len(out.Signals) != 1 {
				t.Fatal("ordinary text hid or forged a limit", err)
			}
			signal := out.Signals[0]
			if signal.Stream != "stdout" || signal.Structured != (format == JSONLines) {
				t.Fatal("plain text acquired provider-envelope trust")
			}
		}
	}
	for _, text := range []string{"Rate limit reached", "Rate limit exceeded", "Too many requests", "429 Too Many Requests", `API Error: 429 {"error":{"message":"Usage limit reached"}}`} {
		out, err := Classify(api.DriverClaudock, JSONLines, nil, []byte("ERROR: "+text+"\n"), 1)
		if err != nil || len(out.Signals) != 1 || out.Signals[0].Kind != RateLimit || out.Signals[0].Structured || !out.Signals[0].Candidate {
			t.Fatal("stderr rate hint lost its text-only status", err)
		}
	}
}

// L2: this must fail with the old scanner's 1 MiB abort. Oversized data is
// deliberately invalid JSON/UTF-8 to prove it is skipped before interpretation.
func TestOversizedRecordThenLimit(t *testing.T) {
	large := bytes.Repeat([]byte{0xff}, 1024*1024+1)
	large = append(large, '\n')
	real := []byte(`{"type":"result","is_error":true,"result":"Usage limit reached"}` + "\r\n")
	for _, stdout := range []bool{true, false} {
		var out Outcome
		var err error
		if stdout {
			out, err = Classify(api.DriverClaudock, JSONLines, append(bytes.Clone(large), real...), nil, 0)
		} else {
			out, err = Classify(api.DriverClaudock, JSONLines, real, large, 0)
		}
		if err != nil || !out.Complete || out.OversizedRecords != 1 || len(out.Signals) != 1 {
			t.Fatal("oversized record suppressed a later small limit", err)
		}
		wantLine, wantOffset := 1, int64(0)
		if stdout {
			wantLine, wantOffset = 2, int64(len(large))
		}
		if out.Signals[0].Line != wantLine || out.Signals[0].Offset != wantOffset || out.Signals[0].SHA256 != string(digest(real)) {
			t.Fatal("skipping oversized bytes corrupted later byte location")
		}
	}
	// Exactly 1 MiB, including the terminator, is still parsed.
	prefix := `{"type":"tool_result","content":"`
	suffix := "\"}\n"
	exact := []byte(prefix + strings.Repeat("x", 1024*1024-len(prefix)-len(suffix)) + suffix)
	out, err := Classify(api.DriverClaudock, JSONLines, append(exact, real...), nil, 1)
	if err != nil || !out.Complete || out.OversizedRecords != 0 || len(out.Signals) != 1 || out.Signals[0].Offset != int64(len(exact)) {
		t.Fatal("record size boundary changed", err)
	}
}

// L3: both code-before-message and a candidate in result before a sourced
// errors entry must resolve to the sourced rule on that same original line.
func TestSourcedSignalWins(t *testing.T) {
	for _, line := range []string{
		`{"type":"result","is_error":true,"result":{"code":"usage_limit_reached","message":"You've hit your usage limit · resets 9pm (UTC)"}}`,
		`{"type":"result","is_error":true,"result":{"code":"usage_limit_reached"},"errors":["Usage limit reached"]}`,
		`{"type":"result","is_error":true,"errors":[{"code":"session_limit_reached"},"You've hit your session limit"]}`,
	} {
		out, err := Classify(api.DriverClaudock, JSONLines, []byte(line), nil, 1)
		if err != nil || len(out.Signals) != 1 || out.Signals[0].Candidate || !out.Signals[0].Structured ||
			(out.Signals[0].Rule != "claude-quota" && out.Signals[0].Rule != "claude-usage-reached") {
			t.Fatal("candidate code hid a sourced message", err)
		}
	}
}

// L4: message splitting, structured API diagnostics and bounded nested error
// fields are independent rows, including auth/rate controls that cannot swap.
func TestNestedMultilineErrors(t *testing.T) {
	for _, entry := range []struct {
		message any
		kind    LimitKind
	}{
		{map[string]any{"message": "Usage limit reached\r\nTry again later."}, UsageLimit},
		{map[string]any{"error": map[string]any{"error": map[string]any{"message": "Usage limit reached"}}}, UsageLimit},
		{`API Error: 429 {"error":{"type":"rate_limit_error","message":"Usage limit reached"}}`, UsageLimit},
		{`API Error: 401 {"error":{"code":"token_expired","message":"OAuth token has expired."}}`, AuthExpired},
	} {
		line, err := json.Marshal(map[string]any{"type": "result", "is_error": true, "result": entry.message})
		if err != nil {
			t.Fatal(err)
		}
		out, err := Classify(api.DriverClaudock, JSONLines, line, nil, 1)
		if err != nil || !out.Complete {
			t.Fatal("structured message was rejected", err)
		}
		found := false
		for _, signal := range out.Signals {
			found = found || (signal.Kind == entry.kind && signal.Structured)
		}
		if !found {
			t.Fatal("nested or multiline provider error was lost")
		}
	}
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		line := []byte(`{"type":"error","error":{"message":"Usage limit reached"}}`)
		out, err := Classify(driver, JSONLines, line, nil, 1)
		if err != nil || len(out.Signals) != 1 || out.Signals[0].Kind != UsageLimit {
			t.Fatal("top-level nested error was lost", err)
		}
	}
	deep := map[string]any{"message": "Usage limit reached"}
	for i := 0; i < 4; i++ {
		deep = map[string]any{"error": deep}
	}
	line, err := json.Marshal(map[string]any{"type": "error", "error": deep})
	if err != nil {
		t.Fatal(err)
	}
	out, err := Classify(api.DriverClaudock, JSONLines, line, nil, 1)
	if err != nil || len(out.Signals) != 0 {
		t.Fatal("nested error depth bound was ignored", err)
	}
}

func TestMalformedAndPrivateOutput(t *testing.T) {
	for _, data := range [][]byte{
		{0xff}, []byte(`{"type":"error"`), []byte("ordinary stdout"), []byte("[]"),
		[]byte(`{"type":"result","is_error":false,"is_error":true,"result":"Usage limit reached"}`),
		[]byte(`{"type":"result","is_error":true,"result":{"message":"Usage limit reached","message":"normal"}}`),
		[]byte(`{"type":"error","message":"Usage limit reached"} {}`),
		[]byte(strings.Repeat(`{"a":`, 66) + "1" + strings.Repeat("}", 66)),
	} {
		out, err := Classify(api.DriverClaudock, JSONLines, data, nil, 1)
		if err == nil || out.Complete {
			t.Fatal("ambiguous or incomplete structured capture was accepted")
		}
	}
	for _, call := range []struct {
		driver api.Driver
		format OutputFormat
	}{{"other", JSONLines}, {api.DriverClaudock, "other"}} {
		out, err := Classify(call.driver, call.format, nil, nil, 0)
		if err == nil || out.Complete {
			t.Fatal("unknown classifier input became a permissive default")
		}
	}
	line := []byte(`{"type":"error","code":"rate_limit_exceeded","message":"synthetic_private_diagnostic"}`)
	out, err := Classify(api.DriverCodex, JSONLines, line, nil, 1)
	if err != nil || len(out.Signals) != 1 {
		t.Fatal("candidate rate error was lost", err)
	}
	encoded, err := json.Marshal(out)
	if err != nil || bytes.Contains(encoded, []byte("synthetic_private_diagnostic")) {
		t.Fatal("diagnostic text leaked into classifier result", err)
	}
	// Bound signal metadata independently from untrusted capture length.
	record := `{"type":"error","code":"rate_limit_exceeded"}` + "\n"
	out, err = Classify(api.DriverCodex, JSONLines, []byte(strings.Repeat(record, 257)), nil, 1)
	if err == nil || out.Complete || len(out.Signals) != 256 {
		t.Fatal(fmt.Sprintf("signal metadata bound failed: count=%d", len(out.Signals)))
	}
}
