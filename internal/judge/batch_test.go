package judge

import (
	"fmt"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/typesafe"
)

func TestBatchOfficialResponseAndEgress(t *testing.T) {
	questions := map[string]any{
		"d0-w0": map[string]any{"type": "noul", "instructions": "Does `texts[0]` contradict `decisions[0]`?"},
		"d1-w0": map[string]any{"type": "noul", "instructions": "Does `texts[0]` contradict `decisions[1]`?"},
	}
	bad := []byte(`{"model":"jev-1.13.0","answers":{"d0-w0":{"type":"noul","noul":0.99}},"usage":{"input_tokens":100,"output_tokens":20}}`)
	if _, ok := readBatchAnswer(bad, questions); ok {
		t.Fatal("partial batch was accepted")
	}
	raw := []byte(`{"model":"jev-1.13.0","answers":{"d0-w0":{"type":"noul","noul":0.99},"d1-w0":{"type":"noul","noul":0.07}},"usage":{"input_tokens":100,"output_tokens":40}}`)
	a, ok := readBatchAnswer(raw, questions)
	if !ok || a.nouls["d0-w0"] != 0.99 || a.nouls["d1-w0"] != 0.07 || a.p != nil {
		t.Fatal("official independent Nouls were lost or aggregated")
	}
	root, err := typesafe.Decode([]byte(`{"at":"2026-10-15T00:00:00.000000Z","ask":"ask-0123456789abcdef0123456789abcdef","event":"outcome","outcome":"answered","probability":null,"model":"jev-1.13.0","request":null,"duration_ms":10,"probabilities":{"d0-w0":0.99,"d1-w0":0.07}}`))
	if err != nil {
		t.Fatal(err)
	}
	// Use the production ID generator so this row does not assume its grammar.
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	root["ask"] = id
	if _, err := parseLogLine(encodeJSON(root)); err != nil {
		t.Fatal("batch egress record cannot be read back", err)
	}
	root["probabilities"].(map[string]any)["d1-w0"] = "0.07"
	if _, err := parseLogLine(encodeJSON(root)); err == nil {
		t.Fatal("malformed batch egress probability was accepted")
	}
}

func TestBatchFitsEgressOutcomeReserve(t *testing.T) {
	values := map[string]float64{}
	for i := 0; i < maxBatchQuestions; i++ {
		key := fmt.Sprintf("d%02d-%s", i, strings.Repeat("x", 60))
		values[key] = 0.12345678901234567
	}
	line := logBytes(map[string]any{"at": "2026-10-15T00:00:00.123456Z", "ask": strings.Repeat("a", 32), "event": "outcome", "outcome": "answered", "probability": nil,
		"model": strings.Repeat("m", 128), "request": strings.Repeat("r", 128), "duration_ms": int64(9223372036854775807), "probabilities": values})
	if len(line) > batchCapacityReserve {
		t.Fatal("bounded batch can exceed its reserved outcome bytes")
	}
	if len(line) <= 1024 {
		t.Fatal("row did not exercise a batch larger than the old scalar reserve")
	}
}
