package claudock

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type spendCaptureReader interface {
	SpendFromCapture(context.Context, api.CaptureRecord) ([]api.VendorSpend, error)
}

func TestSpendVendorResult(t *testing.T) {
	for _, name := range []string{"vendor_cost", "fake_key", "edited", "stderr", "missing_cost", "foreign_session", "fraction"} {
		t.Run(name, func(t *testing.T) {
			f := runnerSetup(t)
			reader, ok := any(f.service).(spendCaptureReader)
			if !ok {
				t.Fatal("vendor result spend capture is missing")
			}
			event := map[string]any{"type": "result", "uuid": "result-one", "session_id": f.request.Session.VendorID,
				"is_error": false, "total_cost_usd": 1.25, "cost_usd": 99,
				"modelUsage": map[string]any{"model": map[string]any{"costUSD": 88}},
				"usage":      map[string]any{"input_tokens": 21, "output_tokens": 7, "cache_read_input_tokens": 3, "cache_creation_input_tokens": 4}}
			stream, want := "stdout", int64(1250000)
			switch name {
			case "fake_key":
				event["is_error"], event["total_cost_usd"] = true, 0
				want = 0
			case "stderr":
				stream = "stderr"
			case "missing_cost":
				delete(event, "total_cost_usd")
			case "foreign_session":
				event["session_id"] = "foreign"
			case "fraction":
				event["total_cost_usd"] = 0.0000001
				want = 1
			}
			record := f.setCapture(encodeEvent(t, event), stream)
			if name == "edited" {
				record.Data.SHA256 = contentDigest([]byte("edited"))
			}
			got, err := reader.SpendFromCapture(context.Background(), record)
			if name == "edited" || name == "missing_cost" || name == "foreign_session" {
				if err == nil {
					t.Fatal("unverified or unpriced result was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if name == "stderr" {
				if len(got) != 0 {
					t.Fatal("stderr became vendor spend")
				}
				return
			}
			if len(got) != 1 || got[0].CostMicros != want || got[0].InputTokens != 21 || got[0].OutputTokens != 7 || got[0].CacheReadTokens != 3 || got[0].CacheCreationTokens != 4 {
				t.Fatal("vendor total cost or usage was replaced by a CLI estimate")
			}
		})
	}
}
