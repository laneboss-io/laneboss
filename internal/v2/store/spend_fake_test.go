//go:build linux && !laneboss_live_spend

package store

import (
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// The default suite replays a result envelope. The explicit live-spend tag
// replaces only these input bytes with stdout from the pinned real executable.
func spendFakeKeyCapture(t *testing.T, p *api.LaunchPlanRecord) (api.CaptureRecord, []byte) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"type": "result", "uuid": "auth-result", "session_id": p.Plan.Runner.Session.VendorID,
		"is_error": true, "total_cost_usd": 0, "usage": map[string]int{"input_tokens": 0, "output_tokens": 0}, "result": "Invalid API key"})
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	return api.CaptureRecord{ID: testID(t), BindingID: p.Plan.Capture.ID, Target: p.Reservation.Target, Stream: "stdout", Primary: true, Coverage: "partial",
		Data: api.BlobRef{ID: testID(t), Class: "capture", Bytes: int64(len(raw)), SHA256: testDigest(raw)}}, raw
}
