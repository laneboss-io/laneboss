package claudock

import (
	"context"
	"testing"
)

// Field shapes and wording come from docs/claudock.md's 2.1.296 formatter
// sources and integrations/claudock/profile_swap/main.go's result/errors reader.
// These are static-format fixtures, never claimed authenticated vendor captures.
func TestVendorTerminalQuota(t *testing.T) {
	f := runnerSetup(t)
	f.installLimitGuard()
	for _, subtype := range []string{"", "success", "error_during_execution"} {
		for _, field := range []string{"result", "errors", "both"} {
			terminal := map[string]any{"type": "result", "is_error": true, "session_id": f.request.Session.VendorID}
			if subtype != "" {
				terminal["subtype"] = subtype
			}
			message := "You've hit your session limit · resets 9pm (UTC)"
			if field != "errors" {
				terminal["result"] = message
			}
			if field != "result" {
				terminal["errors"] = []string{message}
			}
			for _, preceding := range []bool{false, true} {
				data := encodeEvent(t, terminal)
				if preceding {
					data = append(encodeEvent(t, f.quotaEvent(message)), data...)
				}
				signal, err := f.service.LimitFromCapture(context.Background(), f.setCapture(data, "stdout"), f.observation)
				if err != nil || signal == nil || signal.Kind != "session_limit" {
					t.Fatal("documented terminal quota was discarded", subtype, field, err)
				}
			}
		}
	}
}

func TestSuccessSuppressesQuota(t *testing.T) {
	f := runnerSetup(t)
	f.installLimitGuard()
	for _, first := range []map[string]any{f.quotaEvent("Usage limit reached"), {"type": "rate_limit_event", "session_id": f.request.Session.VendorID, "rate_limit_info": map[string]any{"status": "rejected"}}} {
		terminal := map[string]any{"type": "result", "subtype": "success", "is_error": false, "result": "Usage limit reached", "session_id": f.request.Session.VendorID}
		data := append(encodeEvent(t, first), encodeEvent(t, terminal)...)
		signal, err := f.service.LimitFromCapture(context.Background(), f.setCapture(data, "stdout"), f.observation)
		if err != nil || signal != nil {
			t.Fatal("successful terminal result retained quota", err)
		}
	}
}

func TestNonQuotaResultCancelsSignal(t *testing.T) {
	f := runnerSetup(t)
	f.installLimitGuard()
	for _, terminal := range []map[string]any{
		{"type": "result", "is_error": true, "result": "authentication refused"},
		{"type": "result", "is_error": true, "errors": []string{"Usage limit reached", "guard refused"}},
		{"type": "result", "is_error": true, "result": "Usage limit reached", "errors": []string{"guard refused"}},
		{"type": "result", "is_error": true, "result": 7},
		{"type": "result", "is_error": true, "errors": []any{7}},
	} {
		terminal["session_id"] = f.request.Session.VendorID
		data := append(encodeEvent(t, f.quotaEvent("Usage limit reached")), encodeEvent(t, terminal)...)
		signal, err := f.service.LimitFromCapture(context.Background(), f.setCapture(data, "stdout"), f.observation)
		if err != nil || signal != nil {
			t.Fatal("non-quota result promoted preceding quota", err)
		}
	}
}
