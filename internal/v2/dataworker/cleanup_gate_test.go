package dataworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type cleanupCalls struct {
	inventory, writer, admin, retain, lookup, verify int
}

func (p *cleanupPorts) calls() cleanupCalls {
	return cleanupCalls{p.inventories, p.collections, p.removals, p.retentions, p.receiptReads, p.inventoryReads}
}

func assertCleanupRefusal(t *testing.T, p *cleanupPorts, receipt api.CleanupReceipt, err error, code api.ErrorCode, owner, message, assertion string, calls cleanupCalls) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code || typed.Owner != owner || typed.Message != message || receipt.ID != "" || p.calls() != calls {
		t.Fatal(assertion, "error:", err, "calls:", p.calls(), "expected:", calls)
	}
	for _, id := range []api.ID{"archive", "shared", "foreign", "audit"} {
		if string(p.objects[id]) != string(id) {
			t.Fatal("cleanup gate changed protected bytes", id)
		}
	}
}

func TestCleanupObjectGate(t *testing.T) {
	for _, mode := range []string{"before-absent", "after-present", "eligible-retained", "retained-absent"} {
		t.Run(mode, func(t *testing.T) {
			s, p := cleanupFixture(t, mode)
			receipt, err := s.CollectCleanup(context.Background(), p.job)
			assertCleanupRefusal(t, p, receipt, err, api.CodeInvalid, "lb-v2-integrate",
				"cleanup object results lack exact ordered removal or retention readbacks",
				"cleanup object result crossed admin boundary", cleanupCalls{inventory: 1, writer: 1})
			if p.inspections != 1 || p.removed {
				t.Fatal("cleanup object result crossed admin boundary", mode)
			}
		})
	}
}

func TestCleanupReplayGate(t *testing.T) {
	for _, mode := range []string{"echo-replay", "unordered-replay"} {
		t.Run(mode, func(t *testing.T) {
			s, p := cleanupFixture(t, "replay-seed")
			// A real successful fixture pass establishes distinct ordered before
			// and after times. The refused observation still passes the shared
			// removal validator; only freshness against that journal rejects it.
			p.clock.now = p.clock.now.Add(-time.Second / 2)
			if receipt, err := s.CollectCleanup(context.Background(), p.job); err != nil || receipt.ID == "" {
				t.Fatal("cleanup replay seed did not collect", err)
			}
			p.mode = mode
			p.inventories, p.collections, p.removals, p.retentions, p.receiptReads, p.inventoryReads, p.inspections = 0, 0, 0, 0, 0, 0, 0
			receipt, err := s.CollectCleanup(context.Background(), p.job)
			assertCleanupRefusal(t, p, receipt, err, api.CodeIntegrity, "lb-v2-admin",
				"cleanup workspace replay echoed its removal observation",
				"cleanup replay observation escaped its gate", cleanupCalls{inventory: 1})
			if p.inspections != 1 {
				t.Fatal("cleanup replay observation escaped its gate", mode)
			}
		})
	}
}

func TestCleanupRefusalGates(t *testing.T) {
	for _, check := range []struct {
		mode, owner, message, assertion string
		code                            api.ErrorCode
		calls                           cleanupCalls
	}{
		{"retain-dirty", "lb-v2-admin", "cleanup retained dirty work (retain_dirty)", "dirty retention escaped completion gate", api.CodePrerequisite, cleanupCalls{inventory: 1, writer: 1, admin: 1}},
		{"retain-swap", "lb-v2-service", "retained cleanup receipt substituted the measured operations", "retained receipt substitution escaped its gate", api.CodeIntegrity, cleanupCalls{inventory: 1, writer: 1, admin: 1, retain: 1}},
		{"read-swap", "lb-v2-service", "cleanup receipt failed exact retained readback", "receipt readback substitution escaped its gate", api.CodeIntegrity, cleanupCalls{inventory: 1, writer: 1, admin: 1, retain: 1, lookup: 1}},
		{"omit-object", "lb-v2-service", "cleanup omitted an object disposition", "object omission escaped its gate", api.CodeIntegrity, cleanupCalls{inventory: 1, writer: 1}},
		{"reorder-object", "lb-v2-service", "cleanup substituted an inventory object", "object order escaped its gate", api.CodeIntegrity, cleanupCalls{inventory: 1, writer: 1}},
	} {
		t.Run(check.mode, func(t *testing.T) {
			s, p := cleanupFixture(t, check.mode)
			receipt, err := s.CollectCleanup(context.Background(), p.job)
			assertCleanupRefusal(t, p, receipt, err, check.code, check.owner, check.message, check.assertion, check.calls)
			if check.mode == "retain-dirty" && p.removed {
				t.Fatal("dirty retention escaped completion gate")
			}
		})
	}
}
