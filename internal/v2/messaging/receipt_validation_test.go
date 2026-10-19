package messaging

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReceiptAmbiguousEnd(t *testing.T) {
	f, scope, receipt := receiptFixture(t)
	if err := f.service.ValidateReceipt(context.Background(), scope, receipt); err != nil {
		t.Fatal(err)
	}
	duplicate := f.store.events[len(f.store.events)-1]
	duplicate.ID, duplicate.Seq = randomID(t), duplicate.Seq+1
	f.store.events = append(f.store.events, duplicate)
	wantCode(t, f.service.ValidateReceipt(context.Background(), scope, receipt), api.CodeIntegrity)
}

func TestReceiptHistoryOrder(t *testing.T) {
	for _, cell := range []string{"duplicate-id", "sequence"} {
		t.Run(cell, func(t *testing.T) {
			f, scope, receipt := receiptFixture(t)
			if err := f.service.ValidateReceipt(context.Background(), scope, receipt); err != nil {
				t.Fatal(err)
			}
			turn := f.store.events[len(f.store.events)-2]
			end := &f.store.events[len(f.store.events)-1]
			if cell == "duplicate-id" {
				end.ID = turn.ID
			} else {
				end.Seq = turn.Seq
			}
			wantCode(t, f.service.ValidateReceipt(context.Background(), scope, receipt), api.CodeIntegrity)
		})
	}
}

func TestReceiptCausalReferences(t *testing.T) {
	for _, cell := range []string{"mail", "sequence"} {
		t.Run(cell, func(t *testing.T) {
			f, scope, receipt := receiptFixture(t)
			if err := f.service.ValidateReceipt(context.Background(), scope, receipt); err != nil {
				t.Fatal(err)
			}
			turnEvent := &f.store.events[len(f.store.events)-2]
			var turn api.TurnEvent
			if err := json.Unmarshal(turnEvent.Payload, &turn); err != nil {
				t.Fatal(err)
			}
			if cell == "mail" {
				turn.Trigger.MailIDs = []api.ID{randomID(t)}
			} else {
				turn.Trigger.CausingSeqs = []api.Sequence{f.store.mail[receipt.MailID].QueuedSeq + 1}
			}
			turnEvent.Payload = resultJSON(t, turn)
			wantCode(t, f.service.ValidateReceipt(context.Background(), scope, receipt), api.CodeIntegrity)
		})
	}
}

func TestReceiptEndShape(t *testing.T) {
	for _, cell := range []string{"unknown-field", "duplicate", "missing", "null"} {
		t.Run(cell, func(t *testing.T) {
			f, scope, receipt := receiptFixture(t)
			if err := f.service.ValidateReceipt(context.Background(), scope, receipt); err != nil {
				t.Fatal(err)
			}
			last := &f.store.events[len(f.store.events)-1]
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(last.Payload, &raw); err != nil {
				t.Fatal(err)
			}
			switch cell {
			case "unknown-field":
				raw["ignored"] = json.RawMessage(`true`)
			case "duplicate":
				last.Payload = append(append([]byte{}, last.Payload[:len(last.Payload)-1]...), []byte(`,"reason":"exit"}`)...)
			case "missing":
				delete(raw, "profile_continuation")
			case "null":
				raw["profile_continuation"] = json.RawMessage(`null`)
			}
			if cell != "duplicate" {
				last.Payload = resultJSON(t, raw)
			}
			wantCode(t, f.service.ValidateReceipt(context.Background(), scope, receipt), api.CodeIntegrity)
		})
	}
}

func TestReceiptExitEvidence(t *testing.T) {
	for _, cell := range []string{"missing-exit", "two-exits", "unknown-reason", "bad-prompt", "non-utc"} {
		t.Run(cell, func(t *testing.T) {
			f, scope, receipt := receiptFixture(t)
			if err := f.service.ValidateReceipt(context.Background(), scope, receipt); err != nil {
				t.Fatal(err)
			}
			last := &f.store.events[len(f.store.events)-1]
			var end api.RunEndEvent
			if err := json.Unmarshal(last.Payload, &end); err != nil {
				t.Fatal(err)
			}
			receipt.Status = "returned"
			nonzero := 7
			end.Observation.ExitCode = &nonzero
			switch cell {
			case "missing-exit":
				end.Observation.ExitCode = nil
			case "two-exits":
				termination := 9
				end.Observation.Signal = &termination
			case "unknown-reason":
				end.Reason, receipt.Cause = "unrecognized", "unrecognized"
			case "bad-prompt":
				end.Observation.PromptStatus, receipt.PromptStatus = "successful", "successful"
			case "non-utc":
				end.Observation.ObservedAt = "2026-10-01T12:00:00+00:00"
				receipt.ObservedAt = end.Observation.ObservedAt
			}
			last.Payload = resultJSON(t, end)
			err := f.service.ValidateReceipt(context.Background(), scope, receipt)
			if cell == "unknown-reason" || cell == "bad-prompt" || cell == "non-utc" {
				wantCode(t, err, api.CodeInvalid)
			} else {
				wantCode(t, err, api.CodeIntegrity)
			}
		})
	}
}
