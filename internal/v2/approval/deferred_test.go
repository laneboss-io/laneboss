package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestDeferredCommit(t *testing.T) {
	for name, edit := range map[string]func(*api.Commit){
		"missing": func(c *api.Commit) { c.Deferred = nil },
		"key":     func(c *api.Commit) { c.Deferred.Key.IdempotencyKey = "other-key" },
		"digest":  func(c *api.Commit) { c.Deferred.Key.RequestSHA256 = testDigest([]byte("other intent")) },
		"operation": func(c *api.Commit) {
			c.Deferred.OperationID = "other-operation"
		},
		"effect": func(c *api.Commit) { c.Deferred.EffectID = "other-effect" },
		"reply": func(c *api.Commit) {
			c.Reply = &api.RPCReply{Result: json.RawMessage(`{}`)}
			c.Operation.Status = "succeeded"
		},
		"status": func(c *api.Commit) { c.Operation.Status = "succeeded" },
	} {
		t.Run(name, func(t *testing.T) {
			f := readyFixture(t)
			request := api.ChangeApplyRequest{ChangeID: f.store.change.ID, ApprovalID: f.store.approval.ID, ExpectedGeneration: 7}
			scope := f.bound("org.change.apply", request, false)
			f.store.transact = func(tx api.Transaction) (api.Commit, error) {
				if tx.Deferred == nil {
					t.Fatal("apply did not submit its deferred reply binding")
				}
				binding := *tx.Deferred
				commit := api.Commit{Operation: api.Operation{ID: binding.OperationID, Status: "pending"}, Deferred: &binding}
				edit(&commit)
				return commit, nil
			}
			f.store.await = func(api.Scope, api.RequestKey) (api.MutationReceipt, error) {
				t.Fatal("invalid deferred commit reached publication wait")
				return api.MutationReceipt{}, nil
			}
			got, err := f.service.OrgChangeApply(context.Background(), scope, request)
			codeIs(t, err, api.CodeIntegrity)
			if got.ID != "" || f.store.mutations != 1 {
				t.Fatal("invalid deferred commit exposed a receipt or changed transaction count")
			}
		})
	}
}

func TestDeferredRetry(t *testing.T) {
	for _, name := range []string{"pending", "running", "unavailable", "deadline", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			request := api.ChangeApplyRequest{ChangeID: f.store.change.ID, ApprovalID: "approval-one", ExpectedGeneration: 7}
			scope := f.bound("org.change.apply", request, false)
			retained := f.store.receipts[fixtureDomain(scope, requestKey(scope))]
			retained.Deferred = &api.DeferredReply{Key: retained.Key, OperationID: retained.Operation.ID, EffectID: "original-effect"}
			if name == "running" {
				retained.Operation.Status = "running"
			}
			f.store.receipts[fixtureDomain(scope, retained.Key)] = retained
			f.service.deps.Clock = fixtureClock{now: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}
			wanted := api.ChangeReceipt{ID: "original-publication", ChangeID: request.ChangeID, ApprovalID: request.ApprovalID,
				OldGeneration: 7, NewGeneration: 8, ManifestSHA256: f.store.change.ManifestSHA256, AppliedAt: "2026-10-15T09:01:00Z"}
			awaited := 0
			f.store.await = func(current api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
				awaited++
				if key != retained.Key || current.Actor != retained.Actor || current.Config != retained.Config {
					t.Fatal("retry awaited another reservation")
				}
				codes := map[string]api.ErrorCode{"unavailable": api.CodeUnavailable, "deadline": api.CodeDeadline, "cancelled": api.CodeCancelled}
				if code, exists := codes[name]; exists {
					return api.MutationReceipt{}, &api.Error{Code: code, Message: "fixture wait ended"}
				}
				raw, err := json.Marshal(wanted)
				if err != nil {
					t.Fatal(err)
				}
				completed := retained
				completed.Operation.Status, completed.Reply = "succeeded", &api.RPCReply{Result: raw}
				return completed, nil
			}
			got, err := f.service.OrgChangeApply(context.Background(), scope, request)
			switch name {
			case "unavailable", "deadline", "cancelled":
				codes := map[string]api.ErrorCode{"unavailable": api.CodeUnavailable, "deadline": api.CodeDeadline, "cancelled": api.CodeCancelled}
				codeIs(t, err, codes[name])
				if err.(*api.Error).OperationID != retained.Operation.ID || got.ID != "" {
					t.Fatal("retry wait lost its original operation or exposed a receipt")
				}
			default:
				if err != nil || got != wanted {
					t.Fatalf("pending retry did not return the original durable reply: %v", err)
				}
			}
			if awaited != 1 || f.store.changes != 0 || f.store.reads != 0 {
				t.Fatal("pending retry repeated apply preflight or omitted await")
			}
			f.noEffects()
		})
	}
}

func TestDeferredReceipt(t *testing.T) {
	for _, phase := range []string{"lookup", "await"} {
		for name, edit := range map[string]func(*api.DeferredReply){
			"key":       func(d *api.DeferredReply) { d.Key.IdempotencyKey = "other-key" },
			"operation": func(d *api.DeferredReply) { d.OperationID = "other-operation" },
			"effect": func(d *api.DeferredReply) {
				d.EffectID = ""
				if phase == "await" {
					d.EffectID = "other-effect"
				}
			},
		} {
			t.Run(phase+"/"+name, func(t *testing.T) {
				f := newFixture(t)
				request := api.ChangeApplyRequest{ChangeID: f.store.change.ID, ApprovalID: "approval-one", ExpectedGeneration: 7}
				scope := f.bound("org.change.apply", request, false)
				receipt := f.store.receipts[fixtureDomain(scope, requestKey(scope))]
				binding := api.DeferredReply{Key: receipt.Key, OperationID: receipt.Operation.ID, EffectID: "original-effect"}
				foreign := binding
				edit(&foreign)
				receipt.Deferred = &foreign
				var err error
				if phase == "lookup" {
					f.store.lookup = func(api.Scope, api.RequestKey) (api.MutationReceipt, error) { return receipt, nil }
					_, err = f.service.OrgChangeApply(context.Background(), scope, request)
				} else {
					raw, marshalErr := json.Marshal(api.ChangeReceipt{ID: "receipt-one"})
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					receipt.Operation.Status, receipt.Reply = "succeeded", &api.RPCReply{Result: raw}
					f.store.await = func(api.Scope, api.RequestKey) (api.MutationReceipt, error) { return receipt, nil }
					_, err = f.service.publicationReply(context.Background(), scope, receipt.Operation.ID, &binding)
				}
				codeIs(t, err, api.CodeIntegrity)
				if f.store.changes != 0 || f.store.reads != 0 {
					t.Fatal("foreign deferred receipt reached apply preflight")
				}
				f.noEffects()
			})
		}
	}
}

func TestFrameParams(t *testing.T) {
	f := readyFixture(t)
	request := api.ChangeApplyRequest{ChangeID: f.store.change.ID, ApprovalID: f.store.approval.ID, ExpectedGeneration: 7}
	scope := f.bound("org.change.apply", request, false)
	original := scope.Request
	// Build the reordered input from the actual fixture fields, so the test
	// keeps working if the IDs or generation change.
	params := []byte("{\n  \"expected_generation\": " + string(mustJSON(t, request.ExpectedGeneration)) +
		", \"approval_id\": " + string(mustJSON(t, request.ApprovalID)) + ", \"change_id\": " + string(mustJSON(t, request.ChangeID)) + "\n}")
	original.Params = params
	raw := mustJSON(t, original)
	scope.Frame = fixtureFrame(raw)
	tx, err := transaction(scope)
	if err != nil || !bytes.Equal(tx.RawRequest, raw) || !reflect.DeepEqual(tx.Scope.Request, scope.Request) {
		t.Fatalf("equivalent params lost the original frame or were refused: %v", err)
	}
	changed := scope
	changed.Request.RequestID = "another-request"
	_, err = transaction(changed)
	codeIs(t, err, api.CodeIntegrity)
	other := request
	other.ExpectedGeneration++
	original.Params = mustJSON(t, other)
	changed = scope
	changed.Frame = fixtureFrame(mustJSON(t, original))
	_, err = transaction(changed)
	codeIs(t, err, api.CodeIntegrity)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
