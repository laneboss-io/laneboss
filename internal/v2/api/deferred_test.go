package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDeferredRequestEncoding(t *testing.T) {
	tx := deferredTransaction(t)
	var indented bytes.Buffer
	if err := json.Indent(&indented, tx.RawRequest, "", "  "); err != nil {
		t.Fatal(err)
	}
	tx.RawRequest = append([]byte(nil), indented.Bytes()...)
	retained := append([]byte(nil), tx.RawRequest...)
	canonical, err := CanonicalJSON(tx.Scope.Request.Params)
	if err != nil {
		t.Fatal(err)
	}
	tx.Scope.Request.Params = canonical
	t.Run("equivalent", func(t *testing.T) {
		if err := ValidateTransactionShape(tx); err != nil {
			t.Fatalf("equivalent deferred request was refused: %v", err)
		}
		if !bytes.Equal(tx.RawRequest, retained) {
			t.Fatal("deferred validation replaced the original frame")
		}
	})
	t.Run("changed", func(t *testing.T) {
		request := tx.Scope.Request
		request.Params = json.RawMessage(`{"change_id":"different","approval_id":"approval","expected_generation":4}`)
		if deferredRequest(tx.Scope.Config, request, tx.RawRequest, tx.Deferred.Key) {
			t.Fatal("changed deferred params matched the original frame")
		}
	})
	for name, change := range map[string]func(*Request){
		"request_id": func(r *Request) { r.RequestID = "retry-frame" },
		"proof":      func(r *Request) { r.Proof = &ProofRef{ID: "borrowed-proof"} },
		"digest":     func(r *Request) { r.RequestSHA256 = Digest(strings.Repeat("2", 64)) },
	} {
		t.Run(name, func(t *testing.T) {
			request := tx.Scope.Request
			change(&request)
			if deferredRequest(tx.Scope.Config, request, tx.RawRequest, tx.Deferred.Key) {
				t.Fatal("foreign deferred envelope matched the original frame")
			}
		})
	}
}

func deferredTransaction(t *testing.T) Transaction {
	t.Helper()
	apply := ChangeApplyRequest{ChangeID: "change", ApprovalID: "approval", ExpectedGeneration: 4}
	params, err := json.Marshal(apply)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Protocol: Protocol, Schema: SchemaVersion, Config: "demo", Method: "org.change.apply",
		RequestID: "original-frame", IdempotencyKey: ID(strings.Repeat("k", 32)), Params: params}
	request.RequestSHA256, err = RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{Kind: "lane", ID: "coordinator", LifeID: "l6", Level: 6}
	cause := InternalIntent{ID: "publish-intent", Kind: InternalOrgPublish, Config: "demo",
		Actor: Actor{Kind: "service", ID: "publisher"}, RequestedBy: actor,
		CauseOperationID: "operation", CauseRequestID: request.RequestID, EffectID: "publish-effect"}
	return Transaction{Scope: Scope{Config: "demo", Actor: actor, Request: request}, RawRequest: raw,
		Deferred: &DeferredReply{Key: RequestKey{Method: request.Method, IdempotencyKey: request.IdempotencyKey, RequestSHA256: request.RequestSHA256},
			OperationID: "operation", EffectID: cause.EffectID},
		Compare: []Compare{{Kind: CompareOrg, ID: "org", Generation: 4}},
		Guards: []TransactionGuard{{Approval: &ApprovalUse{ApprovalID: apply.ApprovalID, ChangeID: apply.ChangeID,
			ManifestSHA256: Digest(strings.Repeat("1", 64)), BaseGeneration: 4}}},
		Effects: []Effect{{ID: cause.EffectID, OperationID: "operation", Context: &cause, ApplyChange: &apply}}}
}

func TestDeferredMutation(t *testing.T) {
	if err := ValidateTransactionShape(deferredTransaction(t)); err != nil {
		t.Fatalf("guarded synchronous apply could not defer its reply: %v", err)
	}
	for name, mutate := range map[string]func(*Transaction){
		"missing_effect": func(tx *Transaction) { tx.Effects = nil },
		"second_reply":   func(tx *Transaction) { tx.Reply = &RPCReply{Error: &Error{Code: CodeUnavailable}} },
		"missing_guard":  func(tx *Transaction) { tx.Guards = nil },
		"missing_cas":    func(tx *Transaction) { tx.Compare = nil },
		"foreign_effect": func(tx *Transaction) { tx.Deferred.EffectID = "other-effect" },
		"foreign_key":    func(tx *Transaction) { tx.Deferred.Key.IdempotencyKey = "another-key" },
		"foreign_frame":  func(tx *Transaction) { tx.RawRequest = []byte(`{}`) },
		"foreign_guard":  func(tx *Transaction) { tx.Guards[0].Approval.ChangeID = "another-change" },
		"foreign_cause":  func(tx *Transaction) { tx.Effects[0].Context.CauseRequestID = "retry-frame" },
		"wrong_method":   func(tx *Transaction) { tx.Scope.Request.Method = "records.append" },
		"fabricated_receipt": func(tx *Transaction) {
			tx.Deferred = nil
			tx.Reply = &RPCReply{Result: json.RawMessage(`{"id":"future","change_id":"change","approval_id":"approval","old_generation":4,"new_generation":5,"manifest_sha256":"` + strings.Repeat("1", 64) + `","applied_at":"2026-01-01T00:00:00Z"}`)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			tx := deferredTransaction(t)
			mutate(&tx)
			var typed *Error
			if err := ValidateTransactionShape(tx); !errors.As(err, &typed) || typed.Code != CodeInvalid {
				t.Fatalf("unguarded or competing deferred reply was accepted: %v", err)
			}
		})
	}
}

func deferredOutcome(t *testing.T) (MutationReceipt, EffectLease, EffectOutcome) {
	t.Helper()
	tx := deferredTransaction(t)
	receipt := MutationReceipt{Config: tx.Scope.Config, Actor: tx.Scope.Actor, Key: tx.Deferred.Key,
		Operation: Operation{ID: tx.Deferred.OperationID, Status: "running"}, Deferred: tx.Deferred, RawRequest: tx.RawRequest}
	lease := EffectLease{ClaimID: "publish-claim", ExpiresAt: "2026-01-01T00:01:00Z",
		Record: EffectRecord{Effect: tx.Effects[0], Generation: 2, State: EffectClaimed, ClaimID: "publish-claim",
			ClaimantID: "publisher", ClaimExpiresAt: "2026-01-01T00:01:00Z"}}
	publication := ChangeReceipt{ID: "published", ChangeID: "change", ApprovalID: "approval", OldGeneration: 4, NewGeneration: 5,
		ManifestSHA256: tx.Guards[0].Approval.ManifestSHA256, AppliedAt: "2026-01-01T00:00:00Z"}
	raw, err := json.Marshal(publication)
	if err != nil {
		t.Fatal(err)
	}
	outcome := EffectOutcome{EffectID: lease.Record.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: 2,
		Status: "succeeded", Publication: &publication, Reply: &DeferredCompletion{Deferred: *tx.Deferred, Reply: RPCReply{Result: raw}}}
	return receipt, lease, outcome
}

func TestDeferredCompletion(t *testing.T) {
	receipt, lease, outcome := deferredOutcome(t)
	if err := ValidateDeferredCompletion(receipt, lease, outcome); err != nil {
		t.Fatalf("measured publication reply was refused: %v", err)
	}
	failure := &Error{Code: CodeUnavailable, Message: "publication failed", OperationID: receipt.Operation.ID, Owner: "lb-v2-approval"}
	outcome.Status, outcome.Publication, outcome.Error, outcome.Reply.Reply = "failed", nil, failure, RPCReply{Error: failure}
	if err := ValidateDeferredCompletion(receipt, lease, outcome); err != nil {
		t.Fatalf("measured publication failure was refused: %v", err)
	}
	for name, mutate := range map[string]func(*MutationReceipt, *EffectLease, *EffectOutcome){
		"second_reply": func(r *MutationReceipt, _ *EffectLease, o *EffectOutcome) { r.Reply = &o.Reply.Reply },
		"completed":    func(r *MutationReceipt, _ *EffectLease, _ *EffectOutcome) { r.Operation.Status = "succeeded" },
		"claim":        func(_ *MutationReceipt, _ *EffectLease, o *EffectOutcome) { o.ClaimID = "expired-claim" },
		"generation":   func(_ *MutationReceipt, _ *EffectLease, o *EffectOutcome) { o.ExpectedGeneration++ },
		"operation": func(_ *MutationReceipt, _ *EffectLease, o *EffectOutcome) {
			o.Reply.Deferred.OperationID = "other-operation"
		},
		"frame":           func(r *MutationReceipt, _ *EffectLease, _ *EffectOutcome) { r.RawRequest = []byte(`{}`) },
		"effect":          func(_ *MutationReceipt, l *EffectLease, _ *EffectOutcome) { l.Record.Effect.ApplyChange = nil },
		"future_reply":    func(_ *MutationReceipt, _ *EffectLease, o *EffectOutcome) { o.Publication = nil },
		"different_reply": func(_ *MutationReceipt, _ *EffectLease, o *EffectOutcome) { o.Publication.NewGeneration++ },
		"launch_plan": func(_ *MutationReceipt, _ *EffectLease, o *EffectOutcome) {
			plan := launchFixture(t)
			o.LaunchPlan = &plan
		},
		"error_with_publication": func(_ *MutationReceipt, _ *EffectLease, o *EffectOutcome) {
			o.Error = &Error{Code: CodeUnavailable}
			o.Reply.Reply = RPCReply{Error: o.Error}
			o.Status = "failed"
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, l, o := deferredOutcome(t)
			mutate(&r, &l, &o)
			var typed *Error
			if err := ValidateDeferredCompletion(r, l, o); !errors.As(err, &typed) || typed.Code != CodeInvalid || typed.Owner != "lb-v2-service" {
				t.Fatalf("second or unrelated final reply was accepted: %v", err)
			}
		})
	}
}
