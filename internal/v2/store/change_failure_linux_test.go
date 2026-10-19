//go:build linux

package store

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestChangeDefiniteFailure(t *testing.T) {
	s, _, tx := deferredChangeFixture(t)
	ctx := context.Background()
	if _, err := s.Transact(ctx, tx); err != nil {
		t.Fatal(err)
	}
	scope, lease, _ := publicationClaim(t, s, tx)
	failure := &api.Error{Code: api.CodeBudget, Owner: "lb-v2-approval", Message: "component publication budget exhausted before pointer publication", OperationID: tx.Deferred.OperationID}
	outcome := api.EffectOutcome{EffectID: lease.Record.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "failed", Error: failure,
		Reply: &api.DeferredCompletion{Deferred: *tx.Deferred, Reply: api.RPCReply{Error: failure}}}
	commit, err := s.CompleteEffect(ctx, scope, outcome)
	if err != nil || commit.Operation.Status != "failed" || commit.Reply == nil || !reflect.DeepEqual(commit.Reply.Error, failure) {
		t.Fatal("measured unpublished failure did not seal its original reply", err)
	}
	receipt, err := s.LookupReceipt(ctx, tx.Scope, tx.Deferred.Key)
	if err != nil || receipt.Reply == nil || !reflect.DeepEqual(receipt.Reply.Error, failure) || receipt.Operation.Status != "failed" {
		t.Fatal("failed original reply was not replayable", err)
	}
	if check, err := s.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !check.OK {
		if joined := s.verifyOrgApplies(ctx); joined != nil {
			t.Log("publication integrity detail:", joined)
		}
		t.Fatal("failed publication lost store integrity", err)
	}
}

func TestChangePublishedFailureStaysPending(t *testing.T) {
	s, _, tx := deferredChangeFixture(t)
	ctx := context.Background()
	if _, err := s.Transact(ctx, tx); err != nil {
		t.Fatal(err)
	}
	scope, lease, request := publicationClaim(t, s, tx)
	if _, err := s.PublishChange(ctx, scope, request); err != nil {
		t.Fatal(err)
	}
	failure := &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-approval", Message: "component disconnected after pointer publication", OperationID: tx.Deferred.OperationID}
	outcome := api.EffectOutcome{EffectID: lease.Record.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "failed", Error: failure,
		Reply: &api.DeferredCompletion{Deferred: *tx.Deferred, Reply: api.RPCReply{Error: failure}}}
	if _, err := s.CompleteEffect(ctx, scope, outcome); err == nil {
		t.Fatal("uncertain publication was recorded as definitely failed")
	}
	if receipt, err := s.LookupReceipt(ctx, tx.Scope, tx.Deferred.Key); err != nil || receipt.Reply != nil {
		t.Fatal("uncertain publication overwrote its original pending receipt", err)
	}
}
