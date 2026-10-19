//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestOwnedKeepsCleanupReplay(t *testing.T) {
	f := newCollect(t)
	s, ctx := f.arch.s, context.Background()
	if _, err := s.CollectCleanupObjects(ctx, f.arch.executor, f.job, f.inventory); err != nil {
		t.Fatal(err)
	}
	f.native.remove(t, f.job)
	before, err := s.Effect(ctx, f.arch.executor, f.job.Intent.Cause.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	failure := &api.Error{Code: api.CodeInvalid, Message: "collector refused a historical journal after removal", Instead: "Replay the original protected journals."}
	if _, err := callOwnedFailure(s, ctx, f.arch.executor, f.job.Claim, failure, nil); err == nil {
		t.Fatal("cleanup failure stranded protected removal journals in a terminal effect")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
	after, err := s.Effect(ctx, f.arch.executor, before.Effect.ID)
	if err != nil || !sameValue(before, after) || after.Outcome != nil {
		t.Fatal("post-removal refusal changed its original replay claim", err)
	}
	var saved collectionRecord
	if err := storedProjection(ctx, s.db, "collection", before.Effect.ID, &saved); err != nil || saved.RemovalClaim == nil || saved.RemovalClaim.ClaimID != f.job.Claim.ClaimID || saved.Commit != nil {
		t.Fatal("post-removal refusal lost its protected original remover", err)
	}
	results, err := s.CollectCleanupObjects(ctx, f.arch.executor, f.job, f.inventory)
	if err != nil {
		t.Fatal("pending cleanup could not replay its original journals", err)
	}
	receipt, err := s.RetainCleanupReceipt(ctx, f.arch.executor, f.job, api.CleanupReceipt{ID: testID(t), IntentID: f.job.Intent.ID, ClaimID: f.job.Claim.ClaimID, InventoryID: f.inventory.ID, Objects: results, Workspace: f.native.journal})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := api.VerifyCleanup(ctx, s.CleanupReadbacks(f.arch.executor), f.job, f.inventory, receipt, s.deps.Clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteCleanup(ctx, f.arch.executor, f.job, verified); err != nil {
		t.Fatal("original cleanup could not complete after a refused terminal failure", err)
	}
}
