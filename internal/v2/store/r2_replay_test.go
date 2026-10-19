//go:build linux

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type r2Clock struct{ at time.Time }

func (c *r2Clock) Now() time.Time { return c.at }

// A protected journal read authenticates the current job and returns the actual
// historical removing claim unchanged. It does not relabel claim A as claim B.
type replayNative struct{ *collectNative }

func (n replayNative) ReadWorkspaceRemoval(ctx context.Context, job api.CleanupJob) (api.WorkspaceRemoval, error) {
	if err := ctx.Err(); err != nil {
		return api.WorkspaceRemoval{}, err
	}
	if job.Intent.Workspace != n.workspace || job.Intent.ID != n.journal.IntentID || api.ValidateCleanupJob(job, time.Now()) != nil {
		return api.WorkspaceRemoval{}, errors.New("current replay job does not own this protected journal")
	}
	return n.journal, nil
}

func TestCollectReclaimAfterRemoval(t *testing.T) {
	f := newCollect(t)
	s := f.arch.s
	ctx := context.Background()
	// Source authority remains live independently of the short execution claim.
	var grants api.GrantSet
	if err := storedProjection(ctx, s.db, "grants", f.arch.record.Lane.GrantSetID, &grants); err != nil {
		t.Fatal(err)
	}
	grants.ExpiresAt = api.Timestamp(time.Now().Add(10 * time.Minute).UTC().Format(timeFormat))
	fixtureProjection(t, s, "grants", grants.ID, grants.Generation, grants)
	objects, err := s.CollectCleanupObjects(ctx, f.arch.executor, f.job, f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	f.native.remove(t, f.job)
	removal := f.native.journal
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	expiry, err := time.Parse(time.RFC3339Nano, string(f.job.Claim.ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	clock := &r2Clock{at: expiry.Add(time.Second)}
	deps := f.arch.deps
	deps.Clock = clock
	deps.CleanupNative = replayNative{f.native}
	reopened, err := New(deps)
	if err != nil {
		t.Fatal("cleanup removal crash did not reopen", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	scope := f.arch.executor
	scope.Actor.ID = testID(t)
	current, err := reopened.Effect(ctx, scope, f.job.Intent.Cause.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := reopened.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: current.Effect.ID, ExpectedGeneration: current.Generation, ClaimantID: scope.Actor.ID, Deadline: api.Timestamp(clock.Now().Add(time.Minute).UTC().Format(timeFormat))})
	if err != nil {
		t.Fatal(err)
	}
	job, err := reopened.BeginCleanup(ctx, scope, claim)
	if err != nil {
		t.Fatal("reclaimed cleanup lost its stable intent", err)
	}
	replayed, err := reopened.CollectCleanupObjects(ctx, scope, job, f.inventory)
	if err != nil || !sameValue(replayed, objects) {
		t.Fatal("claim B could not replay claim A object and removal journals", err)
	}
	if f.native.journal.ClaimID != removal.ClaimID || f.native.journal.ClaimID == claim.ClaimID {
		t.Fatal("replay relabeled the actual removing claim")
	}
	receipt, err := reopened.RetainCleanupReceipt(ctx, scope, job, api.CleanupReceipt{ID: testID(t), IntentID: job.Intent.ID, ClaimID: claim.ClaimID, InventoryID: f.inventory.ID, Objects: replayed, Workspace: removal})
	if err != nil {
		t.Fatal("reclaimed cleanup could not retain the original removal claim", err)
	}
	verified, err := api.VerifyCleanup(ctx, reopened.CleanupReadbacks(scope), job, f.inventory, receipt, clock)
	if err != nil {
		t.Fatal("reclaimed removal failed fresh namespace verification", err)
	}
	if _, err := reopened.CompleteCleanup(ctx, scope, job, verified); err != nil {
		t.Fatal("claim B could not complete collection after claim A removal", err)
	}
	var lane api.Lane
	if err := storedProjection(ctx, reopened.db, "lane", job.Intent.Cause.Target.LifeID, &lane); err != nil || !lane.Cleaned {
		t.Fatal("reclaimed collection did not reach lane.cleaned", err)
	}
}

func TestCollectRefusesUnknownRemover(t *testing.T) {
	f := newCollect(t)
	if _, err := f.arch.s.CollectCleanupObjects(context.Background(), f.arch.executor, f.job, f.inventory); err != nil {
		t.Fatal(err)
	}
	f.native.remove(t, f.job)
	f.native.journal.ClaimID = testID(t)
	f.arch.s.deps.CleanupNative = replayNative{f.native}
	if _, err := f.arch.s.CollectCleanupObjects(context.Background(), f.arch.executor, f.job, f.inventory); err == nil {
		t.Fatal("journal from a claim that never removed this workspace was accepted")
	} else {
		expectCode(t, err, api.CodeIntegrity)
	}
}
