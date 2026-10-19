//go:build linux

package admin

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// A native journal keeps a helper request as the stage first accepted it: its cause carries that attempt's live
// claimant. A retry by a new claimant carries its own claimant and differs only there (box 61). The helper reads the
// claimant from the explicit attempt its envelope carries; replayClaim is that attempt for claimant on effect.

func replayClaim(t *testing.T, effect api.Effect, claimant api.ID) context.Context {
	t.Helper()
	if effect.Context == nil || effect.Context.Actor == (api.Actor{Kind: "service", ID: claimant}) {
		t.Fatal("the claimant must differ from the effect's author")
	}
	record := api.EffectRecord{Effect: effect, Generation: 2, State: api.EffectClaimed, ClaimID: "claim-" + claimant, ClaimantID: claimant,
		ClaimExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))}
	return api.WithEffectLease(context.Background(), api.EffectLease{Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt})
}

func claimantActor(claimant api.ID) api.Actor { return api.Actor{Kind: "service", ID: claimant} }

func TestReplayPrepareNewClaimant(t *testing.T) {
	m, _, _, _, store := retainedGateFixture(t)
	records, err := store.Records()
	if err != nil || len(records) != 1 || records[0].Gate == nil {
		t.Fatal("the gate fixture lost its prepared journal", err)
	}
	journal := records[0].Gate
	retained := journal.Request
	author := retained.Cause
	effect := api.Effect{ID: author.EffectID, OperationID: author.CauseOperationID, Context: &author, HelperPrepare: &retained}
	ctx := replayClaim(t, effect, claimantB)
	live := retained
	live.Cause.Actor = liveClaimant
	prepared, err := m.prepare(ctx, live)
	if err != nil || prepared != journal.Prepared {
		t.Fatal("the new claimant's prepare retry did not return its retained gate", err)
	}
	turn := live
	turn.Cause.LogicalTurnID = "turn-other"
	_, err = m.prepare(ctx, turn)
	requireRefusal(t, err, "prepare replay changed its retained input")
	foreign := live
	foreign.Cause.Actor = claimantActor("foreign-c")
	_, err = m.prepare(ctx, foreign)
	requireRefusal(t, err, "prepare replay changed its retained input")
	unrelated := effect
	unrelated.ID = "effect-other"
	_, err = m.prepare(replayClaim(t, unrelated, claimantB), live)
	requireRefusal(t, err, "prepare replay changed its retained input")
}

func TestReplayAbortNewClaimant(t *testing.T) {
	m, _, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	retained := testAbortRequest()
	retained.LeaseID, retained.PreparedID, retained.SpecSHA256 = lease.ID, "", ""
	author := retained.Cause
	effect := api.Effect{ID: author.EffectID, OperationID: author.CauseOperationID, Context: &author, HelperAbort: &retained}
	first := retained
	first.Cause.Actor = claimantActor("claimant-a")
	receipt, err := m.abort(replayClaim(t, effect, "claimant-a"), first)
	if err != nil {
		t.Fatal("the first claimant's abort failed", err)
	}
	ctx := replayClaim(t, effect, claimantB)
	live := retained
	live.Cause.Actor = liveClaimant
	replayed, err := m.abort(ctx, live)
	if err != nil || replayed.ID != receipt.ID {
		t.Fatal("the new claimant's abort retry did not return its retained receipt", err)
	}
	turn := live
	turn.Cause.LogicalTurnID = "turn-other"
	_, err = m.abort(ctx, turn)
	requireRefusal(t, err, "changed nonexecuting abort replay")
	_, err = m.abort(replayClaim(t, effect, "claimant-a"), live)
	requireRefusal(t, err, "changed nonexecuting abort replay")
}

func TestReplayReleaseNewClaimant(t *testing.T) {
	m, _, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	retained := testRelease(lease, testObservation(lease))
	author := retained.Cause
	effect := api.Effect{ID: author.EffectID, OperationID: author.CauseOperationID, Context: &author, HelperRelease: &retained}
	first := retained
	first.Cause.Actor = claimantActor("claimant-a")
	receipt, err := m.release(replayClaim(t, effect, "claimant-a"), first)
	if err != nil {
		t.Fatal("the first claimant's release failed", err)
	}
	ctx := replayClaim(t, effect, claimantB)
	live := retained
	live.Cause.Actor = liveClaimant
	replayed, err := m.release(ctx, live)
	if err != nil || replayed.ID != receipt.ID {
		t.Fatal("the new claimant's release retry did not return its retained receipt", err)
	}
	turn := live
	turn.Cause.LogicalTurnID = "turn-other"
	_, err = m.release(ctx, turn)
	requireRefusal(t, err, "helper release was retried with changed cause or observation")
	_, err = m.release(replayClaim(t, effect, "claimant-a"), live)
	requireRefusal(t, err, "helper release was retried with changed cause or observation")
}

// The failed-plan cleanup read compares the journal, which carries the claimant that ran the stage, with the effect's
// retained request, which keeps its author.
func TestReplayCleanupAbortRead(t *testing.T) {
	m, _, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	retained := testAbortRequest()
	retained.LeaseID, retained.PreparedID, retained.SpecSHA256 = lease.ID, "", ""
	author := retained.Cause
	effect := api.Effect{ID: author.EffectID, OperationID: author.CauseOperationID, Context: &author, HelperAbort: &retained}
	ctx := replayClaim(t, effect, claimantB)
	live := retained
	live.Cause.Actor = liveClaimant
	receipt, err := m.abort(ctx, live)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.readPlanCleanupNative(ctx, effect)
	if err != nil || result.Abort == nil || result.Abort.ID != receipt.ID || result.EffectID != effect.ID {
		t.Fatal("the cleanup read refused the abort its live claimant ran", err)
	}
	changed, cause := retained, author
	cause.LogicalTurnID = "turn-other"
	changed.Cause = cause
	other := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, HelperAbort: &changed}
	_, err = m.readPlanCleanupNative(replayClaim(t, other, claimantB), other)
	requireRefusal(t, err, "native abort has no matching terminal helper journal")
	_, err = m.readPlanCleanupNative(context.Background(), effect)
	requireRefusal(t, err, "native abort has no matching terminal helper journal")
}

func TestReplayCleanupReleaseRead(t *testing.T) {
	m, _, _ := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	retained := testRelease(lease, testObservation(lease))
	author := retained.Cause
	effect := api.Effect{ID: author.EffectID, OperationID: author.CauseOperationID, Context: &author, HelperRelease: &retained}
	ctx := replayClaim(t, effect, claimantB)
	live := retained
	live.Cause.Actor = liveClaimant
	receipt, err := m.release(ctx, live)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.readPlanCleanupNative(ctx, effect)
	if err != nil || result.Release == nil || result.Release.ID != receipt.ID || result.EffectID != effect.ID {
		t.Fatal("the cleanup read refused the release its live claimant ran", err)
	}
	changed, cause := retained, author
	cause.LogicalTurnID = "turn-other"
	changed.Cause = cause
	other := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, HelperRelease: &changed}
	_, err = m.readPlanCleanupNative(replayClaim(t, other, claimantB), other)
	requireRefusal(t, err, "native release has no matching terminal helper journal")
	_, err = m.readPlanCleanupNative(context.Background(), effect)
	requireRefusal(t, err, "native release has no matching terminal helper journal")
}
