package admin

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The helper stage (currentStage) lets a live cause carry the current claimant {service, ClaimantID} in place of the
// retained effect's author. Each test retains an effect authored by testCause's service-a, claims it for claimant-b,
// and drives a comparison that follows the stage with that live cause; the negative cases change one other field.

const claimantB = api.ID("claimant-b")

var liveClaimant = api.Actor{Kind: "service", ID: claimantB}

// claimantStore holds one claimed effect: it answers the stage's read for the claimant and takes its preflight fence.
// Every other store method is the nil embedded interface.
type claimantStore struct {
	api.StateStore
	record api.EffectRecord
	fences int
}

func (s *claimantStore) Effect(_ context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	if scope.Actor != (api.Actor{Kind: "service", ID: s.record.ClaimantID}) || id != s.record.Effect.ID {
		return api.EffectRecord{}, failure(api.CodeNotFound, "claimant store has no such effect")
	}
	return s.record, nil
}

func (s *claimantStore) Transact(_ context.Context, tx api.Transaction) (api.Commit, error) {
	if tx.Internal == nil || tx.Scope.Actor != (api.Actor{Kind: "service", ID: s.record.ClaimantID}) || len(tx.Guards) != 1 {
		return api.Commit{}, failure(api.CodeConflict, "claimant store refused the stage fence")
	}
	s.fences++
	return api.Commit{}, nil
}

// drainClaim is the claimant's current lease on effect.
func drainClaim(t *testing.T, effect api.Effect) api.EffectLease {
	t.Helper()
	if effect.Context == nil || effect.Context.Actor == liveClaimant {
		t.Fatal("the claimant must differ from the effect's author")
	}
	record := api.EffectRecord{Effect: effect, Generation: 2, State: api.EffectClaimed, ClaimID: "claim-b", ClaimantID: claimantB,
		ClaimExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))}
	return api.EffectLease{Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt}
}

// claimedEffect is a service whose store holds effect claimed by claimant-b, and that claimant's attempt context.
func claimedEffect(t *testing.T, effect api.Effect) (*Service, context.Context, *claimantStore) {
	t.Helper()
	lease := drainClaim(t, effect)
	store := &claimantStore{record: lease.Record}
	s := &Service{deps: Dependencies{Store: store, Config: "admin-case"}, binding: testBinding()}
	return s, api.WithEffectLease(context.Background(), lease), store
}

func requireRefusal(t *testing.T, err error, message string) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Message != message {
		t.Fatalf("want refusal %q, got %v", message, err)
	}
}

func testAbortRequest() api.HelperAbortRequest {
	cause := testCause(api.InternalHelperAbort, "life-a")
	return api.HelperAbortRequest{Cause: cause, LeaseID: "lease-a", PreparedID: "prepared-a", SpecSHA256: testDigest("spec-a"),
		OperationID: cause.CauseOperationID, EffectID: cause.EffectID}
}

func TestClaimantAllocateWorker(t *testing.T) {
	retained := testAllocation()
	author := retained.Cause
	s, ctx, store := claimedEffect(t, api.Effect{ID: author.EffectID, OperationID: author.CauseOperationID, Context: &author, HelperAllocate: &retained})
	live := retained
	live.Cause.Actor = liveClaimant
	// Past its retained comparison a worker allocation goes to the helper transport, which this test does not have:
	// the allocation must end in that transport's own refusal.
	want := s.call(ctx, "allocate", live, &api.HelperLease{})
	if want == nil {
		t.Fatal("the test requires the helper transport to be absent")
	}
	if _, err := s.Allocate(ctx, live); err == nil || err.Error() != want.Error() || store.fences != 1 {
		t.Fatalf("worker allocation refused the live claimant of its retained effect: %v", err)
	}
	changed := live
	changed.Budget.Processes--
	_, err := s.Allocate(ctx, changed)
	requireRefusal(t, err, "worker allocation differs from its effect")
}

func TestClaimantCaptureRelease(t *testing.T) {
	lease := api.HelperLease{ID: "lease-a", ContainmentID: "containment-a"}
	retained := testRelease(lease, testObservation(lease))
	author := retained.Cause
	s, ctx, store := claimedEffect(t, api.Effect{ID: author.EffectID, OperationID: author.CauseOperationID, Context: &author, HelperRelease: &retained})
	live := retained
	live.Cause.Actor = liveClaimant
	q, err := s.captureDrainQuery(ctx, live)
	if err != nil {
		t.Fatal("capture drain refused the live claimant of its retained release", err)
	}
	if !reflect.DeepEqual(q.Release, live) || q.Abort != nil || !reflect.DeepEqual(q.Claim.Record, store.record) {
		t.Fatal("capture drain query lost its live release or claim")
	}
	changed := live
	changed.LeaseID = "lease-other"
	_, err = s.captureDrainQuery(ctx, changed)
	requireRefusal(t, err, "capture drain differs from its retained release effect")
}

func TestClaimantCaptureAbort(t *testing.T) {
	retained := testAbortRequest()
	author := retained.Cause
	s, ctx, _ := claimedEffect(t, api.Effect{ID: author.EffectID, OperationID: author.CauseOperationID, Context: &author, HelperAbort: &retained})
	live := retained
	live.Cause.Actor = liveClaimant
	q, err := s.captureAbortQuery(ctx, live)
	if err != nil {
		t.Fatal("capture drain refused the live claimant of its retained abort", err)
	}
	if q.Abort == nil || *q.Abort != live {
		t.Fatal("capture drain query lost its live abort")
	}
	changed := live
	changed.PreparedID = "prepared-other"
	_, err = s.captureAbortQuery(ctx, changed)
	requireRefusal(t, err, "capture drain differs from its retained nonexecuting abort")
}

// The native helper checks the query again against the claim it carries: the release or abort and the effect's context.
func TestClaimantDrainQueryCheck(t *testing.T) {
	lease := api.HelperLease{ID: "lease-a", ContainmentID: "containment-a"}
	retained := testRelease(lease, testObservation(lease))
	author := retained.Cause
	release := drainClaim(t, api.Effect{ID: author.EffectID, OperationID: author.CauseOperationID, Context: &author, HelperRelease: &retained})
	kept := testAbortRequest()
	abortAuthor := kept.Cause
	abort := drainClaim(t, api.Effect{ID: abortAuthor.EffectID, OperationID: abortAuthor.CauseOperationID, Context: &abortAuthor, HelperAbort: &kept})
	live := retained
	live.Cause.Actor = liveClaimant
	if err := validateCaptureDrainQuery(captureDrainQuery{Release: live, Claim: release}, "admin-case"); err != nil {
		t.Error("native capture drain refused the live claimant of its retained release", err)
	}
	liveAbort := kept
	liveAbort.Cause.Actor = liveClaimant
	if err := validateCaptureDrainQuery(captureDrainQuery{Abort: &liveAbort, Claim: abort}, "admin-case"); err != nil {
		t.Error("native capture drain refused the live claimant of its retained abort", err)
	}
	foreign := live
	foreign.Cause.Actor = api.Actor{Kind: "service", ID: "foreign-c"}
	turn := live
	turn.Cause.LogicalTurnID = "turn-other"
	moved := live
	moved.LeaseID = "lease-other"
	changed := liveAbort
	changed.LeaseID = "lease-other"
	for name, q := range map[string]captureDrainQuery{
		"foreign_actor": {Release: foreign, Claim: release},
		"cause_turn":    {Release: turn, Claim: release},
		"release_lease": {Release: moved, Claim: release},
		"abort_lease":   {Abort: &changed, Claim: abort},
	} {
		t.Run(name, func(t *testing.T) {
			requireRefusal(t, validateCaptureDrainQuery(q, "admin-case"), "capture drain has no exact retained release claim")
		})
	}
}
