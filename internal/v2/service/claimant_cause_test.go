package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Launch control hands the helper a release or abort whose cause carries the current claimant {service, ClaimantID}
// in place of the retained effect's author (Release, Abort), and RecordRelease and RecordAbort take that request back
// with the helper's receipt. The request may differ from the retained one by that single substitution and nothing else.

var liveClaimant = api.Actor{Kind: "service", ID: "claimant-b"}

// claimantStore holds one effect claimed by claimant-b and records the outcomes completed under that claim.
// Every other store method is the nil embedded interface.
type claimantStore struct {
	api.StateStore
	record    api.EffectRecord
	completed []api.EffectOutcome
}

func (s *claimantStore) Effect(_ context.Context, _ api.Scope, id api.ID) (api.EffectRecord, error) {
	if id != s.record.Effect.ID {
		return api.EffectRecord{}, serviceError(api.CodeNotFound, "claimant store has no such effect")
	}
	return s.record, nil
}

func (s *claimantStore) CompleteEffect(_ context.Context, scope api.Scope, outcome api.EffectOutcome) (api.Commit, error) {
	if scope.Actor != (api.Actor{Kind: "service", ID: s.record.ClaimantID}) || outcome.EffectID != s.record.Effect.ID || outcome.ClaimID != s.record.ClaimID {
		return api.Commit{}, serviceError(api.CodeConflict, "claimant store refused a foreign completion")
	}
	s.completed = append(s.completed, outcome)
	return api.Commit{}, nil
}

func claimantCause(kind api.InternalKind) api.InternalIntent {
	return api.InternalIntent{ID: "intent-a", Kind: kind, Config: "service-fixture", Actor: api.Actor{Kind: "service", ID: "author-a"},
		RequestedBy: api.Actor{Kind: "human", ID: "human-a"}, CauseOperationID: "operation-a", CauseRequestID: "request-a",
		EffectID: "effect-a", Target: api.LifeRef{LifeID: "life-a", Run: 1}, LogicalTurnID: "turn-a"}
}

// claimantServer is a verified launch control whose store holds effect, authored by its context's actor and claimed
// by claimant-b.
func claimantServer(t *testing.T, effect api.Effect) (*Server, *claimantStore) {
	t.Helper()
	if effect.Context.Actor == liveClaimant {
		t.Fatal("the claimant must differ from the effect's author")
	}
	store := &claimantStore{record: api.EffectRecord{Effect: effect, Generation: 2, State: api.EffectClaimed, ClaimID: "claim-b",
		ClaimantID: liveClaimant.ID, ClaimExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))}}
	s := fixtureServer(t)
	s.verified, s.controller, s.deps.Store = true, "controller-a", store
	return s, store
}

func refusedAs(t *testing.T, err error, message string) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeConflict || typed.Message != message {
		t.Fatalf("want conflict %q, got %v", message, err)
	}
}

func TestClaimantRecordRelease(t *testing.T) {
	ctx := context.Background()
	zero := uint64(0)
	author := claimantCause(api.InternalHelperRelease)
	observation := api.ProcessObservation{Handle: api.ProcessHandle{ID: "run-a", Target: author.Target, ContainmentID: "containment-a",
		Generation: "generation-a"}, State: "exited", Survivors: &zero, ObservedAt: "2026-10-18T00:00:00Z"}
	retained := api.HelperReleaseRequest{Cause: author, LeaseID: "lease-a", Observation: observation}
	s, store := claimantServer(t, api.Effect{ID: author.EffectID, OperationID: author.CauseOperationID, Context: &author, HelperRelease: &retained})
	receipt := api.ReleaseReceipt{ID: "receipt-a", LeaseID: "lease-a", EffectID: author.EffectID, OperationID: author.CauseOperationID}
	live := retained
	live.Cause.Actor = liveClaimant
	if err := s.RecordRelease(ctx, live, receipt); err != nil || len(store.completed) != 1 || store.completed[0].Release == nil {
		t.Fatal("release receipt was refused for the live claimant of its retained effect", err)
	}
	const refused = "release receipt belongs to another retained effect"
	foreign := live
	foreign.Cause.Actor = api.Actor{Kind: "service", ID: "foreign-c"}
	refusedAs(t, s.RecordRelease(ctx, foreign, receipt), refused)
	changed := live
	changed.LeaseID = "lease-other"
	refusedAs(t, s.RecordRelease(ctx, changed, receipt), refused)
	if len(store.completed) != 1 {
		t.Fatal("a refused release request completed the effect")
	}
}

func TestClaimantRecordAbort(t *testing.T) {
	ctx := context.Background()
	author := claimantCause(api.InternalHelperAbort)
	retained := api.HelperAbortRequest{Cause: author, LeaseID: "lease-a", PreparedID: "prepared-a", OperationID: author.CauseOperationID, EffectID: author.EffectID}
	s, store := claimantServer(t, api.Effect{ID: author.EffectID, OperationID: author.CauseOperationID, Context: &author, HelperAbort: &retained})
	receipt := api.AbortReceipt{ID: "receipt-a", LeaseID: "lease-a", PreparedID: "prepared-a"}
	live := retained
	live.Cause.Actor = liveClaimant
	if err := s.RecordAbort(ctx, live, receipt); err != nil || len(store.completed) != 1 || store.completed[0].Abort == nil {
		t.Fatal("abort receipt was refused for the live claimant of its retained effect", err)
	}
	const refused = "abort receipt belongs to another retained effect"
	foreign := live
	foreign.Cause.Actor = api.Actor{Kind: "service", ID: "foreign-c"}
	refusedAs(t, s.RecordAbort(ctx, foreign, receipt), refused)
	changed := live
	changed.PreparedID = "prepared-other"
	refusedAs(t, s.RecordAbort(ctx, changed, receipt), refused)
	if len(store.completed) != 1 {
		t.Fatal("a refused abort request completed the effect")
	}
}
