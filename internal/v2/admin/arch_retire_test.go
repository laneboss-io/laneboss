package admin

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type retirementClaimStore struct {
	api.StateStore
	state   archivejob.Recovery
	current api.EffectRecord
}

func (s *retirementClaimStore) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	if err := ctx.Err(); err != nil {
		return api.EffectRecord{}, err
	}
	if scope.Config != "admin-case" || scope.Actor.Kind != "service" || scope.Actor.ID != s.current.ClaimantID || id != s.current.Effect.ID {
		return api.EffectRecord{}, failure(api.CodeForbidden, "foreign retirement fixture scope")
	}
	return s.current, nil
}

func (s *retirementClaimStore) ArchiveRecovery(ctx context.Context, scope api.Scope, claim api.EffectLease) (archivejob.Recovery, error) {
	current, err := s.Effect(ctx, scope, claim.Record.Effect.ID)
	if err != nil {
		return archivejob.Recovery{}, err
	}
	if !reflect.DeepEqual(current, claim.Record) || claim.ClaimID != current.ClaimID || claim.ExpiresAt != current.ClaimExpiresAt {
		return archivejob.Recovery{}, failure(api.CodeConflict, "fixture recovery lost the actual claim")
	}
	return s.state, nil
}

func TestRetirementAuthority(t *testing.T) {
	r := archiveClaimFixture()
	r.Job.Intent.EndEventID, r.Job.Intent.EndSeq = "original-end", 1
	r.Job.Lease.ExpiresAt = api.Timestamp(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
	state := archivejob.Recovery{Job: r.Job, Allocation: api.HelperLease{ID: "original-native", UID: 61002, GID: 61002, ContainmentID: "original-cgroup", EndpointGeneration: 1}, Allocating: true}
	store := &retirementClaimStore{state: state, current: r.Claim.Record}
	s := &Service{deps: Dependencies{Store: store, Config: "admin-case"}}
	q, err := s.archiveRetirementAuthority(context.Background(), r.Job, r.Claim)
	if err != nil || !reflect.DeepEqual(q.Job, state.Job) || q.Allocation != state.Allocation {
		t.Fatalf("acceptance: retirement refused the actual expired-worker recovery: %v", err)
	}
	store.current.ClaimID = "next-current-claim"
	store.current.Generation++
	_, err = s.archiveRetirementAuthority(context.Background(), r.Job, r.Claim)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeConflict || typed.Message != "archive retirement requires the actual current effect claim" {
		t.Fatal("acceptance: retirement accepted a nominal current claim")
	}
}
