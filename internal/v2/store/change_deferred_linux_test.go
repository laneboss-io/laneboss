//go:build linux

package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func deferredChangeFixture(t *testing.T) (*Service, Dependencies, api.Transaction) {
	t.Helper()
	s, deps, proposal := changeFixture(t)
	return deferredChangeFrom(t, s, deps, proposal)
}

func deferredChangeFrom(t *testing.T, s *Service, deps Dependencies, proposal api.Transaction) (*Service, Dependencies, api.Transaction) {
	t.Helper()
	if _, err := s.Transact(context.Background(), proposal); err != nil {
		t.Fatal(err)
	}
	change := proposal.Writes.Changes[0]
	approved := api.ChangeApproval{ID: testID(t), ChangeID: change.ID, RequesterLifeID: change.Requester.LifeID, ApproverKeyID: testID(t), NonceID: testID(t), ManifestSHA256: change.ManifestSHA256, BaseGeneration: 1, ApprovedAt: api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano))}
	fixtureProjection(t, s, "approval", approved.ID, 1, approved)
	request := api.ChangeApplyRequest{ChangeID: change.ID, ApprovalID: approved.ID, ExpectedGeneration: 1}
	scope := proposal.Scope
	scope.Request = testRequest(t, "org.change.apply", request)
	raw := enrollmentJSON(t, scope.Request)
	scope.Frame = &archFrame{raw: raw}
	reservation, err := s.ReserveRequest(context.Background(), api.RequestReservation{Scope: scope, RawRequest: raw, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	effect := testID(t)
	cause := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgPublish, Config: deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}, RequestedBy: scope.Actor, CauseRequestID: scope.Request.RequestID, CauseOperationID: reservation.Operation.ID, EffectID: effect, Target: api.LifeRef{LifeID: change.Requester.LifeID, Run: 1}}
	return s, deps, api.Transaction{Scope: scope, RawRequest: raw, Compare: []api.Compare{{Kind: api.CompareOrg, ID: change.OrgID, Generation: 1}}, Guards: []api.TransactionGuard{{Approval: &api.ApprovalUse{ApprovalID: approved.ID, ChangeID: change.ID, ManifestSHA256: change.ManifestSHA256, BaseGeneration: 1}}}, Effects: []api.Effect{{ID: effect, OperationID: reservation.Operation.ID, Context: &cause, ApplyChange: &request}}, Deferred: &api.DeferredReply{Key: requestKey(scope.Request), OperationID: reservation.Operation.ID, EffectID: effect}}
}

func TestChangeDeferredReservation(t *testing.T) {
	defer func() {
		if value := recover(); value != nil {
			t.Fatalf("apply transaction panicked before retaining its deferred reply: %v", value)
		}
	}()
	s, deps, tx := deferredChangeFixture(t)
	ctx := context.Background()
	commit, err := s.Transact(ctx, tx)
	if err != nil {
		t.Fatal("guarded apply did not durably defer publication", err)
	}
	if commit.Reply != nil || commit.Operation.Status != "pending" || commit.Deferred == nil || *commit.Deferred != *tx.Deferred {
		t.Fatal("queued publication fabricated completion or lost its binding")
	}
	for count := 0; count < 2; count++ {
		replay, err := s.Transact(ctx, tx)
		if err != nil || !replay.Replayed || !reflect.DeepEqual(replay.Deferred, tx.Deferred) || replay.Reply != nil {
			t.Fatal("guarded replay did not reuse its exact pending apply", err)
		}
	}
	retained, err := s.LookupReceipt(ctx, tx.Scope, tx.Deferred.Key)
	if err != nil || retained.Deferred == nil || *retained.Deferred != *tx.Deferred || retained.Reply != nil {
		t.Fatal("pending reply lookup lost original publication", err)
	}
	if owned, err := s.OwnsDeferredMutation(ctx, tx.Scope, tx.Deferred.Key, tx.Deferred.OperationID); err != nil || !owned {
		t.Fatal("dispatcher can overwrite a guarded publication after waiter loss", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(deps)
	if err != nil {
		t.Fatal("pending publication did not survive store reopen", err)
	}
	defer reopened.Close()
	retained, err = reopened.LookupReceipt(ctx, tx.Scope, tx.Deferred.Key)
	if err != nil || !reflect.DeepEqual(retained.Deferred, tx.Deferred) || retained.Reply != nil {
		t.Fatal("reopened pending publication changed", err)
	}
	if check, err := reopened.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !check.OK {
		t.Fatal("retained deferred publication failed real-store integrity", err)
	}
}
