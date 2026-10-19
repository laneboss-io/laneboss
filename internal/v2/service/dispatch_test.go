package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// An explicit receipt ledger isolates admission from production authentication.
// It has no mutation executor and cannot stand in for installed serve evidence.
type dispatchReceiptStore struct {
	unusedStore
	receipts map[api.RequestKey]api.MutationReceipt
	reserves int
}

func (s *dispatchReceiptStore) LookupReceipt(_ context.Context, _ api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	if receipt, ok := s.receipts[key]; ok {
		return receipt, nil
	}
	return api.MutationReceipt{}, serviceError(api.CodeNotFound, "fixture ledger has no receipt")
}

func (s *dispatchReceiptStore) ReserveRequest(context.Context, api.RequestReservation) (api.MutationReceipt, error) {
	s.reserves++
	return api.MutationReceipt{}, serviceError(api.CodeIntegrity, "frozen mutation reached reservation")
}

func (s *dispatchReceiptStore) ReserveMutation(ctx context.Context, request api.RequestReservation) (api.MutationReceipt, bool, error) {
	receipt, err := s.ReserveRequest(ctx, request)
	return receipt, false, err
}

func TestFrozenHostKeepsReads(t *testing.T) {
	s := fixtureServer(t)
	ledger := &dispatchReceiptStore{receipts: make(map[api.RequestKey]api.MutationReceipt)}
	s.deps.Store = ledger
	called := false
	if err := s.Register("blob.begin", func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
		called = true
		return nil, serviceError(api.CodeIntegrity, "frozen mutation reached handler")
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Register("identity.self", identityHandler); err != nil {
		t.Fatal(err)
	}
	s.dispatchPaused = true
	s.freeze = &api.FreezeReceipt{ID: fixtureID(t), Config: s.options.Config, OperationID: fixtureID(t), DispatchEpoch: 1}
	sum := sha256.Sum256(nil)
	request := requestFor(t, "blob.begin", api.BlobBeginRequest{Class: "record", SHA256: api.Digest(hex.EncodeToString(sum[:]))})
	_, _, err := s.dispatch(context.Background(), nil, request)
	codeIs(t, err, api.CodeUnavailable)
	if called || ledger.reserves != 0 {
		t.Fatal("frozen mutation reached handler")
	}
	reply, err := json.Marshal(api.BlobUpload{ObjectID: fixtureID(t), MaxChunkBytes: 1024,
		ExpiresAt: "2030-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	key := api.RequestKey{Method: request.Method, IdempotencyKey: request.IdempotencyKey, RequestSHA256: request.RequestSHA256}
	ledger.receipts[key] = api.MutationReceipt{Key: key, Reply: &api.RPCReply{Result: reply}, LastSeq: 7}
	replayed, scope, err := s.dispatch(context.Background(), nil, request)
	if err != nil || !bytes.Equal(replayed, reply) || scope.ReadView == nil || scope.ReadView.Snapshot().LastSeq != 7 || called {
		t.Fatal("frozen host did not retain exact completed replay", err)
	}
	if _, _, err := s.dispatch(context.Background(), nil, requestFor(t, "identity.self", api.Empty{})); err != nil {
		t.Fatal("frozen host blocked an authorized read", err)
	}
}
