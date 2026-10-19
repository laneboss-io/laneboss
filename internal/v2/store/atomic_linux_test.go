//go:build linux

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReservedExactReply(t *testing.T) {
	s, deps := testStore(t)
	input := testTransaction(t)
	input.Reply = &api.RPCReply{Result: input.Events[0].Payload}
	raw, err := json.MarshalIndent(input.Scope.Request, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := s.ReserveRequest(context.Background(), api.RequestReservation{Scope: input.Scope, RawRequest: raw,
		Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil || reservation.Reply != nil {
		t.Fatal("reservation failed", err)
	}
	input.RawRequest = raw
	commit, err := s.Transact(context.Background(), input)
	if err != nil || commit.Reply == nil || commit.Operation.ID != reservation.Operation.ID {
		t.Fatal("exact reply not committed", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(deps)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	input.Scope.Request.RequestID = testID(t)
	receipt, err := s.LookupReceipt(context.Background(), input.Scope, requestKey(input.Scope.Request))
	if err != nil || receipt.Reply == nil || !bytes.Equal(receipt.Reply.Result, commit.Reply.Result) || !bytes.Equal(receipt.RawRequest, raw) || receipt.LastSeq != commit.LastSeq {
		t.Fatal("restart changed exact receipt", err)
	}
}

func TestPinnedReadView(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	input.Reply = &api.RPCReply{Result: input.Events[0].Payload}
	if _, err := s.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	view, err := s.BeginRead(context.Background(), input.Scope)
	if err != nil {
		t.Fatal("read view unavailable", err)
	}
	defer view.Close()
	second := testTransaction(t)
	second.Reply = &api.RPCReply{Result: second.Events[0].Payload}
	if _, err := s.Transact(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	scope := input.Scope
	scope.ReadView = view
	page, err := s.Records(context.Background(), scope, api.RecordQuery{Collection: "observations", SearchMode: "keyword", Limit: 200})
	if err != nil || len(page.Records) != 1 || view.Snapshot().LastSeq != 1 {
		t.Fatal("read view drifted", err)
	}
	live, err := s.Records(context.Background(), input.Scope, api.RecordQuery{Collection: "observations", SearchMode: "keyword", Limit: 200})
	if err != nil || len(live.Records) != 2 {
		t.Fatal("live read did not advance", err)
	}
}

func TestPendingKeyRejectsChangedIntent(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	raw, err := json.Marshal(input.Scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := s.ReserveRequest(context.Background(), api.RequestReservation{Scope: input.Scope, RawRequest: raw,
		Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal("reservation control failed", err)
	}
	changed := testTransaction(t)
	changed.Scope.Actor = input.Scope.Actor
	changed.Events[0].Actor, changed.Events[0].RequestedBy = input.Scope.Actor, input.Scope.Actor
	var changedRecord api.Record
	if err := json.Unmarshal(changed.Events[0].Payload, &changedRecord); err != nil {
		t.Fatal(err)
	}
	changedRecord.Actor = input.Scope.Actor
	changed.Events[0].Payload, err = json.Marshal(changedRecord)
	if err != nil {
		t.Fatal(err)
	}
	changed.Reply.Result = changed.Events[0].Payload
	changed.Scope.Request.IdempotencyKey = input.Scope.Request.IdempotencyKey
	if _, err := s.Transact(context.Background(), changed); err == nil {
		t.Fatal("pending key accepted changed intent")
	} else {
		expectCode(t, err, api.CodeIdempotencyConflict)
	}
	commit, err := s.Transact(context.Background(), input)
	if err != nil || commit.Operation.ID != reserved.Operation.ID {
		t.Fatal("conflicting intent damaged original reservation", err)
	}
}

func TestEffectRequiresContext(t *testing.T) {
	input := testPendingTransaction(t)
	effect := input.Effects[0]
	if err := validateEffect(effect); err != nil {
		t.Fatal("effect context control failed", err)
	}
	effect.Context = nil
	if err := validateEffect(effect); err == nil {
		t.Fatal("effect without durable context was accepted")
	} else {
		expectCode(t, err, api.CodeInvalid)
	}
}

func TestAwaitReservedReceipt(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	raw, err := json.Marshal(input.Scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := s.ReserveRequest(context.Background(), api.RequestReservation{Scope: input.Scope, RawRequest: raw,
		Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type result struct {
		receipt api.MutationReceipt
		err     error
	}
	completed := make(chan result, 1)
	go func() {
		receipt, err := s.AwaitReceipt(ctx, input.Scope, requestKey(input.Scope.Request))
		completed <- result{receipt, err}
	}()
	commit, err := s.Transact(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-completed:
		if actual.err != nil || actual.receipt.Reply == nil || actual.receipt.Operation.ID != reservation.Operation.ID || !bytes.Equal(actual.receipt.Reply.Result, commit.Reply.Result) {
			t.Fatal("await lost completed exact reservation", actual.err)
		}
	case <-ctx.Done():
		t.Fatal("await did not observe completed reservation")
	}
}

func TestRetainedObjectBytes(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	parent, err := s.Transact(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(testID(t))
	key, operation := testID(t), parent.Operation.ID
	request := api.RetainObjectRequest{Intent: api.InternalIntent{ID: testID(t), Kind: api.InternalObjectRetain, Config: input.Scope.Config,
		Actor: input.Scope.Actor, RequestedBy: input.Scope.Actor, CauseOperationID: operation},
		Object: api.ObjectWrite{ObjectKey: key, Class: "record", Bytes: content, SHA256: testDigest(content), Origin: "service",
			ACL: api.ObjectACL{Config: input.Scope.Config, Owner: input.Scope.Actor, Audience: "owner", Generation: 1}}}
	ref, err := s.RetainObject(context.Background(), input.Scope, request)
	if err != nil {
		t.Fatal("object retention failed", err)
	}
	metadata, err := s.ObjectMetadata(context.Background(), input.Scope, ref.ID)
	if err != nil || metadata.Ref != ref {
		t.Fatal("object metadata changed", err)
	}
	chunk, err := s.Blob(context.Background(), input.Scope, api.BlobReadRequest{ObjectID: ref.ID, Limit: len(content)})
	if err != nil || !bytes.Equal(chunk.Data, content) {
		t.Fatal("object bytes changed", err)
	}
	request.Object.Bytes = append([]byte(nil), content...)
	request.Object.Bytes[0] ^= 1
	request.Object.SHA256 = testDigest(request.Object.Bytes)
	if _, err := s.RetainObject(context.Background(), input.Scope, request); err == nil {
		t.Fatal("immutable object changed under same key")
	}
}

func TestObjectParticipantAudience(t *testing.T) {
	owner := api.Actor{Kind: "lane", ID: testID(t), LifeID: testID(t), Level: 3, Role: "executor"}
	reader := api.Scope{Config: "store-fixture", Actor: api.Actor{Kind: "lane", ID: testID(t), LifeID: testID(t), Level: 3, Role: "executor"}}
	acl := api.ObjectACL{Config: reader.Config, Owner: owner, Audience: "owner", Participants: []api.ID{reader.Actor.ID}, Generation: 1}
	if objectVisible(reader, acl) {
		t.Fatal("owner audience exposed object to an unrelated participant")
	}
	acl.Audience = "participants"
	if !objectVisible(reader, acl) {
		t.Fatal("participant audience control was hidden")
	}
	acl.Config = "other-fixture"
	if objectVisible(reader, acl) {
		t.Fatal("participant audience crossed configuration")
	}
}
