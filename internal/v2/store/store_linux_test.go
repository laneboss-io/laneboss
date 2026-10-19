//go:build linux

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// These fixtures exercise storage, not OS authentication or actual effects.
// Run as an unprivileged test UID on the authorized Linux box.
type testClock struct{}

func (testClock) Now() time.Time { return time.Now() }

func testID(t *testing.T) api.ID {
	t.Helper()
	id, err := wire.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testDigest(data []byte) api.Digest {
	sum := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func testStateDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("storage tests require an unprivileged Linux test UID")
	}
	// testing.TempDir creates its numbered leaf with 0777 subject to umask.
	// Use an explicitly private child owned by this effective UID, matching
	// the production rule without assuming that the login user is a service UID.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(home, ".lb-v2-service-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	ownerMatches := ok && stat.Uid == uint32(os.Geteuid())
	modeMatches := info.Mode() == os.ModeDir|0700
	if !ownerMatches || !modeMatches {
		t.Fatalf("state fixture: owner_matches_euid=%t mode_private=%t", ownerMatches, modeMatches)
	}
	return directory
}

func testStore(t *testing.T) (*Service, Dependencies) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("storage tests require an unprivileged Linux test UID")
	}
	deps := Dependencies{Config: "store-fixture", Directory: testStateDir(t), Clock: testClock{}}
	s, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, deps
}

func testRequest(t *testing.T, method api.Method, body any) api.Request {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "store-fixture",
		Method: method, RequestID: testID(t), IdempotencyKey: testID(t), Params: data}
	request.RequestSHA256, err = wire.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testTransaction(t *testing.T) api.Transaction {
	t.Helper()
	content := api.BlobRef{ID: testID(t), SHA256: testDigest([]byte(testID(t))), Class: "record", Bytes: 32}
	scope := api.Scope{Config: "store-fixture", Actor: api.Actor{Kind: "service", ID: testID(t)}, Source: "worker"}
	scope.Request = testRequest(t, "records.append", api.RecordAppendRequest{
		Collection: "observations", Content: content, RelatedIDs: []api.ID{}})
	life := testID(t)
	record := api.Record{ID: testID(t), Collection: "observations", LifeID: life, Run: 1,
		Content: content, Actor: scope.Actor, Origin: "observation", Generation: 1,
		RecordedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config, Kind: "record.appended",
		Actor: scope.Actor, RequestedBy: scope.Actor, LifeID: life, Run: 1, Origin: "observation",
		StarterChain: []api.ID{}, Payload: data}
	return api.Transaction{Scope: scope, Events: []api.Event{event}, Reply: &api.RPCReply{Result: data}}
}

func expectCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}

func assertOneRecord(t *testing.T, s *Service, input api.Transaction) {
	t.Helper()
	ctx := context.Background()
	page, err := s.Records(ctx, input.Scope, api.RecordQuery{Collection: "observations", SearchMode: "keyword", Limit: 200})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("record inventory: %d, %v", len(page.Records), err)
	}
	events, err := s.Events(ctx, input.Scope, api.EventTailRequest{LifeID: input.Events[0].LifeID, Run: 1})
	if err != nil || len(events.Events) != 1 {
		t.Fatalf("event inventory: %d, %v", len(events.Events), err)
	}
	verification, err := s.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK || verification.Events != 1 {
		t.Fatalf("verification: %+v, %v", verification, err)
	}
}

func TestReplayAfterReopen(t *testing.T) {
	s, deps := testStore(t)
	input := testTransaction(t)
	first, err := s.Transact(context.Background(), input)
	if err != nil || first.Replayed {
		t.Fatal("first commit failed", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	// Even a newly stale comparison is checked after receipt replay.
	input.Compare = []api.Compare{{Kind: api.CompareRecord, ID: testID(t), Generation: 999}}
	second, err := reopened.Transact(context.Background(), input)
	if err != nil || !second.Replayed || second.Operation != first.Operation {
		t.Fatalf("replay changed operation: %+v, %v", second, err)
	}
	assertOneRecord(t, reopened, input)
	input.Compare = nil
	var body api.RecordAppendRequest
	if err := json.Unmarshal(input.Scope.Request.Params, &body); err != nil {
		t.Fatal(err)
	}
	body.Content.SHA256 = testDigest([]byte("changed request content"))
	input.Scope.Request.Params, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	input.Scope.Request.RequestSHA256, err = wire.RequestDigest(input.Scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reopened.Transact(context.Background(), input)
	expectCode(t, err, api.CodeIdempotencyConflict)
	assertOneRecord(t, reopened, input)
}

func TestRollbackInvalidPayload(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	bad := input.Events[0]
	bad.ID = testID(t)
	bad.Payload = json.RawMessage(`{"unexpected":true}`)
	input.Events = append(input.Events, bad)
	_, err := s.Transact(context.Background(), input)
	expectCode(t, err, api.CodeInvalid)
	verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK || verification.Events != 0 || verification.Objects != 0 {
		t.Fatalf("partial transaction survived: %+v, %v", verification, err)
	}
	input.Events = input.Events[:1]
	if _, err := s.Transact(context.Background(), input); err != nil {
		t.Fatal("valid control failed", err)
	}
	assertOneRecord(t, s, input)
}

func TestDurableOutboxIntent(t *testing.T) {
	s, deps := testStore(t)
	input := testPendingTransaction(t)
	commit, err := s.Transact(context.Background(), input)
	if err != nil || commit.Operation.Status != "pending" {
		t.Fatal("outbox was not pending", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := reopened.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	effects, err := reopened.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
	if err != nil || len(effects) != 1 || effects[0].ID != input.Effects[0].ID {
		t.Fatalf("outbox duplicated or lost intent: %d, %v", len(effects), err)
	}
	if effects[0].Stop == nil || effects[0].Stop.Generation != "fixture-generation" {
		t.Fatal("effect payload changed")
	}
	// This test proves intent durability, not completion or process execution.
}

func TestCASAndProofStayClosed(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	input.Compare = []api.Compare{{Kind: api.CompareRecord, ID: testID(t), Generation: 1}}
	_, err := s.Transact(context.Background(), input)
	expectCode(t, err, api.CodeConflict)
	input.Compare = nil
	input.Scope.Actor.Kind = "human"
	input.Events[0].Actor, input.Events[0].RequestedBy = input.Scope.Actor, input.Scope.Actor
	_, err = s.Transact(context.Background(), input)
	expectCode(t, err, api.CodeUnauthenticated)
	verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || verification.Events != 0 || verification.Objects != 0 {
		t.Fatal("closed path mutated state", err)
	}
}

func TestCursorScopeAndFilters(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	if _, err := s.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	query := api.EventTailRequest{LifeID: input.Events[0].LifeID, Run: 1}
	first, err := s.Events(context.Background(), input.Scope, query)
	if err != nil || first.Cursor == "" {
		t.Fatal("cursor absent", err)
	}
	query.Cursor = first.Cursor
	query.Run = 2
	_, err = s.Events(context.Background(), input.Scope, query)
	expectCode(t, err, api.CodeCursorExpired)
	query.Run = 1
	other := input.Scope
	other.Actor.ID = testID(t)
	_, err = s.Events(context.Background(), other, query)
	expectCode(t, err, api.CodeCursorExpired)
	page, err := s.Events(context.Background(), input.Scope, query)
	if err != nil || len(page.Events) != 0 {
		t.Fatal("exclusive cursor replayed event", err)
	}
}

func TestRefuseSecondWriter(t *testing.T) {
	s, deps := testStore(t)
	_, err := New(deps)
	expectCode(t, err, api.CodeUnavailable)
	if _, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"}); err != nil {
		t.Fatal(err)
	}
}

func TestRefuseUnsafeDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("requires unprivileged Linux test UID")
	}
	directory := testStateDir(t)
	deps := Dependencies{Config: "store-fixture", Directory: directory, Clock: testClock{}}
	control, err := New(deps)
	if err != nil {
		t.Fatal("private directory control failed", err)
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	unexpected, err := New(deps)
	if unexpected != nil {
		t.Cleanup(func() {
			if err := unexpected.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	expectCode(t, err, api.CodePrerequisite)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(directory, alias); err != nil {
		t.Fatal(err)
	}
	_, err = New(Dependencies{Config: "store-fixture", Directory: alias, Clock: testClock{}})
	expectCode(t, err, api.CodePrerequisite)
}

type ownerFixtureInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (info ownerFixtureInfo) Sys() any { return &info.stat }

func TestPrivateDirectoryOwner(t *testing.T) {
	directory := testStateDir(t)
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !private(info, true) {
		t.Fatal("same-UID private directory control refused")
	}
	stat := *info.Sys().(*syscall.Stat_t)
	stat.Uid++
	// This is a predicate unit fixture, not a claimed kernel chown canary.
	if private(ownerFixtureInfo{FileInfo: info, stat: stat}, true) {
		t.Fatal("different-owner metadata accepted")
	}
}

func TestDetectChangedProjection(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	if _, err := s.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(context.Background(), "UPDATE projections SET data=? WHERE kind='record'", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	expectCode(t, err, api.CodeIntegrity)
	if verification.OK || len(verification.Problems) == 0 {
		t.Fatal("corruption was credited")
	}
}

func TestEventCollisionIsByteAware(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	if _, err := s.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	input.Scope.Request.RequestID, input.Scope.Request.IdempotencyKey = testID(t), testID(t)
	_, err := s.Transact(context.Background(), input)
	expectCode(t, err, api.CodeNotImplemented)
	input.Events[0].Payload = json.RawMessage(`{"changed":true}`)
	_, err = s.Transact(context.Background(), input)
	expectCode(t, err, api.CodeConflict)
	verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || verification.Events != 1 {
		t.Fatal("event collision changed journal", err)
	}
}

func TestDetectChangedTrigger(t *testing.T) {
	s, _ := testStore(t)
	if _, err := s.db.ExecContext(context.Background(), `DROP TRIGGER events_no_delete;
 CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT 1; END;`); err != nil {
		t.Fatal(err)
	}
	_, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	expectCode(t, err, api.CodeIntegrity)
}

func TestForeignDBStaysUnchanged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("requires unprivileged Linux test UID")
	}
	deps := Dependencies{Config: "store-fixture", Directory: testStateDir(t), Clock: testClock{}}
	path := filepath.Join(deps.Directory, "state.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), "PRAGMA user_version=1; CREATE TABLE foreign_data(value TEXT)"); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(deps)
	expectCode(t, err, api.CodeVersion)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if testDigest(before) != testDigest(after) {
		t.Fatal("incompatible open modified database bytes")
	}
}

func TestReplayKeepsOneIntent(t *testing.T) {
	checkReplayIntent(t, true)
}
func TestLiveRetryKeepsOneIntent(t *testing.T) {
	checkReplayIntent(t, false)
}
func checkReplayIntent(t *testing.T, restart bool) {
	t.Helper()
	s, deps := testStore(t)
	seed := testTransaction(t)
	if _, err := s.Transact(context.Background(), seed); err != nil {
		t.Fatal(err)
	}
	input := testPendingTransaction(t)
	input.Scope.Actor = seed.Scope.Actor
	input.Events[0].Actor, input.Events[0].RequestedBy = seed.Scope.Actor, seed.Scope.Actor
	input.Effects[0].Context.Actor, input.Effects[0].Context.RequestedBy = seed.Scope.Actor, seed.Scope.Actor
	first, err := s.Transact(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if restart {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s, err = New(deps)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	// A restarted module may allocate fresh internal intent IDs. The identical
	// authenticated request/key must still return the original durable receipt.
	retry := input
	retry.Scope.Request.RequestID = testID(t)
	retry.Events = append([]api.Event(nil), input.Events...)
	retry.Events[0].ID, retry.Events[0].OperationID = testID(t), testID(t)
	retry.Events[0].Payload, err = json.Marshal(api.StateEvent{From: "running", To: "stopping", Generation: 2})
	if err != nil {
		t.Fatal(err)
	}
	retry.Effects = append([]api.Effect(nil), input.Effects...)
	retry.Effects[0].ID = testID(t)
	retry.Effects[0].OperationID = retry.Events[0].OperationID
	retry.Effects[0].Context = testEffectContext(t, retry, retry.Effects[0])
	second, err := s.Transact(context.Background(), retry)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rows, err := s.Records(ctx, input.Scope, api.RecordQuery{Collection: "observations", SearchMode: "keyword", Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	events, err := s.Events(ctx, input.Scope, api.EventTailRequest{LifeID: input.Events[0].LifeID, Run: 1})
	if err != nil {
		t.Fatal(err)
	}
	effects, err := s.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Records) != 1 || len(events.Events) != 1 || len(effects) != 1 {
		t.Fatalf("retry duplicated durable intent: records=%d events=%d effects=%d", len(rows.Records), len(events.Events), len(effects))
	}
	if !second.Replayed || second.Operation != first.Operation || effects[0].ID != input.Effects[0].ID {
		t.Fatal("retry changed its original receipt or effect")
	}
	// This does not execute an effect or prove installed socket crash recovery.
}

func testEffectContext(t *testing.T, input api.Transaction, effect api.Effect) *api.InternalIntent {
	t.Helper()
	return &api.InternalIntent{ID: testID(t), Kind: api.InternalLifecycleEffect,
		Config: input.Scope.Config, Actor: input.Scope.Actor, RequestedBy: input.Scope.Actor,
		CauseOperationID: effect.OperationID, CauseRequestID: input.Scope.Request.RequestID,
		EffectID: effect.ID, Target: api.LifeRef{LifeID: input.Events[0].LifeID, Run: 1}}
}

func testPendingTransaction(t *testing.T) api.Transaction {
	t.Helper()
	scope := api.Scope{Config: "store-fixture", Actor: api.Actor{Kind: "service", ID: testID(t)}, Source: "worker"}
	life, op := testID(t), testID(t)
	scope.Request = testRequest(t, "lane.stop", api.StopRequest{Target: api.LifeRef{LifeID: life, Run: 1}, ExpectedGeneration: 1,
		Reason: api.BlobRef{ID: testID(t), SHA256: testDigest([]byte(life)), Bytes: int64(len(life)), Class: "report"}})
	payload, err := json.Marshal(api.StateEvent{From: "running", To: "stopping", Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := json.Marshal(api.Operation{ID: op, Status: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	input := api.Transaction{Scope: scope, Reply: &api.RPCReply{Result: reply}, Events: []api.Event{{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config,
		Kind: "lane.stopping", Actor: scope.Actor, RequestedBy: scope.Actor, LifeID: life, Run: 1, Origin: "service", StarterChain: []api.ID{}, OperationID: op, Payload: payload}}}
	input.Effects = []api.Effect{{ID: testID(t), OperationID: op, Stop: &api.ProcessHandle{ID: testID(t), Target: api.LifeRef{LifeID: life, Run: 1}, ContainmentID: testID(t), Generation: "fixture-generation"}}}
	input.Effects[0].Context = testEffectContext(t, input, input.Effects[0])
	return input
}

func TestDraftFieldsStayClosed(t *testing.T) {
	for _, kind := range []string{"writes", "guards", "reply", "internal", "internal-authority"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := testStore(t)
			input := testTransaction(t)
			switch kind {
			case "writes":
				input.Writes = api.StateWrites{Policy: &api.EffectivePolicy{Generation: 1}}
			case "guards":
				input.Guards = []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: input.Events[0].LifeID, Epoch: 1}}}
			case "reply":
				var wrong api.Record
				if err := json.Unmarshal(input.Events[0].Payload, &wrong); err != nil {
					t.Fatal(err)
				}
				wrong.ID = testID(t)
				data, err := json.Marshal(wrong)
				if err != nil {
					t.Fatal(err)
				}
				input.Reply = &api.RPCReply{Result: data}
			case "internal":
				input.Scope.Request = api.Request{}
				input.Reply = nil
				input.Internal = &api.InternalIntent{ID: testID(t), Config: input.Scope.Config, Kind: api.InternalObjectRetain,
					Actor: input.Scope.Actor, RequestedBy: input.Scope.Actor}
			case "internal-authority":
				input.Scope.Request = api.Request{}
				input.Reply, input.Events = nil, nil
				input.Internal = &api.InternalIntent{ID: testID(t), Config: input.Scope.Config, Kind: api.InternalObjectRetain,
					Actor: api.Actor{Kind: "service", ID: testID(t)}, RequestedBy: input.Scope.Actor}
				if err := api.ValidateTransactionShape(input); err != nil {
					t.Fatal("internal authority control has invalid shape", err)
				}
			}
			_, err := s.Transact(context.Background(), input)
			if err == nil {
				t.Fatal("unsupported draft transaction accepted", kind)
			}
			codes := map[string]api.ErrorCode{"writes": api.CodeInvalid, "guards": api.CodeNotFound, "reply": api.CodeNotFound, "internal": api.CodeInvalid, "internal-authority": api.CodeForbidden}
			expectCode(t, err, codes[kind])
			if kind == "internal" && err.Error() != "invalid_request: invalid typed transaction shape" {
				t.Fatal("internal catalog refusal has wrong message", err)
			}
			if kind == "internal-authority" && err.Error() != "forbidden: internal emitter does not cover these writes or events" {
				t.Fatal("internal authority refusal has wrong message", err)
			}
			verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
			if err != nil || !verification.OK || verification.Events != 0 || verification.Objects != 0 {
				t.Fatal("unsupported draft transaction partially committed", err)
			}
		})
	}
}

func TestRawRequestMatchesScope(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	other := input.Scope.Request
	other.RequestID = testID(t)
	var err error
	input.RawRequest, err = json.MarshalIndent(other, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Transact(context.Background(), input); err == nil {
		t.Fatal("raw request mismatch accepted")
	} else {
		expectCode(t, err, api.CodeInvalid)
	}
	verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK || verification.Events != 0 {
		t.Fatal("raw mismatch partially committed", err)
	}
	input.RawRequest, err = json.MarshalIndent(input.Scope.Request, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	var retained []byte
	if err := s.db.QueryRow("SELECT request FROM receipts").Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retained, input.RawRequest) {
		t.Fatal("raw request bytes changed")
	}
	assertOneRecord(t, s, input)
}

func TestExactRecordLookup(t *testing.T) {
	s, _ := testStore(t)
	first, second := testTransaction(t), testTransaction(t)
	for _, input := range []api.Transaction{first, second} {
		if _, err := s.Transact(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	var wanted api.Record
	if err := json.Unmarshal(second.Events[0].Payload, &wanted); err != nil {
		t.Fatal(err)
	}
	query := api.RecordQuery{RecordID: wanted.ID, SearchMode: "keyword", Limit: 1}
	page, err := s.Records(context.Background(), first.Scope, query)
	if err != nil || len(page.Records) != 1 || !reflect.DeepEqual(page.Records[0], wanted) || page.Cursor != "" {
		t.Fatal("exact lookup returned unrelated records", err)
	}
	query.Collection = "reports"
	page, err = s.Records(context.Background(), first.Scope, query)
	if err != nil || len(page.Records) != 0 || page.Cursor != "" {
		t.Fatal("exact lookup ignored collection", err)
	}
	query.Collection, query.Limit = "", 2
	_, err = s.Records(context.Background(), first.Scope, query)
	expectCode(t, err, api.CodeInvalid)
	query.Limit, query.RecordID = 1, testID(t)
	page, err = s.Records(context.Background(), first.Scope, query)
	if err != nil || len(page.Records) != 0 || page.Cursor != "" {
		t.Fatal("absent exact lookup returned records", err)
	}
}
