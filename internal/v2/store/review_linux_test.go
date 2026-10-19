//go:build linux

package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRejectUnboundAdministrativeScope(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	if _, err := s.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	query := api.RecordQuery{Collection: "observations", SearchMode: "keyword", Limit: 200}
	control, err := s.Records(context.Background(), input.Scope, query)
	if err != nil || len(control.Records) != 1 {
		t.Fatal("protected read control failed", err)
	}
	for _, kind := range []string{"human", "worker"} {
		scope := input.Scope
		scope.Actor.Kind = kind
		if page, err := s.Records(context.Background(), scope, query); err == nil || len(page.Records) != 0 {
			t.Fatal("unbound administrative label read state", kind)
		} else {
			expectCode(t, err, api.CodeUnauthenticated)
		}
	}
	worker := testTransaction(t)
	worker.Scope.Actor.Kind = "worker"
	worker.Events[0].Actor, worker.Events[0].RequestedBy = worker.Scope.Actor, worker.Scope.Actor
	var record api.Record
	if err := json.Unmarshal(worker.Events[0].Payload, &record); err != nil {
		t.Fatal(err)
	}
	record.Actor = worker.Scope.Actor
	worker.Events[0].Payload, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	worker.Reply.Result = worker.Events[0].Payload
	if _, err := s.Transact(context.Background(), worker); err == nil {
		t.Fatal("unbound worker label committed state")
	} else {
		expectCode(t, err, api.CodeUnauthenticated)
	}
}

func TestPostOpenStatePrivacy(t *testing.T) {
	s, deps := testStore(t)
	path := filepath.Join(deps.Directory, "state.sqlite")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err == nil || verification.OK {
		t.Fatal("post-open public state mode was credited")
	}
	expectCode(t, err, api.CodeIntegrity)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	verification, err = s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("restored state privacy control failed", err)
	}
}

func TestEventCursorSinceResume(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	if _, err := s.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	query := api.EventTailRequest{LifeID: input.Events[0].LifeID, Run: 1, Since: 1}
	page, err := s.Events(context.Background(), input.Scope, query)
	if err != nil || len(page.Events) != 0 || page.Cursor == "" {
		t.Fatal("since snapshot control failed", err)
	}
	query.Cursor = page.Cursor
	if _, err := s.Events(context.Background(), input.Scope, query); err == nil {
		t.Fatal("cursor combined with since was accepted")
	}
	query.Since = 0
	if _, err := s.Events(context.Background(), input.Scope, query); err != nil {
		t.Fatal("exclusive cursor could not resume without since", err)
	}
}

func TestRecordMethodOwnLife(t *testing.T) {
	s, _ := testStore(t)
	input := testTransaction(t)
	input.Scope.Request = testRequest(t, "blob.begin", api.BlobBeginRequest{Class: "record", SHA256: testDigest(nil)})
	var err error
	input.Reply.Result, err = json.Marshal(api.BlobUpload{ObjectID: testID(t), MaxChunkBytes: api.MaxChunkBytes, ExpiresAt: "2027-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Transact(context.Background(), input); err == nil {
		t.Fatal("blob method emitted a record event")
	} else {
		expectCode(t, err, api.CodeInvalid)
	}
	input = testTransaction(t)
	var record api.Record
	if err := json.Unmarshal(input.Events[0].Payload, &record); err != nil {
		t.Fatal(err)
	}
	record.Collection, record.Origin = "decisions", "service"
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	input.Events[0].Payload, input.Reply.Result = data, data
	if _, err := s.Transact(context.Background(), input); err == nil {
		t.Fatal("observation intent promoted a canonical decision")
	} else {
		expectCode(t, err, api.CodeForbidden)
	}
}

func TestEffectCompletionIsMeasured(t *testing.T) {
	s, _ := testStore(t)
	input := testPendingTransaction(t)
	if _, err := s.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	effect := input.Effects[0]
	claim, err := s.ClaimEffect(context.Background(), input.Scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
		ClaimantID: input.Scope.Actor.ID, Deadline: "2027-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal("effect claim failed", err)
	}
	outcome := api.EffectOutcome{EffectID: effect.ID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: "succeeded"}
	if _, err := s.CompleteEffect(context.Background(), input.Scope, outcome); err == nil {
		t.Fatal("unmeasured effect was completed")
	}
	zero, exit := uint64(0), 0
	outcome.Observation = &api.ProcessObservation{Handle: *effect.Stop, State: "exited", Survivors: &zero, ExitCode: &exit, PromptStatus: "completed", ObservedAt: "2026-01-01T00:00:00Z"}
	first, err := s.CompleteEffect(context.Background(), input.Scope, outcome)
	if err != nil {
		t.Fatal("measured effect completion failed", err)
	}
	second, err := s.CompleteEffect(context.Background(), input.Scope, outcome)
	if err != nil || !second.Replayed || second.LastSeq != first.LastSeq {
		t.Fatal("completion retry duplicated its event", err)
	}
	pending, err := s.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
	if err != nil || len(pending) != 0 {
		t.Fatal("completed effect remained pending", err)
	}
	verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("effect completion broke structural state", err)
	}
}

func TestRejectWritableAncestor(t *testing.T) {
	parent := testStateDir(t)
	directory := filepath.Join(parent, "state")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Config: "store-fixture", Directory: directory, Clock: testClock{}}
	control, err := New(deps)
	if err != nil {
		t.Fatal("safe ancestor control failed", err)
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0720); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(parent, 0700); err != nil {
			t.Error(err)
		}
	})
	unexpected, err := New(deps)
	if unexpected != nil {
		if closeErr := unexpected.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}
	if err == nil {
		t.Fatal("writable ancestor accepted state writer")
	}
	expectCode(t, err, api.CodePrerequisite)
}

func TestPostOpenStateHardlink(t *testing.T) {
	s, deps := testStore(t)
	path := filepath.Join(deps.Directory, "state.sqlite")
	link := filepath.Join(deps.Directory, "retained-link")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err == nil || verification.OK {
		t.Fatal("post-open state hardlink was credited")
	}
	expectCode(t, err, api.CodeIntegrity)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	verification, err = s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("single-link state control failed", err)
	}
}

func TestIdentityCommitStamped(t *testing.T) {
	s, _ := testStore(t)
	input, binding := identityIntent(t)
	// This isolates store-assigned identity receipts for a leased worker.
	// TestLaunchBindingRestart exercises the full agent reservation/plan tuple.
	binding.Record.Actor = api.Actor{Kind: "worker", ID: testID(t)}
	binding.Record.Kind = "worker"
	var err error
	input.Events[0].Payload, err = json.Marshal(binding.Record)
	if err != nil {
		t.Fatal(err)
	}
	input.Writes.IdentityBindings = []api.LaunchBindingRequest{binding}
	commit, err := s.Transact(context.Background(), input)
	if err != nil {
		t.Fatal("prepared identity control failed", err)
	}
	retained, err := s.LaunchBinding(context.Background(), binding.Record.ID)
	data, encodeErr := json.Marshal(binding.Record)
	if encodeErr == nil {
		data, encodeErr = api.CanonicalJSON(data)
	}
	if err != nil || encodeErr != nil || retained.Identity.LaunchID != binding.Record.ID || retained.Identity.EventID != input.Events[0].ID ||
		retained.Identity.CommittedSeq != commit.LastSeq || retained.Identity.RecordSHA256 != testDigest(data) {
		t.Fatal("identity receipt was not stamped from committed event", err, encodeErr)
	}
	bad, forged := identityIntent(t)
	forged.Record.Actor = api.Actor{Kind: "worker", ID: testID(t)}
	forged.Record.Kind = "worker"
	bad.Events[0].Payload, err = json.Marshal(forged.Record)
	if err != nil {
		t.Fatal(err)
	}
	forged.Identity = api.IdentityCommit{LaunchID: forged.Record.ID, EventID: testID(t), CommittedSeq: 123, RecordSHA256: testDigest([]byte("uncommitted"))}
	bad.Writes.IdentityBindings = []api.LaunchBindingRequest{forged}
	if _, err := s.Transact(context.Background(), bad); err == nil {
		t.Fatal("forged identity commit was accepted")
	} else {
		expectCode(t, err, api.CodeForbidden)
	}
	verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK || verification.Events != 1 {
		t.Fatal("identity authority failure partially committed", err)
	}
}

func identityIntent(t *testing.T) (api.Transaction, api.LaunchBindingRequest) {
	t.Helper()
	scope := api.Scope{Config: "store-fixture", Actor: api.Actor{Kind: "service", ID: testID(t)}, Source: "worker"}
	life := testID(t)
	actor := api.Actor{Kind: "lane", ID: testID(t), LifeID: life, Level: 3, Role: "executor"}
	record := api.LaunchRecord{Kind: "agent", ID: testID(t), Config: scope.Config, Target: api.LifeRef{LifeID: life, Run: 1},
		RootLifeID: life, StarterChain: []api.ID{}, Actor: actor, UIDLeaseID: testID(t), HostUID: uint32(os.Geteuid() + 1),
		ProcessGeneration: "fixture-lifetime", ContainmentID: testID(t), GrantSetID: testID(t), GrantsSHA256: testDigest([]byte(life)), PolicyGeneration: 1, EndpointGeneration: 1}
	prepared := api.PreparedLaunch{ID: testID(t), SpecSHA256: testDigest([]byte(life)), Target: record.Target, ContainmentID: record.ContainmentID,
		ProcessGeneration: record.ProcessGeneration, EndpointGeneration: record.EndpointGeneration, GateID: testID(t)}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config, Kind: "identity.bound", Actor: scope.Actor,
		RequestedBy: scope.Actor, LifeID: life, Run: 1, Origin: "service", StarterChain: []api.ID{}, Payload: data}
	intent := api.InternalIntent{ID: testID(t), Kind: api.InternalLifecycleEffect, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor}
	return api.Transaction{Scope: scope, Internal: &intent, Events: []api.Event{event}}, api.LaunchBindingRequest{Record: record, Prepared: prepared}
}

func TestVerifyMeasuredOperationState(t *testing.T) {
	s, _ := testStore(t)
	input := testPendingTransaction(t)
	commit, err := s.Transact(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	original, err := json.Marshal(commit.Operation)
	if err != nil {
		t.Fatal(err)
	}
	changed := commit.Operation
	changed.Status = "succeeded"
	data, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(context.Background(), "UPDATE operations SET data=? WHERE id=?", data, string(changed.ID)); err != nil {
		t.Fatal(err)
	}
	verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err == nil || verification.OK {
		t.Fatal("unmeasured pending operation state was credited")
	}
	expectCode(t, err, api.CodeIntegrity)
	if _, err := s.db.ExecContext(context.Background(), "UPDATE operations SET data=? WHERE id=?", original, string(changed.ID)); err != nil {
		t.Fatal(err)
	}
	verification, err = s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("measured pending-state control failed", err)
	}
	if _, err := s.db.ExecContext(context.Background(), "DELETE FROM effect_states WHERE id=?", string(input.Effects[0].ID)); err != nil {
		t.Fatal(err)
	}
	verification, err = s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err == nil || verification.OK {
		t.Fatal("missing effect claim state was credited")
	}
}
