//go:build linux

package store

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/approval"
)

// These are real SQLite/object/journal transactions with explicit component
// launch facts. They do not claim native lane or physical human authentication.
func changeFixture(t *testing.T) (*Service, Dependencies, api.Transaction) {
	t.Helper()
	s, deps := testStore(t)
	owner := api.Scope{Config: deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}}
	retain := func(class string, bytes []byte) api.BlobRef {
		ref := api.BlobRef{ID: testID(t), Class: class, SHA256: testDigest(bytes), Bytes: int64(len(bytes))}
		cause := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgBootstrap, Config: deps.Config, Actor: owner.Actor, RequestedBy: owner.Actor}
		object := api.ObjectWrite{ObjectKey: ref.ID, Class: class, Bytes: bytes, SHA256: ref.SHA256, Origin: "service", ACL: api.ObjectACL{Config: deps.Config, Owner: owner.Actor, Audience: "owner", Generation: 1}}
		if _, err := s.Transact(context.Background(), api.Transaction{Scope: owner, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{object}}}); err != nil {
			t.Fatal(err)
		}
		return ref
	}
	ownership := retain("manifest", []byte("source/generated ownership\n"))
	snapshot := api.OrgSnapshot{Config: deps.Config, Ref: api.OrgSnapshotRef{OrgID: api.ID(deps.Config), Generation: 1, ManifestSHA256: testDigest([]byte("approved base"))}, Sources: []api.ResourceFile{}, Derived: []api.ResourceFile{}, OwnershipManifest: ownership, Renderer: api.Executable{ID: testID(t), SHA256: testDigest([]byte("pinned renderer")), Version: "component-v2"}}
	fixtureProjection(t, s, "org", snapshot.Ref.OrgID, 1, snapshot)
	life, launch := testID(t), testID(t)
	actor := api.Actor{Kind: "lane", ID: testID(t), LifeID: life, Level: 6, Role: "supervisor"}
	_, identity := identityIntent(t)
	identity.Record.ID, identity.Record.Actor, identity.Record.Config = launch, actor, deps.Config
	identity.Record.Target, identity.Record.RootLifeID = api.LifeRef{LifeID: life, Run: 1}, life
	fixtureProjection(t, s, "launch", launch, 1, identity.Record)
	after := retain("artifact", []byte("reviewed source bytes\n"))
	change := api.ChangeRequest{Config: deps.Config, ID: testID(t), OrgID: snapshot.Ref.OrgID, Requester: actor, BaseGeneration: 1, SourceSnapshot: snapshot.Ref, OwnershipManifest: ownership, Renderer: snapshot.Renderer,
		Reason: retain("artifact", []byte("review this exact update\n")), Diff: retain("artifact", []byte("+reviewed source bytes\n")), Files: []api.ResourceDelta{{Path: "shared/scripts/check.sh", Action: "add", Mode: 0755, After: &after}}, Derived: []api.ResourceDelta{}, Status: "proposed",
		CreatedAt: api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))}
	var err error
	change.ManifestSHA256, err = approval.ManifestDigest(change)
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest(t, "org.change.propose", api.ChangeProposeRequest{OrgID: change.OrgID, BaseGeneration: 1, Reason: change.Reason, Files: change.Files})
	scope := api.Scope{Config: deps.Config, Actor: actor, LaunchID: launch, EndpointGeneration: 1, Request: request}
	event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: deps.Config, Kind: "org.change.proposed", Actor: actor, RequestedBy: actor, LifeID: life, Run: 1, RootLifeID: life, StarterChain: []api.ID{}, Origin: "service", Payload: enrollmentJSON(t, api.ChangeEvent{Change: change, Reason: "exact source and derived staging"})}
	return s, deps, api.Transaction{Scope: scope, Compare: []api.Compare{{Kind: api.CompareOrg, ID: change.OrgID, Generation: 1}, {Kind: api.CompareChange, ID: change.ID}}, Writes: api.StateWrites{Changes: []api.ChangeRequest{change}}, Events: []api.Event{event}, Reply: &api.RPCReply{Result: enrollmentJSON(t, change)}}
}

func TestChangeProposalAtomic(t *testing.T) {
	s, deps, tx := changeFixture(t)
	ctx := context.Background()
	commit, err := s.Transact(ctx, tx)
	if err != nil {
		t.Fatal("valid exact-source proposal refused", err)
	}
	if commit.Operation.Status != "succeeded" || commit.LastSeq == 0 {
		t.Fatal("proposal did not commit journal and reply")
	}
	replay, err := s.Transact(ctx, tx)
	if err != nil || !replay.Replayed || !reflect.DeepEqual(replay.Reply, commit.Reply) || replay.LastSeq != commit.LastSeq {
		t.Fatal("proposal replay appended or changed its reply", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.Change(ctx, tx.Scope, tx.Writes.Changes[0].ID)
	if err != nil || !reflect.DeepEqual(got, tx.Writes.Changes[0]) || got.Derived == nil {
		t.Fatal("proposal lost exact retained source/empty derived array on reopen", err)
	}
}

func TestChangeProposalFences(t *testing.T) {
	for _, fault := range []string{"foreign_org", "stale_base", "missing_base", "missing_event", "event_bytes", "reply_bytes", "lower_level", "missing_cas", "missing_object", "missing_change"} {
		t.Run(fault, func(t *testing.T) {
			s, _, tx := changeFixture(t)
			change := tx.Writes.Changes[0]
			switch fault {
			case "foreign_org":
				change.OrgID = testID(t)
			case "stale_base":
				tx.Compare[0].Generation++
			case "missing_base":
				if _, err := s.db.Exec("DELETE FROM projections WHERE kind='org'"); err != nil {
					t.Fatal(err)
				}
			case "missing_event":
				tx.Events = nil
			case "event_bytes":
				var value api.ChangeEvent
				if err := json.Unmarshal(tx.Events[0].Payload, &value); err != nil {
					t.Fatal(err)
				}
				value.Change.Reason.ID = testID(t)
				tx.Events[0].Payload = enrollmentJSON(t, value)
			case "reply_bytes":
				tx.Reply.Result = enrollmentJSON(t, api.ChangeRequest{ID: testID(t)})
			case "lower_level":
				tx.Scope.Actor.Level = 5
			case "missing_cas":
				tx.Compare = nil
			case "missing_object":
				change.Diff.ID = testID(t)
			case "missing_change":
				tx.Writes.Changes = nil
			}
			if fault != "missing_change" {
				tx.Writes.Changes[0] = change
			}
			var before int
			if err := s.db.QueryRow("SELECT count(*) FROM events").Scan(&before); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Transact(context.Background(), tx); err == nil {
				t.Fatal("proposal accepted " + fault)
			}
			var after, rows int
			if err := s.db.QueryRow("SELECT count(*) FROM events").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if err := s.db.QueryRow("SELECT count(*) FROM projections WHERE kind='change'").Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if before != after || rows != 0 {
				t.Fatal("refused proposal retained a partial event or change")
			}
		})
	}
}
