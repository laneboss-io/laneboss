//go:build linux

package store

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The trusted component emitter writes an actual journal event and projection.
// This is not the native administrator installation/peer acceptance case.
func configPublication(t *testing.T) (*Service, api.Scope, api.Event, api.OrgSnapshot) {
	t.Helper()
	s, _ := testStore(t)
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}, Source: "service", PolicyGeneration: 1}
	id := testID(t)
	marker := api.InitialPublicationMarker{Schema: "laneboss.initial-marker.v2", Config: scope.Config, ID: id,
		Manifest: api.BlobRef{ID: testID(t), Class: "manifest", Bytes: 32, SHA256: testDigest([]byte(id))}}
	snapshot := api.OrgSnapshot{Ref: api.OrgSnapshotRef{OrgID: api.ID(scope.Config), Generation: 1, ManifestSHA256: marker.Manifest.SHA256},
		Config: scope.Config, Sources: []api.ResourceFile{}, Derived: []api.ResourceFile{}, PublishedBy: id,
		PublishedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	intent := api.InternalIntent{ID: api.ID("initial-" + string(id)), Kind: api.InternalOrgBootstrap, Config: scope.Config,
		Actor: scope.Actor, RequestedBy: scope.Actor, CauseOperationID: api.ID("initial-op-" + string(id)), CauseRequestID: id}
	event := api.Event{Schema: api.SchemaVersion, ID: api.ID("initial-event-" + string(id)), Config: scope.Config,
		Kind: "org.bootstrapped", Actor: scope.Actor, RequestedBy: scope.Actor, Origin: "service", StarterChain: []api.ID{}, Payload: enrollmentJSON(t, marker)}
	commit, err := s.Transact(context.Background(), api.Transaction{Scope: scope, Internal: &intent,
		Compare: []api.Compare{{Kind: api.CompareOrg, ID: api.ID(scope.Config), Generation: 0}},
		Writes:  api.StateWrites{OrgSnapshots: []api.OrgSnapshot{snapshot}}, Events: []api.Event{event}})
	if err != nil {
		t.Fatal("configuration publication fixture did not commit", err)
	}
	event.OperationID, event.Seq = commit.Operation.ID, commit.FirstSeq
	return s, scope, event, snapshot
}

func TestConfigurationEvents(t *testing.T) {
	s, scope, event, _ := configPublication(t)
	since := event.Seq
	event = configAfterLaneEvents(t, s, scope, event)
	page, err := s.Events(context.Background(), scope, api.EventTailRequest{Since: since})
	if err != nil || len(page.Events) != 1 || page.Events[0].ID != event.ID || page.Events[0].OperationID != event.OperationID || !reflect.DeepEqual(page.Events[0].Payload, event.Payload) {
		t.Fatal("internal configuration event read was refused or changed", err)
	}
	if after, err := s.Events(context.Background(), scope, api.EventTailRequest{Since: event.Seq}); err != nil || len(after.Events) != 0 {
		t.Fatal("configuration event since was not exclusive", err)
	}
	human := cacheHuman(t, s, scope)
	if _, err := s.Events(context.Background(), human, api.EventTailRequest{}); err == nil {
		t.Fatal("public event reader acquired configuration selection")
	} else {
		expectCode(t, err, api.CodeInvalid)
	}
}

// More than both page and scan limits separates the desired configuration
// event from the prior position. Lane events must be excluded by the query.
func configAfterLaneEvents(t *testing.T, s *Service, scope api.Scope, first api.Event) api.Event {
	t.Helper()
	ctx := context.Background()
	life := testID(t)
	for start := 0; start < 1205; start += 250 {
		var events []api.Event
		for n := start; n < min(start+250, 1205); n++ {
			content := []byte(testID(t))
			record := api.Record{ID: testID(t), Collection: "observations", LifeID: life, Run: 1,
				Content: api.BlobRef{ID: testID(t), Class: "record", Bytes: int64(len(content)), SHA256: testDigest(content)},
				Actor:   scope.Actor, Origin: "observation", Generation: 1,
				RecordedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))}
			events = append(events, api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config,
				Kind: "record.appended", Actor: scope.Actor, RequestedBy: scope.Actor, LifeID: life, Run: 1,
				Origin: "observation", StarterChain: []api.ID{}, Payload: enrollmentJSON(t, record)})
		}
		cause := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgBootstrap, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor}
		if _, err := s.Transact(ctx, api.Transaction{Scope: scope, Internal: &cause, Events: events}); err != nil {
			t.Fatal("intervening lane journal fixture did not commit", err)
		}
	}
	var marker api.InitialPublicationMarker
	if err := json.Unmarshal(first.Payload, &marker); err != nil {
		t.Fatal(err)
	}
	marker.ID = testID(t)
	event := first
	event.ID, event.Seq, event.Payload = api.ID("initial-event-"+string(marker.ID)), 0, enrollmentJSON(t, marker)
	cause := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgBootstrap, Config: scope.Config, Actor: scope.Actor,
		RequestedBy: scope.Actor, CauseRequestID: marker.ID, CauseOperationID: api.ID("initial-op-" + string(marker.ID))}
	commit, err := s.Transact(ctx, api.Transaction{Scope: scope, Internal: &cause, Events: []api.Event{event}})
	if err != nil {
		t.Fatal("configuration journal tail did not commit", err)
	}
	event.Seq, event.OperationID = commit.FirstSeq, commit.Operation.ID
	return event
}

func TestOrgSnapshotRead(t *testing.T) {
	s, scope, _, snapshot := configPublication(t)
	request := api.OrgSnapshotRequest{OrgID: snapshot.Ref.OrgID, Generation: snapshot.Ref.Generation}
	actual, err := s.OrgSnapshot(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(actual, snapshot) {
		t.Fatal("published org snapshot did not read back", err)
	}
	for _, mode := range []string{"org", "zero", "generation", "config", "retained_org"} {
		t.Run(mode, func(t *testing.T) {
			s, scope, _, snapshot := configPublication(t)
			request := api.OrgSnapshotRequest{OrgID: snapshot.Ref.OrgID, Generation: snapshot.Ref.Generation}
			query := request
			want := api.CodeInvalid
			switch mode {
			case "org":
				query.OrgID = testID(t)
			case "zero":
				query.Generation = 0
			case "generation":
				query.Generation++
				want = api.CodeConflict
			case "config", "retained_org":
				changed := snapshot
				if mode == "config" {
					changed.Config += "-changed"
				} else {
					changed.Ref.OrgID = testID(t)
				}
				fixtureProjection(t, s, "org", request.OrgID, 2, changed)
				want = api.CodeIntegrity
			}
			_, err := s.OrgSnapshot(context.Background(), scope, query)
			if err == nil {
				t.Fatal("org snapshot accepted a foreign selection", mode)
			}
			expectCode(t, err, want)
		})
	}
}
