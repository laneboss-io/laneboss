package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The real HTTP boundary must route the documented mutation with its exact
// authenticated envelope. The unreached root owner deliberately refuses;
// this observer supplies no issued grant or successful mutation result.
type rootGrantDispatchObserver struct {
	HumanTransport
	requests []api.Request
}

func (p *rootGrantDispatchObserver) Dispatch(ctx context.Context, scope api.Scope, request api.Request) (api.Response, error) {
	if request.Method != "grants.root" {
		return p.HumanTransport.Dispatch(ctx, scope, request)
	}
	if scope.Actor.Kind != "human" || scope.Source != "dashboard" || !reflect.DeepEqual(scope.Request, request) || scope.Frame == nil {
		return api.Response{}, forbiddenErr("root dispatch lost its human request", "Use the bound human endpoint.")
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return api.Response{}, err
	}
	p.requests = append(p.requests, request)
	return api.Response{}, api.NotImplemented("root-owner-observer", string(request.RequestID))
}

func TestDashDocumentedRootGrant(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	h.httpConnection = scope.Connection.(*fixtureConnection)
	observer := &rootGrantDispatchObserver{HumanTransport: s.deps.Transport}
	s.deps.Transport = observer
	manifest := h.putBlob("root-manifest", "manifest", []byte(`{"schema":"laneboss.root-grants.v2"}`))
	request := reviewRequest(t, "grants.root", api.RootGrantRequest{Manifest: manifest,
		Budget: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 1 << 20, Processes: 4, DiskBytes: 1 << 20, Currency: "USD"}})
	request.Proof = &api.ProofRef{ID: "root-operation-proof", RequestSHA256: request.RequestSHA256,
		ExpiresAt: api.Timestamp(h.clock.Now().Add(time.Minute).Format(time.RFC3339Nano))}
	t.Run("documented-human-method", func(t *testing.T) {
		response := reviewRPC(t, s, token, request)
		var reply api.Response
		if err := json.Unmarshal(response.Body.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusServiceUnavailable || reply.Error == nil || reply.Error.Code != api.CodeNotImplemented ||
			reply.Error.Owner != "root-owner-observer" || len(observer.requests) != 1 || !reflect.DeepEqual(observer.requests[0], request) {
			t.Fatalf("documented root grant did not reach the authenticated service boundary: status=%d error=%v calls=%d", response.Code, reply.Error, len(observer.requests))
		}
	})
	t.Run("proof-required", func(t *testing.T) {
		before := len(observer.requests)
		missing := request
		missing.Proof = nil
		if response := reviewRPC(t, s, token, missing); response.Code != http.StatusForbidden || len(observer.requests) != before {
			t.Fatal("root grant without proof reached the service dispatcher")
		}
	})
	t.Run("non-human-method-blocked", func(t *testing.T) {
		before := len(observer.requests)
		nonHuman := reviewRequest(t, "org.change.apply", api.ChangeApplyRequest{ChangeID: "change", ApprovalID: "approval", ExpectedGeneration: 1})
		if response := reviewRPC(t, s, token, nonHuman); response.Code != http.StatusForbidden || len(observer.requests) != before {
			t.Fatal("L6 operation was exposed on the human dashboard")
		}
	})
}

type treeEventSelections struct {
	*memHarness
	reads []api.EventTailRequest
}

func (s *treeEventSelections) Events(ctx context.Context, scope api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	s.reads = append(s.reads, request)
	return s.memHarness.Events(ctx, scope, request)
}

func TestDashTreePreselects(t *testing.T) {
	for _, row := range []struct {
		name  string
		query api.DashboardQuery
		lives []api.ID
	}{
		{"life-and-child", api.DashboardQuery{LifeID: "root"}, []api.ID{"root", "child"}},
		{"exact-life", api.DashboardQuery{LifeID: "child"}, []api.ID{"child"}},
		{"level", api.DashboardQuery{Level: 3}, []api.ID{"child", "other"}},
		{"driver", api.DashboardQuery{Driver: api.DriverCodex}, []api.ID{"child"}},
		{"combined", api.DashboardQuery{LifeID: "root", Level: 3, Driver: api.DriverCodex}, []api.ID{"child"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			h, s := draft4Fixture(t)
			scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
			h.lanes["root"] = api.Lane{LifeID: "root", RootLifeID: "root", Run: 1, Level: 4, State: "running", Session: api.Session{Driver: api.DriverClaudock}}
			h.lanes["child"] = api.Lane{LifeID: "child", ParentLifeID: "root", RootLifeID: "root", Run: 1, Level: 3, State: "running", Session: api.Session{Driver: api.DriverCodex}}
			h.lanes["other"] = api.Lane{LifeID: "other", RootLifeID: "other", Run: 1, Level: 3, State: "running", Session: api.Session{Driver: api.DriverClaudock}}
			trace := &treeEventSelections{memHarness: h}
			s.deps.Store = trace
			query := row.query
			query.Limit = 20
			view, err := s.DashboardTree(context.Background(), scope, query)
			if err != nil || len(view.Nodes) != len(row.lives) || len(trace.reads) != len(row.lives) {
				t.Fatalf("tree did not select before reading events: nodes=%d reads=%d want=%d error=%v", len(view.Nodes), len(trace.reads), len(row.lives), err)
			}
			want := make(map[api.ID]bool)
			for _, life := range row.lives {
				want[life] = true
			}
			for _, read := range trace.reads {
				if !want[read.LifeID] || read.Run != 1 {
					t.Fatal("tree fetched an unselected life/run")
				}
				delete(want, read.LifeID)
			}
			if len(want) != 0 {
				t.Fatal("tree repeated one life instead of reading its selected inventory")
			}
		})
	}
}

func TestDashProofBinding(t *testing.T) {
	for _, method := range []api.Method{"lane.stop", "lane.resume", "lane.mark", "mail.send", "human.session"} {
		t.Run(string(method), func(t *testing.T) {
			h, s := draft4Fixture(t)
			scope, session, token := h.establishVerifiedScope(t, s, "cfg-dash")
			original := scope.Connection.(*fixtureConnection)
			h.httpConnection = original
			before := sessionFact(t, h, scope, session.ID)
			h.clock.Advance(time.Minute)
			operation := reviewRequest(t, method, struct{}{})
			target, base := api.ID("proof-target"), api.Generation(1)
			if method == "human.session" {
				target, base = "cfg-dash", 0
			}
			request := reviewRequest(t, "human.challenge", api.HumanChallengeRequest{
				Method: method, TargetID: target, BaseGeneration: base, RequestSHA256: operation.RequestSHA256})
			w := reviewRPC(t, s, "", request)
			if w.Code != 200 {
				t.Fatalf("proof staging challenge failed: %s", w.Body.String())
			}
			if method == "human.session" {
				if h.httpConnection.ID() == original.ID() || h.httpConnection.principal == original.principal {
					t.Fatal("session proof reused the authenticated connection")
				}
			} else if h.httpConnection.ID() != original.ID() || h.httpConnection.principal != original.principal {
				t.Fatal("operation proof rotated the authenticated connection")
			}
			var response api.Response
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			var challenge api.HumanChallenge
			if err := json.Unmarshal(response.Result, &challenge); err != nil {
				t.Fatal(err)
			}
			w = reviewRPC(t, s, "", reviewRequest(t, "human.confirm", api.HumanConfirmRequest{
				ChallengeID: challenge.ID, CredentialID: "fixture-credential", ClientDataJSON: []byte("client-data"),
				AuthenticatorData: []byte("auth-data"), Signature: []byte("signature")}))
			if w.Code != 200 {
				t.Fatalf("proof staging confirmation failed: %s", w.Body.String())
			}
			if !reflect.DeepEqual(before, sessionFact(t, h, scope, session.ID)) {
				t.Fatal("proof staging changed the original read session")
			}
			if reviewRead(t, s, token, "/api/v2/tree").Code != 200 {
				t.Fatal("proof staging invalidated the authenticated cookie")
			}
		})
	}
}

func TestDashTreeBounds(t *testing.T) {
	for _, origin := range []string{"policy", "bootstrap"} {
		t.Run(origin, func(t *testing.T) {
			h, s := draft4Fixture(t)
			sources := []api.SourceRef{{ID: "L3-worker", Path: "instances/L3-worker.toml"}, {ID: "L3-idle", Path: "roles/L3-idle.toml"}}
			h.policy = &api.EffectivePolicy{Generation: 1}
			if origin == "policy" {
				h.policy.Sources = sources
			} else {
				h.appendEvent(api.Event{Seq: 1, Origin: "service", Kind: "org.bootstrapped",
					Payload: reviewJSON(t, api.ConfigView{Generation: 1, Sources: sources})})
			}
			scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
			lane := api.Lane{LifeID: "tree-worker", Name: "L3-worker", RootLifeID: "tree-worker", Level: 3,
				Run: 2, Generation: 1, LastSeq: 2, State: "running", Session: api.Session{Driver: api.DriverCodex}}
			h.lanes[lane.LifeID] = lane
			h.lanes["tree-idle"] = api.Lane{LifeID: "tree-idle", Name: "L3-idle", RootLifeID: "tree-idle", Level: 3,
				Run: 1, State: "idle", Session: api.Session{Driver: api.DriverClaudock}}
			h.appendEvent(api.Event{Seq: 2, Origin: "service", Kind: "lane.state", LifeID: lane.LifeID, Run: lane.Run,
				RecordedAt: "2026-10-16T11:30:00Z", Payload: reviewJSON(t, api.StateEvent{To: lane.State, Generation: lane.Generation})})
			unbounded, err := s.DashboardTree(context.Background(), scope, api.DashboardQuery{Limit: 10})
			wantConfigured := origin == "policy"
			wantNodes := 2
			if wantConfigured {
				wantNodes = 4
			}
			if err != nil || len(unbounded.Nodes) != wantNodes {
				t.Fatalf("tree configuration setup failed: %v %+v", err, unbounded.Nodes)
			}
			if !wantConfigured {
				for _, node := range unbounded.Nodes {
					if node.Configured || !node.Live || node.LifeID == "" || node.InstanceID != "" {
						t.Fatalf("bootstrap event supplied configuration without current Policy: %+v", node)
					}
				}
			}
			for _, row := range []struct {
				name  string
				query api.DashboardQuery
			}{
				{"since", api.DashboardQuery{Since: "2026-10-16T11:00:00Z"}},
				{"until", api.DashboardQuery{Until: "2026-10-16T11:45:00Z"}},
				{"both", api.DashboardQuery{Since: "2026-10-16T11:00:00Z", Until: "2026-10-16T11:45:00Z"}},
				{"life", api.DashboardQuery{LifeID: lane.LifeID}},
				{"run", api.DashboardQuery{Run: lane.Run}},
				{"driver", api.DashboardQuery{Driver: lane.Session.Driver}},
				{"all", api.DashboardQuery{LifeID: lane.LifeID, Run: lane.Run, Driver: lane.Session.Driver,
					Since: "2026-10-16T11:00:00Z", Until: "2026-10-16T11:45:00Z"}},
			} {
				t.Run(row.name, func(t *testing.T) {
					query := row.query
					query.Limit = 1
					view, err := s.DashboardTree(context.Background(), scope, query)
					if err != nil || len(view.Nodes) != 1 || view.Cursor != "" || view.Nodes[0].LifeID != lane.LifeID {
						t.Fatalf("filtered tree included an untimed configured row: %v %+v", err, view)
					}
					if view.Nodes[0].Configured != wantConfigured || wantConfigured && view.Nodes[0].InstanceID != "L3-worker" ||
						!wantConfigured && view.Nodes[0].InstanceID != "" {
						t.Fatalf("filtered live lane lost configured membership: %+v", view.Nodes[0])
					}
				})
			}
			for _, query := range []api.DashboardQuery{{Since: "2026-10-16T11:45:00Z", Limit: 10}, {Until: "2026-10-16T11:15:00Z", Limit: 10}} {
				view, err := s.DashboardTree(context.Background(), scope, query)
				if err != nil || len(view.Nodes) != 0 {
					t.Fatalf("tree observation escaped its actual time bounds: %v %+v", err, view)
				}
			}
		})
	}
}

type timedOrgStore struct {
	*memHarness
	snapshot api.OrgSnapshot
}

func (s timedOrgStore) OrgSnapshot(_ context.Context, scope api.Scope, request api.OrgSnapshotRequest) (api.OrgSnapshot, error) {
	if err := api.ValidateOrgSnapshotSelection(scope, request, s.snapshot); err != nil {
		return api.OrgSnapshot{}, err
	}
	return s.snapshot, nil
}

func TestDashResourceTimes(t *testing.T) {
	for _, kind := range []string{"script", "plugin"} {
		for _, shape := range []string{"applied", "bootstrap", "latest", "digest", "unknown", "invalid", "published", "snapshot", "deleted"} {
			t.Run(shape+"_"+kind, func(t *testing.T) {
				h, s := draft4Fixture(t)
				path := "scripts/timed.sh"
				if kind == "plugin" {
					path = "plugins/timed.py"
				}
				original := h.putBlob("timed-source", "artifact", []byte("first source bytes"))
				current := original
				if shape == "digest" {
					current = h.putBlob("changed-source", "artifact", []byte("changed source bytes"))
				}
				source := api.SourceRef{ID: current.ID, Path: path, SHA256: current.SHA256}
				h.policy = &api.EffectivePolicy{Generation: 5, Sources: []api.SourceRef{source}}
				scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
				h.lanes["resource-owner"] = api.Lane{LifeID: "resource-owner", Run: 1, Level: 6, State: "running", Session: api.Session{Driver: api.DriverClaudock}}
				wantTime := api.Timestamp("2026-10-16T11:20:00Z")
				wantCount, wantGeneration := 1, api.Generation(5)
				apply := func(generation api.Generation, at api.Timestamp, action string) {
					delta := api.ResourceDelta{Action: action, Path: path, Mode: 0644, After: &original}
					if action == "replace" {
						delta.BeforeSHA256 = original.SHA256
					}
					if action == "delete" {
						delta.BeforeSHA256, delta.After = original.SHA256, nil
					}
					change := api.ChangeRequest{ID: api.ID(fmt.Sprintf("change-%d", generation)),
						Files: []api.ResourceDelta{delta}}
					h.appendEvent(api.Event{Origin: "service", Kind: "org.change.applied", LifeID: "resource-owner", Run: 1, Payload: reviewJSON(t,
						api.ChangeEvent{Change: change, Receipt: &api.ChangeReceipt{ID: api.ID(fmt.Sprintf("receipt-%d", generation)),
							NewGeneration: generation, AppliedAt: at}})})
				}
				switch shape {
				case "applied", "digest":
					apply(2, wantTime, "add")
					if shape == "digest" {
						wantTime = ""
					}
				case "bootstrap":
					h.appendEvent(api.Event{Origin: "service", Kind: "org.bootstrapped", RecordedAt: wantTime,
						Payload: reviewJSON(t, api.ConfigView{Generation: 2, Sources: []api.SourceRef{source}})})
					// Bootstrap publication is available as the protected current
					// snapshot; the human never reads its life-less journal event.
					s.deps.Store = timedOrgStore{memHarness: h, snapshot: api.OrgSnapshot{Config: scope.Config,
						Ref: api.OrgSnapshotRef{OrgID: api.ID(scope.Config), Generation: h.policy.Generation}, PublishedAt: wantTime,
						Sources: []api.ResourceFile{{Source: source, Content: current, Kind: kind, RevisionGeneration: 2}}}}
				case "latest":
					apply(1, "2026-10-16T10:30:00Z", "add")
					apply(2, wantTime, "replace")
					wantTime = "2026-10-16T11:40:00Z"
					apply(4, wantTime, "replace")
				case "unknown":
					wantTime = ""
				case "invalid":
					apply(2, "invalid-time", "add")
					wantTime = ""
				case "published", "snapshot":
					wantTime = "2026-10-16T11:35:00Z"
					s.deps.Store = timedOrgStore{memHarness: h, snapshot: api.OrgSnapshot{Config: scope.Config,
						Ref: api.OrgSnapshotRef{OrgID: api.ID(scope.Config), Generation: h.policy.Generation}, PublishedAt: wantTime,
						Sources: []api.ResourceFile{{Source: source, Content: current, Kind: kind, RevisionGeneration: 4}}}}
					if shape == "snapshot" {
						apply(2, "2026-10-16T11:20:00Z", "add")
					}
				case "deleted":
					apply(6, wantTime, "delete")
					apply(2, wantTime, "add")
					wantCount, wantGeneration = 0, 6
				}
				read := s.DashboardResources
				if kind == "plugin" {
					read = s.DashboardPlugins
				}
				view, err := read(context.Background(), scope, api.DashboardQuery{Limit: 10})
				if err != nil || len(view.Resources) != wantCount || view.Generation != wantGeneration {
					t.Fatalf("resource timestamp reconciliation changed inventory: %v %+v", err, view)
				}
				if wantCount != 0 && (view.Resources[0].ObservedAt != wantTime || view.Resources[0].SHA256 != current.SHA256 || view.Resources[0].Version != "g5") {
					t.Fatalf("resource observation differs from retained history: want %s got %+v", wantTime, view.Resources[0])
				}
				for _, query := range []api.DashboardQuery{
					{Since: "2026-10-16T11:00:00Z", Limit: 10},
					{Until: "2026-10-16T11:45:00Z", Limit: 10},
					{Since: "2026-10-16T11:00:00Z", Until: "2026-10-16T11:45:00Z", Limit: 10},
				} {
					bounded, err := read(context.Background(), scope, query)
					count := wantCount
					if wantTime == "" {
						count = 0
					}
					if err != nil || len(bounded.Resources) != count {
						t.Fatalf("resource time bounds lost actual observation: %v %+v", err, bounded)
					}
				}
				if wantCount != 0 && wantTime != "" {
					outside, err := read(context.Background(), scope, api.DashboardQuery{Since: "2026-10-16T11:45:00Z", Limit: 10})
					if err != nil || len(outside.Resources) != 0 {
						t.Fatalf("resource observation was replaced by a default time: %v %+v", err, outside)
					}
				}
			})
		}
	}
}

func TestDashLaneTimes(t *testing.T) {
	for _, shape := range []string{"ahead", "created", "adopted", "prepared", "started", "resumed", "unknown", "invalid", "untrusted", "bad_latest"} {
		t.Run(shape, func(t *testing.T) {
			h, s := draft4Fixture(t)
			scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
			lane := api.Lane{LifeID: "timed-lane", Name: "worker", Run: 1, Level: 3, State: "verifying", Generation: 9, LastSeq: 9,
				StarterChain: []api.ID{}, Session: api.Session{Driver: api.DriverCodex}}
			h.lanes[lane.LifeID] = lane
			stale := lane
			stale.State, stale.Generation, stale.LastSeq = "running", 1, 1
			wantTime := api.Timestamp("2026-10-16T11:20:00Z")
			event := api.Event{Origin: "service", Seq: 2, Kind: "lane.started", LifeID: lane.LifeID,
				RecordedAt: wantTime, Payload: reviewJSON(t, api.LaunchEvent{Lane: stale})}
			switch shape {
			case "created", "adopted", "started", "resumed":
				event.Kind, event.LifeID = api.EventKind("lane."+shape), ""
			case "prepared":
				event.Kind, event.LifeID = "launch.prepared", ""
			case "unknown":
				event.RecordedAt, wantTime = "", ""
			case "invalid":
				event.RecordedAt, wantTime = "invalid-time", ""
			case "untrusted":
				event.Origin, wantTime = "runner", ""
			}
			// Assign exact event bytes: appendEvent supplies a timestamp when absent.
			h.events = []api.Event{event}
			if shape == "bad_latest" {
				h.events = append(h.events, api.Event{Origin: "service", LifeID: lane.LifeID, Seq: 8,
					Kind: "lane.state", RecordedAt: "invalid-time", Payload: reviewJSON(t, api.StateEvent{To: lane.State, Generation: lane.Generation})})
			}
			h.events = append(h.events, api.Event{Origin: "service", LifeID: lane.LifeID, Seq: 9,
				Kind: "lane.state", Payload: reviewJSON(t, api.StateEvent{To: lane.State, Generation: lane.Generation})})
			_, byID, times, seq := reconcileLanes([]api.Lane{lane}, h.events)
			if times[lane.LifeID] != wantTime || byID[lane.LifeID].State != lane.State || byID[lane.LifeID].Generation != 9 || seq != 9 {
				t.Fatalf("lane observation differs from actual service history: want %s got %s", wantTime, times[lane.LifeID])
			}
			// Keep the payload-fallback unit control above. Store-facing view
			// fixtures need the life/run headers stamped by the real writer.
			for i := range h.events {
				h.events[i].LifeID, h.events[i].Run = lane.LifeID, lane.Run
			}
			unbounded, err := s.DashboardLifecycle(context.Background(), scope, api.DashboardQuery{Limit: 10})
			if err != nil || len(unbounded.Lanes) != 1 || unbounded.Lanes[0].State != lane.State {
				t.Fatalf("timestamp reconciliation regressed lane state: %v %+v", err, unbounded)
			}
			for _, query := range []api.DashboardQuery{
				{Since: "2026-10-16T11:00:00Z", Limit: 10}, {Until: "2026-10-16T11:45:00Z", Limit: 10},
				{Since: "2026-10-16T11:00:00Z", Until: "2026-10-16T11:45:00Z", Limit: 10},
				{LifeID: lane.LifeID, Run: lane.Run, Level: lane.Level, Driver: lane.Session.Driver,
					Since: "2026-10-16T11:00:00Z", Until: "2026-10-16T11:45:00Z", Limit: 10},
			} {
				want := 1
				if wantTime == "" {
					want = 0
				}
				view, err := s.DashboardLifecycle(context.Background(), scope, query)
				if err != nil || len(view.Lanes) != want {
					t.Fatalf("lifecycle time bounds lost actual observation: %v %+v", err, view)
				}
				tree, err := s.DashboardTree(context.Background(), scope, query)
				if err != nil || len(tree.Nodes) != want {
					t.Fatalf("tree time bounds lost actual lane observation: %v %+v", err, tree)
				}
			}
		})
	}
}

func TestDashTimeOrder(t *testing.T) {
	lane := api.Lane{LifeID: "ordered", State: "verifying", Generation: 9, LastSeq: 9}
	newer := api.Event{Origin: "service", LifeID: lane.LifeID, Kind: "lane.state", Seq: 5, RecordedAt: "2026-10-16T11:40:00Z",
		Payload: reviewJSON(t, api.StateEvent{To: lane.State, Generation: lane.Generation})}
	older := newer
	older.Seq, older.RecordedAt = 2, "2026-10-16T11:20:00Z"
	for _, events := range [][]api.Event{{older, newer}, {newer, older}} {
		_, byID, times, _ := reconcileLanes([]api.Lane{lane}, events)
		if times[lane.LifeID] != newer.RecordedAt || byID[lane.LifeID].State != lane.State {
			t.Fatal("lane observation regressed by event order")
		}
	}
}
