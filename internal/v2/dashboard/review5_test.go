package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func reviewJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func reviewRead(t *testing.T, s *Service, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443"+path, nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func reviewRequest(t *testing.T, method api.Method, params any) api.Request {
	t.Helper()
	req, _, err := newReadRequest("cfg-dash", method, params)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestDashReauth(t *testing.T) {
	for _, state := range []string{"idle", "revoked", "identity", "restart", "unknown"} {
		t.Run(state, func(t *testing.T) {
			h, s := draft4Fixture(t)
			scope, oldSession, token := h.establishVerifiedScope(t, s, "cfg-dash")
			h.httpConnection = scope.Connection.(*fixtureConnection)
			switch state {
			case "idle":
				h.clock.Advance(5 * time.Minute)
			case "revoked":
				s.RevokeSession(oldSession.ID)
			case "identity":
				h.revokeOnIdentitySide(oldSession.ID)
			case "restart":
				s.sessionsByToken = make(map[string]*browserSession)
				s.sessionsByID = make(map[api.ID]*browserSession)
			case "unknown":
				token = "unknown-session-cookie"
			}
			sessionReq := reviewRequest(t, "human.session", api.HumanSessionRequest{})
			challengeReq := reviewRequest(t, "human.challenge", api.HumanChallengeRequest{Method: "human.session", TargetID: "cfg-dash", RequestSHA256: sessionReq.RequestSHA256})
			w := reviewRPC(t, s, token, challengeReq)
			cleared := false
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == sessionCookieName && cookie.MaxAge < 0 && cookie.Path == "/" && cookie.HttpOnly && cookie.Secure {
					cleared = true
				}
			}
			if w.Code != 200 || !cleared {
				t.Fatalf("stale cookie blocked the new authentication ceremony: %d %s", w.Code, w.Body.String())
			}
			var response api.Response
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			var challenge api.HumanChallenge
			if err := json.Unmarshal(response.Result, &challenge); err != nil {
				t.Fatal(err)
			}
			confirmReq := reviewRequest(t, "human.confirm", api.HumanConfirmRequest{ChallengeID: challenge.ID, CredentialID: "cred-test-1", ClientDataJSON: []byte("client-data"), AuthenticatorData: []byte("auth-data"), Signature: []byte("sig")})
			w = reviewRPC(t, s, "", confirmReq)
			if w.Code != 200 {
				t.Fatalf("new authentication confirmation failed: %s", w.Body.String())
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			var proof api.ProofRef
			if err := json.Unmarshal(response.Result, &proof); err != nil {
				t.Fatal(err)
			}
			sessionReq.Proof = &proof
			w = reviewRPC(t, s, "", sessionReq)
			if w.Code != 200 {
				t.Fatalf("new authentication session failed: %s", w.Body.String())
			}
			var fresh string
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == sessionCookieName && cookie.MaxAge > 0 {
					fresh = cookie.Value
				}
			}
			if fresh == "" || fresh == token || h.httpConnection.ID() == scope.Connection.ID() || reviewRead(t, s, fresh, "/api/v2/tree").Code != 200 {
				t.Fatal("cookie deletion did not restore an authenticated browser")
			}
		})
	}
}

func TestDashPolicyReload(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, hs, token := h.establishVerifiedScope(t, s, "cfg-dash")
	before := sessionFact(t, h, scope, hs.ID)
	h.policy = &api.EffectivePolicy{Generation: 2}
	got, err := s.authenticateCookie(context.Background(), idleRequest(token), false)
	if err != nil || got.Scope.PolicyGeneration != 2 || s.sessionsByID[hs.ID].Scope.PolicyGeneration != 2 || !reflect.DeepEqual(before, sessionFact(t, h, scope, hs.ID)) {
		t.Fatalf("policy advance stranded the existing browser session: %v", err)
	}
	if reviewRead(t, s, token, "/api/v2/tree").Code != 200 || h.lastReadScope.PolicyGeneration != 2 {
		t.Fatal("policy advance stranded the existing browser session")
	}
}

func TestDashReauthLabels(t *testing.T) {
	h, s := draft4Fixture(t)
	_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	h.clock.Advance(5 * time.Minute)
	for _, cookie := range []string{"", token} {
		req := reviewRequest(t, "human.challenge", api.HumanChallengeRequest{Method: "human.session", TargetID: "cfg-dash", RequestSHA256: api.Digest(strings.Repeat("a", 64))})
		r := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8443/api/v2/rpc", strings.NewReader(string(reviewJSON(t, req))))
		r.Header.Set("Origin", "https://127.0.0.1:8443")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Actor", "forged")
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("reauthentication accepted a header identity label")
		}
	}
}

func decisionSeed(t *testing.T, h *memHarness, id api.ID, life api.ID, run api.RunNumber, level int) api.Record {
	t.Helper()
	text := "Decision " + string(id)
	at := api.Timestamp("2026-10-16T11:00:00Z")
	ref := h.putDecisionDocument(t, api.ID("document-"+string(id)), text, at, true)
	actor := api.Actor{Kind: "human", ID: "owner"}
	if level != 0 {
		actor = api.Actor{Kind: "lane", ID: life, LifeID: life, Level: level, Role: "supervisor"}
	}
	record := api.Record{ID: id, Collection: "decisions", LifeID: life, Run: run, Actor: actor, Content: ref, Origin: "service", RecordedAt: at, Generation: 1}
	h.decisions[id] = api.DecisionProjection{RecordID: id, Status: "active", Candidate: api.DecisionCandidate{ID: id, Text: text, EffectiveAt: at, Binding: true}}
	return record
}

func TestDashDecisionScope(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	old := decisionSeed(t, h, "old", "executive", 1, 6)
	next := decisionSeed(t, h, "new", "another", 2, 0)
	next.Action, next.RelatedIDs = "supersede", []api.ID{old.ID}
	projection := h.decisions[next.ID]
	projection.SupersedesID = old.ID
	h.decisions[next.ID] = projection
	h.records["decisions"] = []api.Record{old, next}
	view, err := s.DashboardDecisions(context.Background(), scope, api.DashboardQuery{LifeID: old.LifeID, Run: 1, Level: 6, Limit: 200})
	if err != nil || len(view.Decisions) != 0 {
		t.Fatalf("display filters resurrected a superseded decision: %v", err)
	}
	view, err = s.DashboardDecisions(context.Background(), scope, api.DashboardQuery{Limit: 200})
	if err != nil || len(view.Decisions) != 1 || view.Decisions[0].ID != next.ID {
		t.Fatalf("global decision history lost the replacement: %v", err)
	}
}

func TestDashDecisionCanonical(t *testing.T) {
	for _, field := range []string{"binding", "time", "scope", "source"} {
		t.Run(field, func(t *testing.T) {
			h, s := draft4Fixture(t)
			scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
			record := decisionSeed(t, h, "canonical", "", 0, 0)
			h.records["decisions"] = []api.Record{record}
			view, err := s.DashboardDecisions(context.Background(), scope, api.DashboardQuery{Limit: 10})
			if err != nil || len(view.Decisions) != 1 || !view.Decisions[0].Binding {
				t.Fatalf("canonical decision setup failed: %v", err)
			}
			projection := h.decisions[record.ID]
			switch field {
			case "binding":
				projection.Candidate.Binding = false
			case "time":
				projection.Candidate.EffectiveAt = "2026-10-16T10:00:00Z"
			case "scope":
				projection.Candidate.AppliesTo.Levels = []int{6}
			case "source":
				projection.Candidate.Source.SHA256 = api.Digest(strings.Repeat("a", 64))
			}
			h.decisions[record.ID] = projection
			_, err = s.DashboardDecisions(context.Background(), scope, api.DashboardQuery{Limit: 10})
			if err == nil || asAPIError(err).Code != api.CodeIntegrity {
				t.Fatal("decision view trusted noncanonical projection fields")
			}
		})
	}
}

type smallPageStore struct {
	*memHarness
	repeat bool
}

func smallPage(cursor string, size, limit int) (int, int, error) {
	start := 0
	var err error
	if cursor != "" {
		start, err = strconv.Atoi(cursor)
	}
	if err != nil || start < 0 || start > size {
		return 0, 0, invalidErr("invalid fixture cursor", "Use the previous page cursor.")
	}
	pageSize := 37
	if limit > 0 && limit < pageSize {
		pageSize = limit
	}
	end := start + pageSize
	if end > size {
		end = size
	}
	return start, end, nil
}

func (p smallPageStore) Mail(ctx context.Context, scope api.Scope, request api.ListRequest) (api.MailPage, error) {
	page, err := p.memHarness.Mail(ctx, scope, request)
	if err != nil {
		return api.MailPage{}, err
	}
	start, end, err := smallPage(request.Cursor, len(page.Messages), request.Limit)
	if err != nil {
		return api.MailPage{}, err
	}
	cursor := ""
	if end < len(page.Messages) {
		cursor = strconv.Itoa(end)
	}
	if p.repeat && request.Cursor != "" {
		cursor = request.Cursor
	}
	return api.MailPage{Messages: page.Messages[start:end], Cursor: cursor}, nil
}

func (p smallPageStore) Records(ctx context.Context, scope api.Scope, request api.RecordQuery) (api.RecordPage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failRecords != nil {
		return api.RecordPage{}, p.failRecords
	}
	if p.failStore != nil {
		return api.RecordPage{}, p.failStore
	}
	var records []api.Record
	for _, record := range p.records[request.Collection] {
		if request.LifeID == "" || record.LifeID == request.LifeID {
			records = append(records, record)
		}
	}
	start, end, err := smallPage(request.Cursor, len(records), request.Limit)
	if err != nil {
		return api.RecordPage{}, err
	}
	cursor := ""
	if end < len(records) {
		cursor = strconv.Itoa(end)
	}
	return api.RecordPage{Records: records[start:end], Cursor: cursor}, nil
}

func TestDashAllPages(t *testing.T) {
	for _, kind := range []string{"mail", "decisions", "refusals"} {
		t.Run(kind, func(t *testing.T) {
			h, s := draft4Fixture(t)
			scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
			for index := 0; index < 205; index++ {
				id := api.ID(fmt.Sprintf("item-%03d", index))
				switch kind {
				case "mail":
					h.mails = append(h.mails, api.Mail{ID: id, QueuedSeq: api.Sequence(index + 1), Status: "queued"})
				case "decisions":
					h.records[kind] = append(h.records[kind], decisionSeed(t, h, id, "", 0, 0))
				case "refusals":
					ref := h.putBlob(id, "record", reviewJSON(t, api.PolicyDecision{ID: id, Result: "warn", AuditComplete: true}))
					h.records[kind] = append(h.records[kind], api.Record{ID: id, Collection: kind, Origin: "service", Content: ref})
				}
			}
			s.deps.Store = smallPageStore{memHarness: h}
			switch kind {
			case "mail":
				view, err := s.DashboardRaw(context.Background(), scope, api.DashboardQuery{Limit: 200})
				if err != nil || len(view.Messages) != 205 {
					t.Fatalf("mail inventory truncated at a store page: %v", err)
				}
			case "decisions":
				count, cursor := 0, ""
				for {
					view, err := s.DashboardDecisions(context.Background(), scope, api.DashboardQuery{Limit: 200, Cursor: cursor})
					if err != nil {
						t.Fatal(err)
					}
					count += len(view.Decisions)
					if view.Cursor == "" {
						break
					}
					cursor = view.Cursor
				}
				if count != 205 {
					t.Fatalf("decision inventory truncated at a store page: %d", count)
				}
			case "refusals":
				view, err := s.DashboardRefusals(context.Background(), scope, api.DashboardQuery{Limit: 200})
				if err != nil || len(view.Receipts) != 205 {
					t.Fatalf("refusal inventory truncated at a store page: %v", err)
				}
			}
		})
	}
}

func TestDashPageCycle(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	for index := 0; index < 80; index++ {
		h.mails = append(h.mails, api.Mail{ID: api.ID(fmt.Sprint(index))})
	}
	s.deps.Store = smallPageStore{memHarness: h, repeat: true}
	_, err := s.DashboardRaw(context.Background(), scope, api.DashboardQuery{Limit: 200})
	if err == nil || asAPIError(err).Code != api.CodeIntegrity {
		t.Fatal("repeated store cursor passed as complete inventory")
	}
}

type eventCycleStore struct {
	*memHarness
	retained api.EventPage
}

func (s *eventCycleStore) Events(ctx context.Context, scope api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	page, err := s.memHarness.Events(ctx, scope, request)
	if err != nil {
		return api.EventPage{}, err
	}
	if len(page.Events) != 0 {
		s.retained = page
	} else {
		page = s.retained
	}
	page.Complete = false
	return page, nil
}

func TestDashEventCycle(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	h.lanes["cycle"] = api.Lane{LifeID: "cycle", Run: 1}
	h.appendEvent(api.Event{Origin: "service", Kind: "lane.state", LifeID: "cycle", Run: 1,
		Payload: reviewJSON(t, api.StateEvent{To: "running", Generation: 1})})
	s.deps.Store = &eventCycleStore{memHarness: h}
	_, err := s.DashboardLifecycle(context.Background(), scope, api.DashboardQuery{Limit: 10})
	if err == nil || asAPIError(err).Code != api.CodeIntegrity {
		t.Fatal("repeated event page passed as complete history")
	}
}

func TestDashViewHistory(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	lane := api.Lane{LifeID: "history", Run: 1, LastSeq: 1, Level: 3, State: "running", Generation: 1, Session: api.Session{Driver: api.DriverCodex}}
	h.lanes[lane.LifeID] = lane
	zero := uint64(0)
	h.appendEvent(api.Event{Seq: 2, Origin: "service", LifeID: lane.LifeID, Run: 1, Kind: "lane.ended", Payload: reviewJSON(t, api.RunEndEvent{Observation: api.ProcessObservation{State: "exited", Survivors: &zero}})})
	lane.Run, lane.Generation, lane.Session.Driver = 2, 2, api.DriverClaudock
	h.appendEvent(api.Event{Seq: 3, Origin: "service", LifeID: lane.LifeID, Run: 2, Kind: "lane.resumed", Payload: reviewJSON(t, api.LaunchEvent{Lane: lane})})
	// Keep stale metadata for reconciliation, but retain the committed run
	// selector so the view can explicitly read its real run history.
	projected := h.lanes[lane.LifeID]
	projected.Run = lane.Run
	h.lanes[lane.LifeID] = projected
	view, err := s.DashboardLifecycle(context.Background(), scope, api.DashboardQuery{LifeID: lane.LifeID, Run: 1, Limit: 10})
	if err != nil || len(view.Lanes) != 0 {
		t.Fatalf("run filter hid newer lifecycle history: %v", err)
	}
	ref := h.putBlob("capture-history", "capture", []byte("x"))
	h.appendEvent(api.Event{Seq: 4, Origin: "service", LifeID: lane.LifeID, Run: 1, Kind: "capture.appended", Payload: reviewJSON(t, api.CaptureRecord{ID: "capture", Target: api.LifeRef{LifeID: lane.LifeID, Run: 1}, Data: ref, Primary: true, Coverage: "complete", ObservedAt: api.Timestamp(h.clock.Now().Format(time.RFC3339Nano))})})
	raw, err := s.DashboardRaw(context.Background(), scope, api.DashboardQuery{Run: 1, Driver: api.DriverClaudock, Limit: 10})
	if err != nil || len(raw.Records) != 1 {
		t.Fatalf("raw filters used stale lane metadata: %v", err)
	}
	h.appendEvent(api.Event{Seq: 5, Origin: "service", LifeID: lane.LifeID, Run: 1, Kind: "policy.evaluated", Payload: reviewJSON(t, api.PolicyDecision{ID: "warning", Result: "warn", AuditComplete: true})})
	refusals, err := s.DashboardRefusals(context.Background(), scope, api.DashboardQuery{Run: 1, Driver: api.DriverClaudock, Limit: 10})
	if err != nil || len(refusals.Receipts) != 1 {
		t.Fatalf("refusal filters used stale lane metadata: %v", err)
	}
}

func TestDashSnapshotWins(t *testing.T) {
	h, s := draft4Fixture(t)
	h.policy = &api.EffectivePolicy{Generation: 2, Sources: []api.SourceRef{{ID: "new", Path: "scripts/example.sh", Generation: 2, SHA256: api.Digest(strings.Repeat("b", 64))}}}
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	h.appendEvent(api.Event{Origin: "service", Kind: "org.bootstrapped", Payload: reviewJSON(t, api.ConfigView{Generation: 1, Sources: []api.SourceRef{{ID: "old", Path: "scripts/example.sh", Generation: 1, SHA256: api.Digest(strings.Repeat("a", 64))}}})})
	resources, err := s.DashboardResources(context.Background(), scope, api.DashboardQuery{Limit: 10})
	if err != nil || len(resources.Resources) != 1 || resources.Resources[0].Version != "g2" || resources.Resources[0].SHA256 != h.policy.Sources[0].SHA256 {
		t.Fatalf("historical bootstrap regressed current resources: %v", err)
	}
	for _, status := range []string{"delivered", "returned"} {
		mail := api.Mail{ID: api.ID(status), Status: status, QueuedSeq: 1}
		h.mails = append(h.mails, mail)
		mail.Status = "queued"
		h.appendEvent(api.Event{Origin: "service", Kind: "mail.queued", Payload: reviewJSON(t, mail)})
	}
	raw, err := s.DashboardRaw(context.Background(), scope, api.DashboardQuery{Limit: 10})
	if err != nil || len(raw.Messages) != 2 {
		t.Fatalf("mail snapshot setup failed: %v", err)
	}
	for _, mail := range raw.Messages {
		if mail.Status != string(mail.ID) {
			t.Fatal("historical queue event regressed terminal mail")
		}
	}
}

func TestDashMissingTimes(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	h.lanes["untimed"] = api.Lane{LifeID: "untimed", State: "running", Run: 1, Level: 3}
	h.mails = []api.Mail{{ID: "untimed", Status: "queued"}}
	unbounded, err := s.DashboardLifecycle(context.Background(), scope, api.DashboardQuery{Limit: 10})
	if err != nil || len(unbounded.Lanes) != 1 {
		t.Fatalf("untimed lane setup failed: %v", err)
	}
	query := api.DashboardQuery{Limit: 10, Since: "2026-10-16T11:00:00Z"}
	bounded, err := s.DashboardLifecycle(context.Background(), scope, query)
	if err != nil || len(bounded.Lanes) != 0 {
		t.Fatalf("unknown lane timestamp bypassed time bounds: %v", err)
	}
	tree, err := s.DashboardTree(context.Background(), scope, query)
	if err != nil || len(tree.Nodes) != 0 {
		t.Fatalf("unknown tree timestamp bypassed time bounds: %v", err)
	}
	raw, err := s.DashboardRaw(context.Background(), scope, query)
	if err != nil || len(raw.Messages) != 0 {
		t.Fatalf("unknown mail timestamp bypassed time bounds: %v", err)
	}
	h.policy = &api.EffectivePolicy{Generation: 2, Sources: []api.SourceRef{{ID: "untimed", Path: "scripts/untimed.sh", Generation: 2, SHA256: api.Digest(strings.Repeat("a", 64))}}}
	resources, err := s.DashboardResources(context.Background(), scope, query)
	if err != nil || len(resources.Resources) != 0 {
		t.Fatalf("unknown resource timestamp bypassed time bounds: %v", err)
	}
}

type changeFaultStore struct {
	*memHarness
	failure error
}

func (s changeFaultStore) Change(context.Context, api.Scope, api.ID) (api.ChangeRequest, error) {
	return api.ChangeRequest{}, s.failure
}

func TestDashChangeErrors(t *testing.T) {
	for _, known := range []bool{false, true} {
		name := "empty"
		if known {
			name = "known"
		}
		t.Run(name, func(t *testing.T) {
			h, s := draft4Fixture(t)
			scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
			if known {
				h.appendEvent(api.Event{Origin: "service", Kind: "org.change.proposed", Payload: reviewJSON(t, api.ChangeEvent{Change: api.ChangeRequest{ID: "change"}})})
			}
			failure := api.NotImplemented("lb-v2-service", "fixture unavailable change index")
			s.deps.Store = changeFaultStore{h, failure}
			_, err := s.DashboardApprovals(context.Background(), scope, api.DashboardQuery{Limit: 10})
			if !errors.Is(err, failure) {
				t.Fatal("approvals hid an unavailable change store")
			}
		})
	}
}

func resourceHistory(t *testing.T, h *memHarness) {
	t.Helper()
	h.lanes["resource-owner"] = api.Lane{LifeID: "resource-owner", Run: 1, Level: 6, State: "running", Session: api.Session{Driver: api.DriverClaudock}}
	h.lanes["worker"] = api.Lane{LifeID: "worker", Run: 2, Level: 3, State: "running", Session: api.Session{Driver: api.DriverCodex}}
	files := []api.ResourceDelta{}
	objects := []api.MaterializedObject{}
	for _, path := range []string{"scripts/example.sh", "plugins/example.py"} {
		ref := h.putBlob(api.ID("resource-"+strconv.Itoa(len(files))), "artifact", []byte(path))
		files = append(files, api.ResourceDelta{Action: "add", Path: path, After: &ref})
		objects = append(objects, api.MaterializedObject{SourceIdentity: "/" + path, SnapshotSHA256: ref.SHA256})
	}
	change := api.ChangeRequest{ID: "change", Files: files}
	approval := api.ChangeApproval{ID: "approval", ChangeID: change.ID, SimulatedPresence: true}
	h.appendEvent(api.Event{Origin: "service", Kind: "org.change.approved", Payload: reviewJSON(t, api.ChangeEvent{Change: change, Approval: &approval})})
	// Publication completion retains the approval and its applying life/run.
	h.appendEvent(api.Event{Origin: "service", Kind: "org.change.applied", LifeID: "resource-owner", Run: 1,
		Payload: reviewJSON(t, api.ChangeEvent{Change: change, Approval: &approval,
			Receipt: &api.ChangeReceipt{ID: "receipt", ChangeID: change.ID, NewGeneration: 2, AppliedAt: api.Timestamp(h.clock.Now().Format(time.RFC3339Nano))}})})
	h.appendEvent(api.Event{Origin: "service", Actor: api.Actor{Kind: "worker"}, LifeID: "worker", Run: 2, Kind: "data.materialized", Payload: reviewJSON(t, api.Materialization{Objects: objects})})
}

func TestDashResourcePresence(t *testing.T) {
	h, s := draft4Fixture(t)
	_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	resourceHistory(t, h)
	for _, route := range []string{"plugins", "resources"} {
		w := reviewRead(t, s, token, "/api/v2/"+route+"?life_id=target&run=1")
		var view api.ResourceView
		if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || len(view.Resources) != 1 || view.Resources[0].ApprovalID != "approval" || w.Header().Get("X-Laneboss-Presence") != "simulated" || w.Header().Get("X-Laneboss-Human-Approval") != "not_proven" {
			t.Fatalf("resource response lost simulated approval provenance: %d %s", w.Code, w.Body.String())
		}
		if route == "plugins" && !view.Resources[0].VerifiedLoaded {
			t.Fatal("life filter hid worker plugin verification")
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, idleRequest(token))
	if w.Code != 200 || w.Header().Get("X-Laneboss-Presence") != "simulated" || w.Header().Get("X-Laneboss-Human-Approval") != "not_proven" {
		t.Fatal("SSE lost simulated event provenance")
	}
}

type metadataDroppingTransport struct{ HumanTransport }

func (p metadataDroppingTransport) Dispatch(_ context.Context, scope api.Scope, req api.Request) (api.Response, error) {
	return p.HumanTransport.Dispatch(context.Background(), scope, req)
}

func TestDashResourceMetadata(t *testing.T) {
	h, s := draft4Fixture(t)
	_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	resourceHistory(t, h)
	s.deps.Transport = metadataDroppingTransport{h}
	w := reviewRead(t, s, token, "/api/v2/resources")
	if w.Code != 503 || !strings.Contains(w.Body.String(), "resource response presence provenance") {
		t.Fatal("resource provenance silently failed open")
	}
}
