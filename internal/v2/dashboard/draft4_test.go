package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type observedTransport struct {
	HumanTransport
	calls     int
	scopes    int
	pollTimes []time.Time
	raw       []byte
	fail      error
}

func (o *observedTransport) Scope(ctx context.Context, r *http.Request, req api.Request, raw []byte, claim *SessionClaim) (api.Scope, error) {
	o.scopes++
	o.raw = append([]byte(nil), raw...)
	return o.HumanTransport.Scope(ctx, r, req, raw, claim)
}

func (o *observedTransport) Dispatch(ctx context.Context, scope api.Scope, req api.Request) (api.Response, error) {
	o.calls++
	if o.fail != nil {
		return api.Response{}, o.fail
	}
	return o.HumanTransport.Dispatch(ctx, scope, req)
}

func (o *observedTransport) PollEvents(ctx context.Context, scope api.Scope, tail api.EventTailRequest) (api.EventPage, error) {
	o.calls++
	o.pollTimes = append(o.pollTimes, time.Now())
	if o.fail != nil {
		return api.EventPage{}, o.fail
	}
	poller, ok := o.HumanTransport.(HumanLivenessTransport)
	if !ok {
		return api.EventPage{}, api.NotImplemented("lb-v2-service", "fixture event liveness")
	}
	return poller.PollEvents(ctx, scope, tail)
}

func TestDashServiceDispatch(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	h.lanes["life-stop"] = api.Lane{LifeID: "life-stop", Run: 1, State: "running", Generation: 1}
	reason := h.putBlob("stop-reason", "task", []byte("stop for projection review"))
	req, _ := h.issueProofFor(t, "cfg-dash", "lane.stop", "life-stop", 1,
		api.StopRequest{Target: api.LifeRef{LifeID: "life-stop", Run: 1}, ExpectedGeneration: 1, Reason: reason})
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	transport := &observedTransport{HumanTransport: h}
	s.deps.Transport = transport
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8443/api/v2/rpc", bytes.NewReader(raw))
		r.Header.Set("Origin", "https://127.0.0.1:8443")
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	w := call()
	if w.Code != http.StatusOK || transport.calls != 1 || !bytes.Equal(transport.raw, raw) ||
		h.lastMutationAct != scope.Actor || h.lanes["life-stop"].State != "verifying" {
		t.Fatalf("dashboard bypassed exact service dispatch: %d %s", w.Code, w.Body.String())
	}
	transport.fail = api.NotImplemented("lb-v2-lifecycle", "lifecycle.lane.stop")
	w = call()
	var response api.Response
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusServiceUnavailable || transport.calls != 2 || response.Error == nil ||
		response.Error.Code != api.CodeNotImplemented || response.Error.Owner != "lb-v2-lifecycle" {
		t.Fatal("dashboard bypassed service authorization on replay")
	}
}

func TestDashMissingTransport(t *testing.T) {
	_, s := draft4Fixture(t)
	s.deps.Transport = nil
	req, raw, err := newReadRequest("cfg-dash", "human.challenge", api.HumanChallengeRequest{Method: "human.session",
		TargetID: "cfg-dash", RequestSHA256: api.Digest(strings.Repeat("a", 64))})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8443/api/v2/rpc", bytes.NewReader(raw))
	r.Header.Set("Origin", "https://127.0.0.1:8443")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var response api.Response
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusServiceUnavailable || response.RequestID != req.RequestID || response.Error == nil ||
		response.Error.Code != api.CodeNotImplemented || response.Error.Owner != "lb-v2-service" {
		t.Fatal("missing human transport lost its owning failure")
	}
}

func draft4Fixture(t *testing.T) (*memHarness, *Service) {
	t.Helper()
	h := newMemHarness()
	s, err := New(Dependencies{Store: h, Human: h.human(), Lifecycle: h, Messaging: h, Approval: h, Clock: h.clock, Transport: h})
	if err != nil {
		t.Fatal(err)
	}
	h.dashboard = s
	if err := s.ConfigureHTTP("cfg-dash", "https://127.0.0.1:8443", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	return h, s
}

func TestDashLiveSnapshot(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, session, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	before, err := scope.Connection.ReadAuthority(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if scope.Actor.ID == session.ID {
		t.Fatal("fixture conflated principal and session")
	}
	stale := before
	stale.Generation--
	scope.ReadAuthority = &stale
	h.clock.Advance(time.Minute)
	if _, err := s.DashboardLifecycle(context.Background(), scope, api.DashboardQuery{Limit: 10}); err != nil {
		t.Fatalf("dashboard used a stale read snapshot: %v", err)
	}
	current, err := scope.Connection.ReadAuthority(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := h.lastReadScope
	if got.ReadAuthority == nil || *got.ReadAuthority != current || current.Generation <= before.Generation ||
		current.SessionID != session.ID || got.Actor.ID != current.PrincipalID {
		t.Fatal("dashboard used a stale read snapshot")
	}
}

type revisionIdentity struct{ *memHarness }

func (i revisionIdentity) IdentitySelf(ctx context.Context, scope api.Scope, input api.Empty) (api.Scope, error) {
	verified, err := i.memHarness.IdentitySelf(ctx, scope, input)
	if err != nil {
		return api.Scope{}, err
	}
	a, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return api.Scope{}, err
	}
	i.mu.Lock()
	session := i.readSessions[a.SessionID]
	session.Generation++
	i.readSessions[a.SessionID] = session
	i.mu.Unlock()
	return verified, nil
}

func TestDashStoreRevision(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	s.identity = revisionIdentity{h}
	_, err := s.DashboardLifecycle(context.Background(), scope, api.DashboardQuery{Limit: 10})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated || h.lastReadScope.Connection != nil {
		t.Fatalf("dashboard admitted a changed session revision: %v", err)
	}
}

func TestDashSessionBoundary(t *testing.T) {
	for _, name := range []string{"principal", "connection", "endpoint", "expired", "absolute", "revoked", "closed"} {
		t.Run(name, func(t *testing.T) {
			h, s := draft4Fixture(t)
			scope, session, _ := h.establishVerifiedScope(t, s, "cfg-dash")
			switch name {
			case "principal":
				scope.Actor.ID = "foreign-principal"
			case "connection":
				scope.Connection = h.newFixtureScope("cfg-dash").Connection
			case "endpoint":
				scope.EndpointGeneration++
			case "expired":
				h.clock.Advance(5 * time.Minute)
			case "absolute":
				h.clock.Advance(30 * time.Minute)
			case "revoked":
				h.revokeOnIdentitySide(session.ID)
			case "closed":
				if err := scope.Connection.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.DashboardLifecycle(context.Background(), scope, api.DashboardQuery{Limit: 10}); err == nil || h.lastReadScope.Connection != nil {
				t.Fatal("dashboard admitted foreign or expired read authority")
			}
		})
	}
}

func TestDashCurrentPolicy(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	h.policy = &api.EffectivePolicy{Generation: 4}
	h.lanes["life-old"] = api.Lane{LifeID: "life-old", Run: 1, Level: 3, State: "running", PolicyGeneration: 3}
	page, err := s.DashboardLifecycle(context.Background(), scope, api.DashboardQuery{Limit: 10})
	if err != nil || h.lastReadScope.PolicyGeneration != 4 || len(page.Lanes) != 1 || page.Lanes[0].PolicyGeneration != 3 {
		t.Fatalf("dashboard replaced current or historical policy: %v", err)
	}
}

func TestDashPolicyEvent(t *testing.T) {
	lane := api.Lane{LifeID: "life-policy", Run: 1, Generation: 2, PolicyGeneration: 3, GrantSetID: "grant-set", LastSeq: 10}
	advance := api.PolicyAdvanceEvent{FromGeneration: 3, ToGeneration: 4, LaneGeneration: 3, GrantSetID: lane.GrantSetID, PolicySHA256: api.Digest(strings.Repeat("a", 64))}
	raw, err := json.Marshal(advance)
	if err != nil {
		t.Fatal(err)
	}
	event := api.Event{Kind: "lane.policy", Origin: "service", LifeID: lane.LifeID, Run: lane.Run, Seq: 11, Payload: raw}
	lanes, _, _, _ := reconcileLanes([]api.Lane{lane}, []api.Event{event})
	if len(lanes) != 1 || lanes[0].PolicyGeneration != 4 || lanes[0].Generation != 3 || lanes[0].LastSeq != 11 || lane.PolicyGeneration != 3 {
		t.Fatal("dashboard ignored a committed policy advance")
	}
	event.Origin = "lane"
	lanes, _, _, _ = reconcileLanes([]api.Lane{lane}, []api.Event{event})
	if lanes[0].PolicyGeneration != 3 {
		t.Fatal("lane observation advanced policy")
	}
}

func TestDashLaunchPlanView(t *testing.T) {
	record := api.LaunchPlanRecord{Reservation: api.LaunchReservation{ID: "reservation", Target: api.LifeRef{LifeID: "reserved-life", Run: 1}}, Generation: 1, Phase: "reserved"}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	lanes, _, _, seq := reconcileLanes(nil, []api.Event{{Kind: "launch.planned", Origin: "service", Seq: 8, Payload: raw}})
	if len(lanes) != 0 || seq != 8 {
		t.Fatal("launch plan projection changed visibility")
	}
}

func TestDashStrictBodies(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	r := &testRegistrar{}
	if err := s.Register(r); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{`{"cursor":"","limit":10,"limit":20}`, `{"cursor":"","limit":10,"Limit":20}`,
		`{"cursor":null,"limit":10}`, `{"cursor":"","limit":10,"extra":true}`} {
		for method, handler := range r.handlers {
			_, err := handler(context.Background(), scope, json.RawMessage(input))
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
				t.Fatalf("dashboard strict decode was bypassed: %s: %v", method, err)
			}
		}
	}
}

func TestDashHTTPParams(t *testing.T) {
	_, s := draft4Fixture(t)
	// A malformed method body must fail before the absent service transport.
	s.deps.Transport = nil
	req, _, err := newReadRequest("cfg-dash", "human.challenge", map[string]any{"method": "human.session", "target_id": "cfg-dash",
		"request_sha256": strings.Repeat("a", 64), "base_generation": 0, "extra": true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8443/api/v2/rpc", strings.NewReader(string(raw)))
	r.Header.Set("Origin", "https://127.0.0.1:8443")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var response api.Response
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusBadRequest || response.Error == nil || response.Error.Code != api.CodeInvalid {
		t.Fatal("HTTP method params escaped strict decode")
	}
}

func TestDashPresence(t *testing.T) {
	for _, name := range []string{"proof", "ticket", "session", "operation", "approval", "application", "aggregate"} {
		t.Run(name, func(t *testing.T) {
			var value any
			switch name {
			case "proof":
				value = api.ProofRef{ID: "proof", SimulatedPresence: true}
			case "ticket":
				value = api.Ticket{ID: "ticket", SimulatedPresence: true}
			case "session":
				value = api.HumanSession{ID: "session", SimulatedPresence: true}
			case "operation":
				value = api.Operation{ID: "operation", Status: "pending", SimulatedPresence: true}
			case "approval":
				value = api.ChangeApproval{ID: "approval", SimulatedPresence: true}
			case "application":
				value = api.ChangeReceipt{ID: "application", SimulatedPresence: true}
			case "aggregate":
				value = api.ApprovalView{Approvals: []api.ChangeApproval{{ID: "approval", SimulatedPresence: true}},
					Applications: []api.ChangeReceipt{{ID: "application"}}}
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			writeRPCResponse(w, http.StatusOK, api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, Result: raw})
			if w.Header().Get("X-Laneboss-Presence") != "simulated" || w.Header().Get("X-Laneboss-Human-Approval") != "not_proven" {
				t.Fatal("simulated result was reported as human approval")
			}
			var response api.Response
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			var decoded any
			if err := json.Unmarshal(response.Result, &decoded); err != nil || !simulatedPresence(decoded) {
				t.Fatal("response lost simulated presence provenance")
			}
		})
	}
	w := httptest.NewRecorder()
	writeJSONResult(w, api.Operation{ID: "ordinary", Status: "pending"})
	if w.Header().Get("X-Laneboss-Presence") == "simulated" {
		t.Fatal("unmarked result invented simulation")
	}
}

func TestDashFixturePorts(t *testing.T) {
	h := newMemHarness()
	ctx, scope := context.Background(), api.Scope{}
	checks := []struct {
		name string
		call func() error
	}{
		{"cred_read", func() error { _, e := h.CredentialProjection(ctx, "cfg-dash", "missing"); return e }},
		{"cred_reserve", func() error {
			_, e := h.ReserveCredentialProjection(ctx, scope, api.CredentialProjectionRequest{})
			return e
		}},
		{"cred_commit", func() error {
			_, e := h.CommitCredentialProjection(ctx, scope, api.CredentialProjectionReceipt{})
			return e
		}},
		{"cred_fence", func() error {
			_, e := h.FenceCredentialProjection(ctx, scope, api.CredentialWithdrawalRequest{})
			return e
		}},
		{"cred_withdraw", func() error {
			_, e := h.CompleteCredentialWithdrawal(ctx, scope, api.CredentialWithdrawalReceipt{})
			return e
		}},
		{"current_policy", func() error { _, e := h.CurrentApprovedPolicy(ctx, scope); return e }},
		{"capture", func() error { _, e := h.AppendCapture(ctx, scope, api.CaptureAppendRequest{}); return e }},
		{"capture_state", func() error { _, e := h.CaptureState(ctx, scope, "missing"); return e }},
		{"launch", func() error { _, e := h.ReserveLaunch(ctx, scope, api.LaunchReservationRequest{}); return e }},
		{"plan", func() error { _, e := h.LaunchPlan(ctx, scope, "missing"); return e }},
		{"data", func() error { _, e := h.LaunchDataStage(ctx, scope, api.LaunchDataRequest{}); return e }},
		{"channel", func() error { _, e := h.PrepareChannelJob(ctx, scope, api.ChannelPrepareRequest{}); return e }},
		{"inventory", func() error { _, e := h.HumanEnrollments(ctx, "cfg-dash"); return e }},
		{"enroll", func() error { _, e := h.ReserveEnrollment(ctx, api.EnrollmentCeremonyRequest{}); return e }},
		{"challenge", func() error { _, e := h.EnrollmentChallenge(ctx, "cfg-dash", "missing"); return e }},
		{"worker", func() error { _, e := h.WorkerBinding(ctx, api.InstalledBinding{}, api.PeerFacts{}); return e }},
		{"revocation", func() error { _, e := h.LaunchRevocation(ctx, "missing"); return e }},
		{"refresh", func() error { _, e := h.RefreshReadSession(ctx, scope, api.ReadSessionRefreshRequest{}); return e }},
		{"guidance", func() error { _, e := h.AwaitGuidance(ctx, scope, api.GuidanceAwaitRequest{}); return e }},
		{"policy", func() error { _, e := h.PolicyAt(ctx, scope, 1); return e }},
		{"policy_refresh", func() error { _, e := h.RefreshLanePolicy(ctx, scope, api.PolicyAdvanceRequest{}); return e }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			var typed *api.Error
			if err := check.call(); !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-service" {
				t.Fatal("unimplemented fixture returned success or wrong owner")
			}
		})
	}
}

func TestDashSessionPresence(t *testing.T) {
	h, s := draft4Fixture(t)
	h.simulatedCredential = true
	scope, session, token := h.establishVerifiedScope(t, s, "cfg-dash")
	if !session.SimulatedPresence {
		t.Fatal("fixture failed to retain verified presence")
	}
	r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/lifecycle", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("X-Laneboss-Presence") != "simulated" ||
		w.Header().Get("X-Laneboss-Human-Approval") != "not_proven" {
		t.Fatal("session-dependent read lost simulated presence")
	}
	session.SimulatedPresence = false
	if _, err := s.trackHumanSession(context.Background(), scope, session); err == nil {
		t.Fatal("session reply lost verified simulated presence")
	}
}

func TestDashControlsOwner(t *testing.T) {
	for _, name := range []string{"start", "input"} {
		t.Run(name, func(t *testing.T) {
			h, s := draft4Fixture(t)
			_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
			method := api.Method("lane." + name)
			var params any
			if name == "start" {
				params = api.StartRequest{Lane: "new-lane", ProjectID: "project", Level: 6, Role: "top", RootTicketID: "fixture-ticket",
					Driver: api.DriverCodex, Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{},
						Secrets: []api.SecretDelegation{}, Profiles: []api.ProfileDelegation{}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
			} else {
				params = api.AttachInputRequest{Target: api.LifeRef{LifeID: "fixture-life", Run: 1}, ChannelID: "input-channel",
					Input: []byte("input"), Columns: 80, Rows: 24}
			}
			req, _, err := newReadRequest("cfg-dash", method, params)
			if err != nil {
				t.Fatal(err)
			}
			if name == "input" {
				req.Proof = &api.ProofRef{ID: "fixture-proof", RequestSHA256: req.RequestSHA256, ExpiresAt: api.Timestamp(h.clock.Now().Add(time.Minute).Format(time.RFC3339Nano))}
			}
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			transport := &observedTransport{HumanTransport: h, fail: api.NotImplemented("lb-v2-lifecycle", string(method))}
			s.deps.Transport = transport
			r := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8443/api/v2/rpc", bytes.NewReader(raw))
			r.Header.Set("Origin", "https://127.0.0.1:8443")
			r.Header.Set("Content-Type", "application/json")
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			var response api.Response
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusServiceUnavailable || transport.calls != 1 || response.Error == nil || response.Error.Owner != "lb-v2-lifecycle" {
				t.Fatal("lane control did not reach its service owner")
			}
		})
	}
}

func TestDashCaptureRefusal(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	h.lanes["life-refused"] = api.Lane{LifeID: "life-refused", Level: 3, Run: 1}
	binding := api.CaptureBinding{ID: "capture-refused", Config: "cfg-dash", Target: api.LifeRef{LifeID: "life-refused", Run: 1},
		Status: "refused", Refusal: &api.Error{Code: api.CodeUnavailable}, Streams: []api.CaptureStreamBinding{}}
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	h.appendEvent(api.Event{Kind: "capture.refused", Origin: "service", LifeID: "life-refused", Run: 1, Payload: raw})
	view, err := s.DashboardRaw(context.Background(), scope, api.DashboardQuery{Limit: 10})
	if err != nil || len(view.Gaps) != 2 || len(view.Records) != 0 {
		t.Fatalf("refused capture disappeared from raw coverage: %v", err)
	}
	for _, gap := range view.Gaps {
		if gap.BindingID != binding.ID || gap.Target != binding.Target || gap.EndOffset != nil {
			t.Fatal("refused capture invented measured bytes")
		}
	}
}

func TestDashReviewCoverage(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	h.lanes["life-reviewed"] = api.Lane{LifeID: "life-reviewed", Level: 3, Run: 1}
	raw, err := json.Marshal(api.ReviewReceipt{ID: "historical-review", Coverage: api.CoverageComplete})
	if err != nil {
		t.Fatal(err)
	}
	h.appendEvent(api.Event{Kind: "lane.reviewed", Origin: "service", LifeID: "life-reviewed", Run: 1, Payload: raw})
	view, err := s.DashboardRefusals(context.Background(), scope, api.DashboardQuery{Limit: 10})
	if err != nil || len(view.Counts) != 1 || !view.Counts[0].UnknownCoverage {
		t.Fatalf("historical review was shown as verified coverage: %v", err)
	}
}

func TestDashCookieRefresh(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	h.clock.Advance(4 * time.Minute)
	req, _, err := newReadRequest("cfg-dash", "operation.get", api.OperationGetRequest{OperationID: "fixture-operation"})
	if err != nil {
		t.Fatal(err)
	}
	scope = fixtureRequestScope(scope, req)
	if err := h.Authorize(context.Background(), scope, req); err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(2 * time.Minute)
	r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/lifecycle", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("cached idle deadline expired a live session: %d", w.Code)
	}
}

func TestDashSessionReplay(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, original, token := h.establishVerifiedScope(t, s, "cfg-dash")
	h.clock.Advance(4 * time.Minute)
	req, _, err := newReadRequest("cfg-dash", "operation.get", api.OperationGetRequest{OperationID: "fixture-operation"})
	if err != nil {
		t.Fatal(err)
	}
	scope = fixtureRequestScope(scope, req)
	if err := h.Authorize(context.Background(), scope, req); err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(2 * time.Minute)
	replayed, err := s.trackHumanSession(context.Background(), scope, original)
	if err != nil || replayed != token {
		t.Fatalf("retained session reply lost current authority: %v", err)
	}
}

func TestDashSSEDispatch(t *testing.T) {
	h, s := draft4Fixture(t)
	_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	transport := &observedTransport{HumanTransport: h, fail: api.NotImplemented("lb-v2-lifecycle", "event.tail")}
	s.deps.Transport = transport
	r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/events?follow=false", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || transport.calls != 1 {
		t.Fatal("SSE bypassed the event service dispatcher")
	}
	var response api.Response
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusServiceUnavailable || transport.calls != 1 || response.Error == nil || response.Error.Owner != "lb-v2-lifecycle" {
		t.Fatal("SSE bypassed the event service dispatcher")
	}
}
