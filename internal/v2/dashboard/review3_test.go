package dashboard

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func reviewRPC(t *testing.T, s *Service, token string, req api.Request) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8443/api/v2/rpc", bytes.NewReader(raw))
	r.Header.Set("Origin", "https://127.0.0.1:8443")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if token != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func reviewFrames(t *testing.T, raw string) []api.StreamFrame {
	t.Helper()
	var frames []api.StreamFrame
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var frame api.StreamFrame
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &frame); err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	return frames
}

func TestDashServiceEvent(t *testing.T) {
	h, s := draft4Fixture(t)
	_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	h.lanes["life-event"] = api.Lane{LifeID: "life-event", Run: 1, State: "running", Generation: 1}
	reason := h.putBlob("event-stop-reason", "task", []byte("stop to verify event delivery"))
	req, _ := h.issueProofFor(t, "cfg-dash", "lane.stop", "life-event", 1,
		api.StopRequest{Target: api.LifeRef{LifeID: "life-event", Run: 1}, ExpectedGeneration: 1, Reason: reason})
	if w := reviewRPC(t, s, token, req); w.Code != http.StatusOK {
		t.Fatalf("event stop setup failed: %d %s", w.Code, w.Body.String())
	}
	read, _, err := newReadRequest("cfg-dash", "lane.status", api.LifeRef{LifeID: "life-event", Run: 1})
	if err != nil {
		t.Fatal(err)
	}
	w := reviewRPC(t, s, token, read)
	var response api.Response
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	var lane api.Lane
	if err := json.Unmarshal(response.Result, &lane); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || lane.State != "verifying" || lane.LastSeq == 0 {
		t.Fatal("service event read-back did not reach stopped lane")
	}
	r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/events?life_id=life-event&run=1&until=lane.state&follow=false", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var delivered bool
	for _, frame := range reviewFrames(t, w.Body.String()) {
		if frame.End || frame.Error != nil {
			continue
		}
		ev := frame.Event
		if ev == nil || ev.Kind != "lane.state" || ev.Origin != "service" || ev.LifeID != lane.LifeID || ev.Run != lane.Run || ev.ID == "" || ev.Seq == 0 || ev.Seq > lane.LastSeq {
			continue
		}
		var change struct {
			From       string         `json:"from"`
			To         string         `json:"to"`
			Generation api.Generation `json:"generation"`
		}
		if err := json.Unmarshal(ev.Payload, &change); err != nil {
			t.Fatal(err)
		}
		delivered = change.From == "running" && change.To == lane.State && change.Generation == lane.Generation
	}
	if w.Code != 200 || !delivered {
		t.Fatal("cookie SSE lost the service state event")
	}
}

func TestDashUnconfiguredPins(t *testing.T) {
	h := newMemHarness()
	s, err := New(Dependencies{Store: h, Human: h.human(), Lifecycle: h, Messaging: h, Approval: h, Transport: h})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/api/v2/rpc", "/enroll"} {
		r := httptest.NewRequest(http.MethodPost, "http://evil.example:8443"+path, strings.NewReader(`{}`))
		r.Header.Set("Origin", "http://evil.example:8443")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		var response api.Response
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if w.Code != 503 || response.Error == nil || response.Error.Code != api.CodePrerequisite || response.Error.Owner != ownerName {
			t.Fatal("unconfigured HTTP pins admitted a request")
		}
	}
}

func TestDashHTTPSPins(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1:8443", "https://127.0.0.1:8443?x=y", "https://user" + "@" + "127.0.0.1:8443", "https://127.0.0.1:8443#fragment"} {
		h := newMemHarness()
		s, err := New(Dependencies{Store: h, Human: h.human(), Lifecycle: h, Messaging: h, Approval: h})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ConfigureHTTP("cfg-dash", origin, "127.0.0.1"); err == nil {
			t.Fatal("HTTP pins accepted an insecure or ambiguous origin")
		}
	}
	_, s := draft4Fixture(t)
	if err := s.ConfigureHTTP("cfg-dash", "https://127.0.0.1:8443", "foreign.example"); err == nil {
		t.Fatal("HTTP pins accepted a foreign RP")
	}
}

func TestDashPollRate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deadline time.Duration
		calls    int
	}{
		{"initial", 220 * time.Millisecond, 1},
		{"follow", 2200 * time.Millisecond, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The real handler, ticker and context deadline share synctest's
			// virtual clock. Host load cannot advance this clock during work.
			synctest.Test(t, func(t *testing.T) {
				h, s := draft4Fixture(t)
				_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
				trace := &observedTransport{HumanTransport: h}
				s.deps.Transport = trace
				r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/events?follow=true&deadline_ms="+strconv.FormatInt(tc.deadline.Milliseconds(), 10), nil)
				r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
				w := httptest.NewRecorder()
				started := time.Now()
				s.ServeHTTP(w, r)
				frames := reviewFrames(t, w.Body.String())
				if w.Code != http.StatusOK || len(frames) != 1 || !frames[0].End || frames[0].Event != nil ||
					frames[0].Error == nil || frames[0].Error.Code != api.CodeDeadline {
					t.Fatalf("SSE deadline lost its typed terminal frame: status=%d body=%s", w.Code, w.Body.String())
				}
				if trace.calls != tc.calls || len(trace.pollTimes) != tc.calls || time.Since(started) != tc.deadline {
					t.Fatalf("passive SSE exceeded its bounded polling rate: calls=%d want=%d elapsed=%s want=%s", trace.calls, tc.calls, time.Since(started), tc.deadline)
				}
				for index, at := range trace.pollTimes {
					if index == 0 {
						if !at.Equal(started) {
							t.Fatal("passive SSE exceeded its bounded polling rate: initial poll was delayed")
						}
						continue
					}
					if at.Sub(trace.pollTimes[index-1]) < time.Second {
						t.Fatalf("passive SSE exceeded its bounded polling rate: poll gap=%s", at.Sub(trace.pollTimes[index-1]))
					}
				}
			})
		})
	}
}

func TestDashExpiredDispatch(t *testing.T) {
	h, s := draft4Fixture(t)
	_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	params := api.MailSendRequest{RecipientLifeID: "life-expired", Content: api.BlobRef{ID: "content", SHA256: api.Digest(strings.Repeat("a", 64)), Bytes: 1, Class: "prompt"}}
	req, proof := h.issueProofFor(t, "cfg-dash", "mail.send", params.RecipientLifeID, 0, params)
	proof.ExpiresAt = api.Timestamp(h.clock.Now().Format(time.RFC3339Nano))
	trace := &observedTransport{HumanTransport: h}
	s.deps.Transport = trace
	w := reviewRPC(t, s, token, req)
	if w.Code != 403 || trace.calls != 0 {
		t.Fatal("expired proof reached normal mutation dispatch")
	}
}

func TestDashExpiredReplay(t *testing.T) {
	h, s := draft4Fixture(t)
	_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	h.lanes["life-replay"] = api.Lane{LifeID: "life-replay", Run: 1, State: "running", Generation: 1}
	reason := h.putBlob("replay-stop", "task", []byte("stop once"))
	req, _ := h.issueProofFor(t, "cfg-dash", "lane.stop", "life-replay", 1, api.StopRequest{Target: api.LifeRef{LifeID: "life-replay", Run: 1}, ExpectedGeneration: 1, Reason: reason})
	first := reviewRPC(t, s, token, req)
	if first.Code != 200 {
		t.Fatalf("replay setup failed: %s", first.Body.String())
	}
	expires, err := parseTimestamp(req.Proof.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(expires.Sub(h.clock.Now()))
	second := reviewRPC(t, s, token, req)
	if second.Code != 200 || first.Body.String() != second.Body.String() || len(h.stoppedLives) != 1 {
		t.Fatal("completed receipt was lost at proof expiry")
	}
	req.IdempotencyKey = "new-uncommitted-receipt-001"
	if w := reviewRPC(t, s, token, req); w.Code != 403 {
		t.Fatal("expired proof started an uncommitted operation")
	}
}

func TestDashTokenLifecycle(t *testing.T) {
	t.Run("replacement", func(t *testing.T) {
		h, s := draft4Fixture(t)
		_, hs, oldToken := h.establishVerifiedScope(t, s, "cfg-dash")
		scope := h.newFixtureScope("cfg-dash")
		stored := h.readSessions[hs.ID]
		stored.PrincipalID, stored.ConnectionID = scope.Actor.ID, scope.Connection.ID()
		h.readSessions[hs.ID] = stored
		if err := scope.Connection.BindReadAuthority(api.ReadAuthorityFromSession(stored)); err != nil {
			t.Fatal(err)
		}
		req, _, err := newReadRequest("cfg-dash", "dashboard.tree", api.DashboardQuery{})
		if err != nil {
			t.Fatal(err)
		}
		scope = fixtureRequestScope(scope, req)
		newToken, err := s.trackHumanSession(context.Background(), scope, hs)
		if err != nil {
			t.Fatal(err)
		}
		if newToken == oldToken || s.sessionsByToken[oldToken] != nil || len(s.sessionsByToken) != 1 {
			t.Fatal("replaced session retained its old cookie token")
		}
	})
	t.Run("sweep", func(t *testing.T) {
		h, s := draft4Fixture(t)
		_, old, oldToken := h.establishVerifiedScope(t, s, "cfg-dash")
		_, revoked, _ := h.establishVerifiedScope(t, s, "cfg-dash")
		s.RevokeSession(revoked.ID)
		h.clock.Advance(30 * time.Minute)
		h.establishVerifiedScope(t, s, "cfg-dash")
		if s.sessionsByToken[oldToken] != nil || s.sessionsByID[old.ID] != nil || len(s.revokedSessions) != 0 || len(s.sessionsByToken) != 1 {
			t.Fatal("absolute-expired session or revocation survived sweep")
		}
	})
}

func TestDashCursorMAC(t *testing.T) {
	_, s := draft4Fixture(t)
	raw := []byte(`{"cursor":"payload"}`)
	mac := hmac.New(sha256.New, s.cursorKey[:])
	_, _ = mac.Write(raw)
	if s.hmacSign(raw) != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("SSE cursor did not use HMAC-SHA256")
	}
}

func TestDashCursorReconnect(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	cursor := s.buildSSECursor(scope, api.EventTailRequest{}, 7)
	r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/events?since=2&follow=false", nil)
	r.Header.Set("Last-Event-ID", cursor)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"end":true`) {
		t.Fatal("EventSource reconnect rejected its original since offset")
	}
}

type filteredPoll struct {
	HumanTransport
	since []api.Sequence
}

func (p *filteredPoll) PollEvents(_ context.Context, _ api.Scope, req api.EventTailRequest) (api.EventPage, error) {
	p.since = append(p.since, req.Since)
	ev := api.Event{Seq: 8, ID: "filtered", Origin: "service", Kind: "lane.state", LifeID: "other", Run: 1, Payload: json.RawMessage(`{"to":"running"}`)}
	if req.Since >= 8 {
		ev.Seq, ev.ID, ev.LifeID = 9, "selected", "target"
	}
	return api.EventPage{Events: []api.Event{ev}}, nil
}
func TestDashFilteredPage(t *testing.T) {
	h, s := draft4Fixture(t)
	_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	p := &filteredPoll{HumanTransport: h}
	s.deps.Transport = p
	r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/events?life_id=target&until=lane.state&follow=true&deadline_ms=5000", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || len(p.since) != 2 || p.since[1] != 8 || !strings.Contains(w.Body.String(), `"id":"selected"`) {
		t.Fatal("filtered event page stalled the SSE read position")
	}
}

func TestDashUnknownRoute(t *testing.T) {
	_, s := draft4Fixture(t)
	s.deps.Transport = nil
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/anything", nil))
	if w.Code != 404 {
		t.Fatal("unknown route reached the human transport")
	}
}

func TestDashScopeCount(t *testing.T) {
	h, s := draft4Fixture(t)
	_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	trace := &observedTransport{HumanTransport: h}
	s.deps.Transport = trace
	r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/tree?limit=7", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || trace.scopes != 1 || trace.calls != 1 {
		t.Fatal("dashboard view repeated its human scope round trip")
	}
}

func TestDashCSPHeader(t *testing.T) {
	_, s := draft4Fixture(t)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/", nil))
	_, after, ok := strings.Cut(w.Header().Get("Content-Security-Policy"), "script-src ")
	sources, _, closed := strings.Cut(after, ";")
	if w.Code != 200 || !ok || !closed || !strings.Contains(sources, "'sha256-") || strings.Contains(sources, "unsafe-inline") {
		t.Fatal("HTTP script CSP permitted unpinned inline code")
	}
}

func TestDashCookieOnly(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	scope = fixtureEventScope(t, scope, api.EventTailRequest{})
	_, err := s.sseBatch(context.Background(), idleRequest(token), scope, "", api.EventTailRequest{}, 0)
	if err == nil || asAPIError(err).Code != api.CodeUnauthenticated {
		t.Fatal("SSE accepted the cookieless helper path")
	}
}

func TestDashEnrollmentOwner(t *testing.T) {
	_, s := draft4Fixture(t)
	r := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8443/api/v2/enrollment/begin", strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://127.0.0.1:8443")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var response api.Response
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != 503 || response.Error == nil || response.Error.Code != api.CodeNotImplemented || response.Error.Owner != "lb-v2-service" {
		t.Fatal("unwired browser enrollment lost its protected owner failure")
	}
}
