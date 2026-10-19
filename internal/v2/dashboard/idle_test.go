package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestDashDecisionJSON(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	ref := h.putDecisionDocument(t, "decision-doc", "Retain strict decision fields", "2026-10-16T11:50:00Z", true)
	candidate, err := s.decodeDecisionRecord(context.Background(), scope,
		api.Record{ID: "decision", Content: ref, Generation: 1, Actor: api.Actor{Kind: "human", ID: scope.Actor.ID}})
	if err != nil || candidate.Text != "Retain strict decision fields" || !candidate.Binding ||
		candidate.EffectiveAt != "2026-10-16T11:50:00Z" || candidate.AppliesTo.Levels == nil {
		t.Fatalf("decision fixture violated strict document shape: %v", err)
	}
	partial := h.putBlob("decision-partial", "record", []byte(`{"id":"decision","text":"partial","effective_at":"2026-10-16T11:50:00Z","binding":true}`))
	_, err = s.decodeDecisionRecord(context.Background(), scope, api.Record{ID: "decision", Content: partial})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
		t.Fatal("partial decision JSON escaped strict decoding")
	}
}

func idleRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/events?follow=false", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	return r
}

func sessionFact(t *testing.T, h *memHarness, scope api.Scope, id api.ID) api.StoredReadSession {
	t.Helper()
	stored, err := h.ReadSession(context.Background(), scope, id)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func requireIdleRefusal(t *testing.T, err error) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
		t.Fatalf("passive SSE survived the committed idle deadline: %v", err)
	}
}

func TestDashSSEIdle(t *testing.T) {
	t.Run("passive", func(t *testing.T) {
		h, s := draft4Fixture(t)
		scope, session, token := h.establishVerifiedScope(t, s, "cfg-dash")
		before := sessionFact(t, h, scope, session.ID)
		authority, err := scope.Connection.ReadAuthority(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for poll := 0; poll < 4; poll++ {
			h.clock.Advance(time.Minute)
			events, err := s.sseBatch(context.Background(), idleRequest(token), scope, token, api.EventTailRequest{}, 0)
			if err != nil || len(events) != 0 {
				t.Fatalf("non-refreshing SSE poll failed before idle expiry: %v", err)
			}
			after := sessionFact(t, h, scope, session.ID)
			current, err := scope.Connection.ReadAuthority(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) || authority != current {
				t.Fatal("passive SSE refreshed durable read authority")
			}
		}
		h.clock.Advance(time.Minute)
		_, err = s.sseBatch(context.Background(), idleRequest(token), scope, token, api.EventTailRequest{}, 0)
		requireIdleRefusal(t, err)
	})
	t.Run("foreground", func(t *testing.T) {
		h, s := draft4Fixture(t)
		scope, session, token := h.establishVerifiedScope(t, s, "cfg-dash")
		before := sessionFact(t, h, scope, session.ID)
		h.clock.Advance(4 * time.Minute)
		r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/tree", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		after := sessionFact(t, h, scope, session.ID)
		if w.Code != http.StatusOK || after.Generation <= before.Generation || after.Session.IdleExpiresAt == before.Session.IdleExpiresAt ||
			after.Session.ExpiresAt != before.Session.ExpiresAt {
			t.Fatal("foreground read lost its bounded idle refresh")
		}
		h.clock.Advance(4 * time.Minute)
		if _, err := s.sseBatch(context.Background(), idleRequest(token), scope, token, api.EventTailRequest{}, 0); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(after, sessionFact(t, h, scope, session.ID)) {
			t.Fatal("passive SSE refreshed durable read authority")
		}
		h.clock.Advance(time.Minute)
		_, err := s.sseBatch(context.Background(), idleRequest(token), scope, token, api.EventTailRequest{}, 0)
		requireIdleRefusal(t, err)
	})
	t.Run("revoked", func(t *testing.T) {
		h, s := draft4Fixture(t)
		scope, session, token := h.establishVerifiedScope(t, s, "cfg-dash")
		h.revokeOnIdentitySide(session.ID)
		_, err := s.sseBatch(context.Background(), idleRequest(token), scope, token, api.EventTailRequest{}, 0)
		requireIdleRefusal(t, err)
	})
}

// This canary runs the old refreshing event.tail path intentionally. Its
// measured state is the control for TestDashSSEIdle, not a native-peer claim.
func TestDashSSERefreshCanary(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, session, token := h.establishVerifiedScope(t, s, "cfg-dash")
	before := sessionFact(t, h, scope, session.ID)
	h.clock.Advance(4 * time.Minute)
	req, raw, err := newReadRequest(scope.Config, "event.tail", api.EventTailRequest{})
	if err != nil {
		t.Fatal(err)
	}
	sessionClaim, err := s.authenticateCookie(context.Background(), idleRequest(token), false)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := s.httpScope(context.Background(), idleRequest(token), req, raw, sessionClaim)
	if err != nil {
		t.Fatal(err)
	}
	response, err := s.deps.Transport.Dispatch(context.Background(), bound, req)
	if err != nil || response.Error != nil {
		t.Fatalf("refreshing canary failed to reach event read: %v", err)
	}
	var page api.EventPage
	if err := api.DecodeObject(response.Result, &page); err != nil {
		t.Fatal(err)
	}
	after := sessionFact(t, h, scope, session.ID)
	if after.Generation <= before.Generation || after.Session.IdleExpiresAt == before.Session.IdleExpiresAt ||
		after.Session.ExpiresAt != before.Session.ExpiresAt {
		t.Fatal("refreshing canary did not demonstrate idle extension")
	}
	h.clock.Advance(2 * time.Minute)
	if _, err := s.authenticateCookie(context.Background(), idleRequest(token), false); err != nil {
		t.Fatalf("refreshing canary did not survive the original idle deadline: %v", err)
	}
}

type foregroundOnly struct{ HumanTransport }

func TestDashPollCapability(t *testing.T) {
	h, s := draft4Fixture(t)
	_, _, token := h.establishVerifiedScope(t, s, "cfg-dash")
	s.deps.Transport = foregroundOnly{h}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, idleRequest(token))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("SSE fell back to a refreshing dispatcher")
	}
	var response api.Response
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != api.CodeNotImplemented || response.Error.Owner != "lb-v2-service" {
		t.Fatal("missing non-refreshing poll lost its owning failure")
	}
}

func TestDashAbsoluteCap(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, session, token := h.establishVerifiedScope(t, s, "cfg-dash")
	started := h.clock.Now()
	absolute, err := parseTimestamp(session.ExpiresAt)
	if err != nil || !absolute.Equal(started.Add(30*time.Minute)) {
		t.Fatal("read session exceeded its thirty-minute absolute cap")
	}
	for step := 0; step < 7; step++ {
		h.clock.Advance(4 * time.Minute)
		r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/tree", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("foreground read expired before absolute cap: %d", w.Code)
		}
	}
	stored := sessionFact(t, h, scope, session.ID)
	idle, err := parseTimestamp(stored.Session.IdleExpiresAt)
	if err != nil || stored.Session.ExpiresAt != session.ExpiresAt || !idle.Equal(absolute) {
		t.Fatal("foreground refresh moved the absolute cap")
	}
	h.clock.Advance(2 * time.Minute)
	_, err = s.sseBatch(context.Background(), idleRequest(token), scope, token, api.EventTailRequest{}, 0)
	requireIdleRefusal(t, err)
}

// Isolate the dashboard deadline gate from PollEvents' independent check.
func TestDashIdleBoundary(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, _, _ := h.establishVerifiedScope(t, s, "cfg-dash")
	h.clock.Advance(5 * time.Minute)
	_, err := s.snapshotHumanScope(context.Background(), scope)
	requireIdleRefusal(t, err)
}

type idlePollTrace struct {
	HumanTransport
	polls chan struct{}
}

func (p idlePollTrace) PollEvents(ctx context.Context, scope api.Scope, tail api.EventTailRequest) (api.EventPage, error) {
	page, err := p.HumanTransport.(HumanLivenessTransport).PollEvents(ctx, scope, tail)
	if err == nil {
		select {
		case p.polls <- struct{}{}:
		default:
		}
	}
	return page, err
}

func TestDashStreamIdle(t *testing.T) {
	h, s := draft4Fixture(t)
	scope, session, token := h.establishVerifiedScope(t, s, "cfg-dash")
	before := sessionFact(t, h, scope, session.ID)
	polls := make(chan struct{}, 8)
	s.deps.Transport = idlePollTrace{HumanTransport: h, polls: polls}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8443/api/v2/events?follow=true", nil).WithContext(ctx)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); s.ServeHTTP(w, r) }()
	waitPoll := func() {
		t.Helper()
		select {
		case <-polls:
		case <-time.After(2 * time.Second):
			cancel()
			<-done
			t.Fatal("SSE stream did not reach its liveness poll")
		}
	}
	waitPoll()
	h.clock.Advance(4 * time.Minute)
	waitPoll()
	if !reflect.DeepEqual(before, sessionFact(t, h, scope, session.ID)) {
		cancel()
		<-done
		t.Fatal("SSE stream refreshed durable read authority")
	}
	h.clock.Advance(time.Minute)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("SSE stream survived its committed idle deadline")
	}
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `"code":"unauthenticated"`) || !strings.Contains(body, `"end":true`) {
		t.Fatal("SSE expiry did not emit an authenticated terminal error")
	}
}
