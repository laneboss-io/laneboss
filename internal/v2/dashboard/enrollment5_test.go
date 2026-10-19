package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This models protected ceremony scheduling and opaque-byte forwarding only.
// Cryptographic verification remains in identity and its separate integration
// test; these bytes are not an authenticator or installed-service claim.
type ceremonyTrace struct {
	mu                  sync.Mutex
	clock               *fakeClock
	ceremony            api.EnrollmentCeremonyRequest
	challenge           api.EnrollmentChallenge
	client, attestation []byte
	begins, calls       int
	entered, release    chan struct{}
	failure             error
	alter               func(*api.EnrollmentReceipt)
}

func (g *ceremonyTrace) AuthorizeEnrollment(_ context.Context, request *http.Request) (api.EnrollmentCeremonyRequest, error) {
	if cookie, err := request.Cookie("admin_fixture"); err != nil || cookie.Value != "owner-opened" {
		return api.EnrollmentCeremonyRequest{}, forbiddenErr("fixture owner ceremony is absent", "Open the protected ceremony.")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ceremony, nil
}

func (g *ceremonyTrace) BeginHumanEnrollment(_ context.Context, request api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if request != g.ceremony {
		return api.EnrollmentChallenge{}, forbiddenErr("fixture ceremony changed", "Open a current ceremony.")
	}
	g.begins++
	nonce := sha256.Sum256([]byte(string(request.CeremonyID) + strconv.Itoa(g.begins)))
	g.challenge = api.EnrollmentChallenge{ID: api.ID("challenge-" + strconv.Itoa(g.begins)), Ceremony: request, Challenge: nonce[:], Origin: "https://127.0.0.1:8443", RPID: "127.0.0.1", EndpointGeneration: 1, InstallationGeneration: 1, ExpiresAt: api.Timestamp(g.clock.Now().Add(2 * time.Minute).Format(time.RFC3339Nano))}
	return g.challenge, nil
}

func (g *ceremonyTrace) CompleteHumanEnrollment(_ context.Context, request api.EnrollmentValidationRequest) (api.EnrollmentReceipt, error) {
	g.mu.Lock()
	g.calls++
	call := g.calls
	challenge, failure, alter := g.challenge, g.failure, g.alter
	if request.Ceremony != g.ceremony || request.ChallengeID != challenge.ID || request.AttestationMarker != "" || !bytes.Equal(request.ClientDataJSON, g.client) || !bytes.Equal(request.AttestationObject, g.attestation) {
		g.mu.Unlock()
		return api.EnrollmentReceipt{}, invalidErr("fixture registration bytes changed", "Preserve the browser response.")
	}
	g.mu.Unlock()
	if call == 1 && g.entered != nil {
		close(g.entered)
		<-g.release
	}
	if call > 1 {
		return api.EnrollmentReceipt{}, conflictErr("fixture challenge was already forwarded", "Begin another ceremony.")
	}
	if failure != nil {
		return api.EnrollmentReceipt{}, failure
	}
	digest := sha256.Sum256(append(append([]byte(nil), request.ClientDataJSON...), request.AttestationObject...))
	id := hex.EncodeToString(digest[:16])
	receipt := api.EnrollmentReceipt{CeremonyID: request.Ceremony.CeremonyID, ChallengeID: challenge.ID, PrincipalID: request.Ceremony.PrincipalID, Config: request.Ceremony.Config, Generation: 1,
		Evidence: api.BlobRef{ID: api.ID("evidence-" + id), SHA256: api.Digest(hex.EncodeToString(digest[:])), Bytes: int64(len(g.client) + len(g.attestation)), Class: "artifact"}, OperationID: api.ID("operation-" + id), EventID: api.ID("event-" + id), CommittedSeq: api.Sequence(call)}
	if alter != nil {
		alter(&receipt)
	}
	return receipt, nil
}

func ceremonyFixture(t *testing.T) (*Service, *ceremonyTrace) {
	t.Helper()
	h, s := draft4Fixture(t)
	g := &ceremonyTrace{clock: h.clock, ceremony: api.EnrollmentCeremonyRequest{Config: "cfg-dash", CeremonyID: "ceremony", PrincipalID: "owner"}, client: []byte("opaque-client-registration"), attestation: []byte("opaque-attestation-statement")}
	digest := sha256.Sum256([]byte("fixture helper"))
	endpoint := api.AdminEnrollmentEndpoint{Config: "cfg-dash", Socket: "/run/fixture-enrollment.sock", ServiceUID: 1001, InstallationGeneration: 1, Origin: "https://127.0.0.1:8443", RPID: "127.0.0.1", Helper: api.Executable{ID: "fixture-helper", SHA256: api.Digest(hex.EncodeToString(digest[:])), Version: "fixture"}}
	if err := s.ConfigureEnrollment(endpoint, g); err != nil {
		t.Fatal(err)
	}
	return s, g
}

func ceremonyCall(s *Service, method string, body []byte, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8443/api/v2/enrollment/"+method, bytes.NewReader(body))
	r.Header.Set("Origin", "https://127.0.0.1:8443")
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "admin_fixture", Value: "owner-opened"})
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func beginCeremony(t *testing.T, s *Service) *http.Cookie {
	t.Helper()
	w := ceremonyCall(s, "begin", []byte(`{}`), nil)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("ceremony setup failed: %d %s", w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0]
}

func TestDashEnrollRetry(t *testing.T) {
	s, g := ceremonyFixture(t)
	var cookie *http.Cookie
	for attempt := 0; attempt < 24; attempt++ {
		prior := cookie
		if attempt%3 == 0 {
			g.ceremony.CeremonyID = api.ID("ceremony-" + strconv.Itoa(attempt))
		} else if attempt%2 == 0 {
			prior = nil
		}
		w := ceremonyCall(s, "begin", []byte(`{}`), prior)
		if w.Code != 200 || len(w.Result().Cookies()) != 1 || len(s.enrollments) != 1 {
			t.Fatal("enrollment retries exhausted browser ceremony capacity")
		}
		cookie = w.Result().Cookies()[0]
	}
}

func TestDashEnrollConsume(t *testing.T) {
	s, g := ceremonyFixture(t)
	cookie := beginCeremony(t, s)
	g.entered, g.release = make(chan struct{}), make(chan struct{})
	body := reviewJSON(t, map[string]any{"client_data_json": g.client, "attestation_object": g.attestation})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- ceremonyCall(s, "complete", body, cookie) }()
	select {
	case <-g.entered:
	case <-time.After(2 * time.Second):
		close(g.release)
		<-done
		t.Fatal("ceremony did not reach protected completion")
	}
	second := ceremonyCall(s, "complete", body, cookie)
	close(g.release)
	first := <-done
	if first.Code != 200 || second.Code != 401 || g.calls != 1 || len(s.enrollments) != 0 {
		t.Fatal("enrollment challenge was forwarded more than once")
	}
	for _, reply := range []*httptest.ResponseRecorder{first, second} {
		if len(reply.Result().Cookies()) != 1 || reply.Result().Cookies()[0].MaxAge >= 0 {
			t.Fatal("enrollment attempt retained its ceremony cookie")
		}
	}
	if first.Header().Get("X-Laneboss-Human-Approval") != "not_proven" || first.Header().Get("X-Laneboss-Presence") != "not_proven" {
		t.Fatal("enrollment completion lost presence reporting")
	}
}

func TestDashEnrollFailure(t *testing.T) {
	s, g := ceremonyFixture(t)
	cookie := beginCeremony(t, s)
	g.failure = api.NotImplemented("lb-v2-service", "fixture completion unavailable")
	body := reviewJSON(t, map[string]any{"client_data_json": g.client, "attestation_object": g.attestation})
	first := ceremonyCall(s, "complete", body, cookie)
	second := ceremonyCall(s, "complete", body, cookie)
	if first.Code != 503 || second.Code != 401 || g.calls != 1 || len(s.enrollments) != 0 {
		t.Fatal("failed enrollment completion remained reusable")
	}
}

func TestDashEnrollReceipt(t *testing.T) {
	for _, field := range []string{"operation", "event", "blob", "class", "size", "simulated"} {
		t.Run(field, func(t *testing.T) {
			s, g := ceremonyFixture(t)
			cookie := beginCeremony(t, s)
			g.alter = func(receipt *api.EnrollmentReceipt) {
				switch field {
				case "operation":
					receipt.OperationID = "invalid/id"
				case "event":
					receipt.EventID = "invalid/id"
				case "blob":
					receipt.Evidence.ID = "invalid/id"
				case "class":
					receipt.Evidence.Class = "record"
				case "size":
					receipt.Evidence.Bytes = api.MaxObjectBytes + 1
				case "simulated":
					receipt.SimulatedPresence = true
				}
			}
			w := ceremonyCall(s, "complete", reviewJSON(t, map[string]any{"client_data_json": g.client, "attestation_object": g.attestation}), cookie)
			if w.Code != 500 || len(s.enrollments) != 0 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge >= 0 {
				t.Fatal("enrollment accepted an invalid receipt binding")
			}
		})
	}
}
