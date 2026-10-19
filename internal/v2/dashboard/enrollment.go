package dashboard

import (
	"context"
	"crypto/sha256"
	"io"
	"mime"
	"net/http"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	webv2 "laneboss.io/laneboss/web/v2"
)

// BrowserEnrollmentTransport is installed by the service, backed by the fixed
// admin helper's private control channel. AuthorizeEnrollment must require a
// current owner-only helper-opened ceremony, bound to this browser. Origin,
// a query parameter, possession of this page or a public human RPC is not that
// authorization. Both calls recheck the protected installation and absent
// enrollment baseline. This port must never invoke a caller-selected executable.
type BrowserEnrollmentTransport interface {
	api.AdminEnrollment
	AuthorizeEnrollment(context.Context, *http.Request) (api.EnrollmentCeremonyRequest, error)
}

type browserEnrollment struct {
	challenge api.EnrollmentChallenge
	expires   time.Time
}

// ConfigureEnrollment consumes the protected installed admin_enrollment record,
// never browser data. The service owns authenticating the administrative channel.
func (s *Service) ConfigureEnrollment(endpoint api.AdminEnrollmentEndpoint, transport BrowserEnrollmentTransport) error {
	if err := api.ValidateAdminEnrollmentEndpoint(endpoint); err != nil {
		return err
	}
	if transport == nil {
		return invalidErr("protected enrollment transport is required", "Bind the installed administrator ceremony.")
	}
	if err := s.ConfigureHTTP(endpoint.Config, endpoint.Origin, endpoint.RPID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enrollmentTransport != nil {
		return conflictErr("enrollment transport is already installed", "Use the existing protected ceremony.")
	}
	s.enrollmentEndpoint, s.enrollmentTransport = endpoint, transport
	s.enrollments = make(map[string]browserEnrollment)
	return nil
}

func (s *Service) handleEnrollment(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeErrorResponse(w, "", invalidErr("enrollment query parameters are forbidden", "Use the protected ceremony."))
		return
	}
	if r.URL.Path == "/enroll" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(webv2.EnrollmentPage())
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/api/v2/enrollment/begin" && r.URL.Path != "/api/v2/enrollment/complete" {
		writeErrorResponse(w, "", invalidErr("invalid enrollment route or method", "Use the enrollment page."))
		return
	}
	if r.URL.Path == "/api/v2/enrollment/complete" {
		http.SetCookie(w, &http.Cookie{Name: "laneboss_enrollment", Path: "/api/v2/enrollment", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeErrorResponse(w, "", invalidErr("enrollment requires JSON", "Use the enrollment page."))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, api.MaxFrameBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > api.MaxFrameBytes {
		writeErrorResponse(w, "", invalidErr("invalid enrollment frame size", "Use the enrollment page."))
		return
	}
	s.mu.Lock()
	endpoint, transport := s.enrollmentEndpoint, s.enrollmentTransport
	for token, enrollment := range s.enrollments {
		if !s.now().Before(enrollment.expires) {
			delete(s.enrollments, token)
		}
	}
	s.mu.Unlock()
	if transport == nil {
		writeErrorResponse(w, "", api.NotImplemented("lb-v2-service", "protected browser enrollment ceremony"))
		return
	}
	ceremony, err := transport.AuthorizeEnrollment(r.Context(), r)
	if err != nil {
		writeErrorResponse(w, "", err)
		return
	}
	if ceremony.Config != endpoint.Config || ceremony.ExpectedGeneration != 0 {
		writeErrorResponse(w, "", forbiddenErr("browser enrollment requires the protected absent baseline", "Use the administrator helper or existing human approval path."))
		return
	}
	if r.URL.Path == "/api/v2/enrollment/begin" {
		var empty api.Empty
		if err := api.DecodeObject(raw, &empty); err != nil {
			writeErrorResponse(w, "", err)
			return
		}
		challenge, err := transport.BeginHumanEnrollment(r.Context(), ceremony)
		if err != nil {
			writeErrorResponse(w, "", err)
			return
		}
		if err := api.ValidateEnrollmentChallenge(challenge, ceremony, s.now()); err != nil {
			writeErrorResponse(w, "", err)
			return
		}
		if challenge.Origin != endpoint.Origin || challenge.RPID != endpoint.RPID || challenge.InstallationGeneration != endpoint.InstallationGeneration {
			writeErrorResponse(w, "", integrityErr("enrollment challenge differs from protected installation", "Inspect the administrator ceremony."))
			return
		}
		challenge.Challenge = append([]byte(nil), challenge.Challenge...)
		token, err := randomHex(32)
		if err != nil {
			writeErrorResponse(w, "", err)
			return
		}
		expires, _ := parseTimestamp(challenge.ExpiresAt)
		s.mu.Lock()
		prior, _ := r.Cookie("laneboss_enrollment")
		for existing, entry := range s.enrollments {
			if prior != nil && existing == prior.Value || entry.challenge.Ceremony.CeremonyID == ceremony.CeremonyID {
				delete(s.enrollments, existing)
			}
		}
		if len(s.enrollments) >= 16 {
			s.mu.Unlock()
			writeErrorResponse(w, "", unavailableErr("too many open enrollment ceremonies", "Complete or let existing ceremonies expire."))
			return
		}
		s.enrollments[token] = browserEnrollment{challenge: challenge, expires: expires}
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "laneboss_enrollment", Value: token, Path: "/api/v2/enrollment", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(expires.Sub(s.now()) / time.Second)})
		userHandle := sha256.Sum256([]byte("laneboss-enrollment-user\x00" + endpoint.Config + "\x00" + string(ceremony.PrincipalID)))
		writeJSONResult(w, struct {
			Challenge []byte `json:"challenge"`
			Origin    string `json:"origin"`
			RPID      string `json:"rp_id"`
			UserID    []byte `json:"user_id"`
		}{challenge.Challenge, endpoint.Origin, endpoint.RPID, userHandle[:]})
		return
	}
	// This closed body has no marker, principal, RP, origin or challenge selector.
	var body struct {
		ClientDataJSON    []byte `json:"client_data_json"`
		AttestationObject []byte `json:"attestation_object"`
	}
	if err := api.DecodeObject(raw, &body); err != nil {
		writeErrorResponse(w, "", err)
		return
	}
	if len(body.ClientDataJSON) == 0 || len(body.AttestationObject) == 0 {
		writeErrorResponse(w, "", invalidErr("registration bytes are required", "Use a real security key in the enrollment page."))
		return
	}
	cookie, err := r.Cookie("laneboss_enrollment")
	if err != nil {
		writeErrorResponse(w, "", unauthErr("missing enrollment ceremony cookie", "Begin the protected enrollment ceremony."))
		return
	}
	s.mu.Lock()
	enrollment, ok := s.enrollments[cookie.Value]
	valid := ok && s.now().Before(enrollment.expires) && reflect.DeepEqual(enrollment.challenge.Ceremony, ceremony)
	if valid {
		delete(s.enrollments, cookie.Value)
	}
	s.mu.Unlock()
	if !valid {
		writeErrorResponse(w, "", unauthErr("enrollment ceremony expired or changed", "Begin the protected enrollment ceremony."))
		return
	}
	request := api.EnrollmentValidationRequest{Ceremony: ceremony, ChallengeID: enrollment.challenge.ID,
		ClientDataJSON: body.ClientDataJSON, AttestationObject: body.AttestationObject}
	receipt, err := transport.CompleteHumanEnrollment(r.Context(), request)
	if err != nil {
		writeErrorResponse(w, "", err)
		return
	}
	if receipt.SimulatedPresence || receipt.CeremonyID != ceremony.CeremonyID || receipt.ChallengeID != request.ChallengeID ||
		receipt.Config != endpoint.Config || receipt.PrincipalID != ceremony.PrincipalID || receipt.Generation != 1 ||
		receipt.CommittedSeq == 0 || !validID(receipt.OperationID) || !validID(receipt.EventID) || !validID(receipt.Evidence.ID) ||
		!validDigest(receipt.Evidence.SHA256) || receipt.Evidence.Bytes <= 0 || receipt.Evidence.Bytes > api.MaxObjectBytes || receipt.Evidence.Class != "artifact" {
		writeErrorResponse(w, "", integrityErr("enrollment receipt lacks real registration provenance", "Inspect the identity and administrator ceremony."))
		return
	}
	writeJSONResult(w, receipt)
}
