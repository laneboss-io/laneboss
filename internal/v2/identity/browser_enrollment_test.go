package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dashboard"
)

type browserUnused struct {
	// Enrollment routes must never invoke lifecycle; an accidental call fails
	// the test instead of importing the tagged native lifecycle test drivers.
	api.LifecycleAPI
}

func (browserUnused) MailSend(context.Context, api.Scope, api.MailSendRequest) (api.Mail, error) {
	return api.Mail{}, api.NotImplemented("lb-v2-messaging", "browser fixture MailSend")
}
func (browserUnused) MailList(context.Context, api.Scope, api.ListRequest) (api.MailPage, error) {
	return api.MailPage{}, api.NotImplemented("lb-v2-messaging", "browser fixture MailList")
}
func (browserUnused) ReportSubmit(context.Context, api.Scope, api.ReportRequest) (api.Mail, error) {
	return api.Mail{}, api.NotImplemented("lb-v2-messaging", "browser fixture ReportSubmit")
}
func (browserUnused) OrgChangePropose(context.Context, api.Scope, api.ChangeProposeRequest) (api.ChangeRequest, error) {
	return api.ChangeRequest{}, api.NotImplemented("lb-v2-approval", "browser fixture OrgChangePropose")
}
func (browserUnused) OrgChangeGet(context.Context, api.Scope, api.ChangeGetRequest) (api.ChangeRequest, error) {
	return api.ChangeRequest{}, api.NotImplemented("lb-v2-approval", "browser fixture OrgChangeGet")
}
func (browserUnused) OrgChangeApprove(context.Context, api.Scope, api.ChangeApproveRequest) (api.ChangeApproval, error) {
	return api.ChangeApproval{}, api.NotImplemented("lb-v2-approval", "browser fixture OrgChangeApprove")
}
func (browserUnused) OrgChangeApply(context.Context, api.Scope, api.ChangeApplyRequest) (api.ChangeReceipt, error) {
	return api.ChangeReceipt{}, api.NotImplemented("lb-v2-approval", "browser fixture OrgChangeApply")
}

// This models the missing service/admin transaction for adapter tests. Real
// registration verification is the production identity implementation below;
// neither these generated fixture keys nor this ledger prove physical presence.
type browserCeremony struct {
	identity *Service
	store    *fixtureStore
	grant    string
	input    api.EnrollmentValidationRequest
	receipts []api.EnrollmentReceipt
	deny     bool
}

func (b *browserCeremony) AuthorizeEnrollment(_ context.Context, r *http.Request) (api.EnrollmentCeremonyRequest, error) {
	cookie, err := r.Cookie("admin_ceremony")
	if err != nil || cookie.Value != b.grant || b.deny {
		return api.EnrollmentCeremonyRequest{}, &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-admin"}
	}
	return b.store.ceremony.Ceremony, nil
}
func (b *browserCeremony) BeginHumanEnrollment(ctx context.Context, req api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	return b.identity.BeginEnrollment(ctx, req)
}
func (b *browserCeremony) CompleteHumanEnrollment(ctx context.Context, req api.EnrollmentValidationRequest) (api.EnrollmentReceipt, error) {
	b.input = req
	install, err := b.identity.ValidateEnrollment(ctx, req)
	if err != nil {
		return api.EnrollmentReceipt{}, err
	}
	if err := api.ValidateInitialEnrollment(*b.store.ceremony, req, install, b.identity.deps.Clock.Now()); err != nil {
		return api.EnrollmentReceipt{}, err
	}
	if b.store.ceremony.Consumed || len(b.receipts) != 0 {
		return api.EnrollmentReceipt{}, &api.Error{Code: api.CodeConflict}
	}
	b.store.ceremony.Consumed = true
	receipt := api.EnrollmentReceipt{CeremonyID: req.Ceremony.CeremonyID, ChallengeID: req.ChallengeID, PrincipalID: install.Enrollment.PrincipalID,
		Config: install.Enrollment.Config, Generation: install.Enrollment.Generation, Evidence: install.CeremonyEvidence,
		OperationID: api.ID("operation-" + string(install.ValidationID)), EventID: api.ID("event-" + string(install.ValidationID)),
		CommittedSeq: api.Sequence(len(b.receipts) + 1), SimulatedPresence: install.Enrollment.Credentials[0].SimulatedPresence}
	b.receipts = append(b.receipts, receipt)
	return receipt, nil
}

func TestBrowserEnrollment(t *testing.T) {
	for _, rule := range []string{"valid", "origin", "uv", "marker", "aaguid", "cookie", "grant", "expiry", "pins"} {
		t.Run(rule, func(t *testing.T) {
			identity, store, _ := serviceFixture(t)
			aaguid := "00000000-0000-0000-0000-000000000001"
			if rule == "aaguid" {
				aaguid = api.SoftwareAuthenticatorAAGUID
			}
			f := newRegistration(t, identity.deps.Clock.Now(), "ES256", aaguid, "")
			store.ceremony = &f.challenge
			gate := &browserCeremony{identity: identity, store: store, grant: base64.RawURLEncoding.EncodeToString(f.challenge.Challenge)}
			unused := browserUnused{}
			view, err := dashboard.New(dashboard.Dependencies{Store: store, Human: identity, Identity: identity, Authenticator: identity,
				Lifecycle: unused, Messaging: unused, Approval: unused, Clock: identity.deps.Clock})
			if err != nil {
				t.Fatal(err)
			}
			endpoint := api.AdminEnrollmentEndpoint{Config: f.challenge.Ceremony.Config, Socket: "/run/fixture-enrollment.sock", ServiceUID: 1001,
				InstallationGeneration: f.challenge.InstallationGeneration, Origin: f.challenge.Origin, RPID: f.challenge.RPID,
				Helper: api.Executable{ID: "fixture-helper", SHA256: digestBytes([]byte("fixture-helper")), Version: "fixture"}}
			if err := view.ConfigureEnrollment(endpoint, gate); err != nil {
				t.Fatal(err)
			}
			if rule == "pins" {
				store.ceremony.Origin, store.ceremony.RPID = "https://foreign.example", "foreign.example"
			}
			call := func(path string, raw []byte, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, endpoint.Origin+path, bytes.NewReader(raw))
				r.Header.Set("Origin", endpoint.Origin)
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Sec-Fetch-Site", "same-origin")
				for _, cookie := range cookies {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				view.ServeHTTP(w, r)
				return w
			}
			if w := call("/api/v2/enrollment/begin", []byte(`{}`)); w.Code != 403 {
				t.Fatal("browser enrollment bypassed administrator authorization")
			}
			adminCookie := &http.Cookie{Name: "admin_ceremony", Value: gate.grant}
			begun := call("/api/v2/enrollment/begin", []byte(`{}`), adminCookie)
			if rule == "pins" {
				if begun.Code != 500 || len(begun.Result().Cookies()) != 0 {
					t.Fatal("browser ceremony accepted foreign installation pins")
				}
				return
			}
			if begun.Code != 200 || len(begun.Result().Cookies()) != 1 {
				t.Fatalf("browser ceremony setup failed: %d %s", begun.Code, begun.Body.String())
			}
			var options struct {
				Challenge []byte `json:"challenge"`
				Origin    string `json:"origin"`
				RPID      string `json:"rp_id"`
				UserID    []byte `json:"user_id"`
			}
			if err := api.DecodeObject(begun.Body.Bytes(), &options); err != nil {
				t.Fatal(err)
			}
			userHandle := sha256.Sum256([]byte("laneboss-enrollment-user\x00" + endpoint.Config + "\x00" + string(f.challenge.Ceremony.PrincipalID)))
			if options.Origin != endpoint.Origin || options.RPID != endpoint.RPID || !bytes.Equal(options.Challenge, f.challenge.Challenge) || !bytes.Equal(options.UserID, userHandle[:]) {
				t.Fatal("browser options lost protected enrollment pins")
			}
			cookie := begun.Result().Cookies()[0]
			if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatal("browser enrollment cookie lost its protections")
			}
			switch rule {
			case "origin":
				var client map[string]any
				if err := json.Unmarshal(f.request.ClientDataJSON, &client); err != nil {
					t.Fatal(err)
				}
				client["origin"] = "https://foreign.example"
				f.request.ClientDataJSON = launchJSON(t, client)
				f.seal(t)
			case "uv":
				f.auth[32] &^= 0x04
				f.seal(t)
			case "cookie":
				cookie.Value = "unknown-browser"
			case "grant":
				gate.deny = true
			case "expiry":
				store.ceremony.ExpiresAt = timestamp(identity.deps.Clock.Now().Add(-time.Second))
			}
			body := map[string]any{"client_data_json": f.request.ClientDataJSON, "attestation_object": f.request.AttestationObject}
			if rule == "marker" {
				body["attestation_marker"] = api.SoftwareAuthenticatorAttestationMarker
			}
			completed := call("/api/v2/enrollment/complete", launchJSON(t, body), adminCookie, cookie)
			if rule != "valid" {
				if completed.Code == 200 || len(gate.receipts) != 0 {
					t.Fatal("browser enrollment admitted unverified or software registration")
				}
				return
			}
			if completed.Code != 200 || len(gate.receipts) != 1 || !store.ceremony.Consumed || gate.input.AttestationMarker != "" ||
				!bytes.Equal(gate.input.ClientDataJSON, f.request.ClientDataJSON) || !bytes.Equal(gate.input.AttestationObject, f.request.AttestationObject) {
				t.Fatalf("browser registration did not reach identity verification: %d %s", completed.Code, completed.Body.String())
			}
			var receipt api.EnrollmentReceipt
			if err := json.Unmarshal(completed.Body.Bytes(), &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.SimulatedPresence || receipt.CommittedSeq == 0 || !reflect.DeepEqual(receipt, gate.receipts[0]) {
				t.Fatal("browser registration lost the committed identity receipt")
			}
		})
	}
}
