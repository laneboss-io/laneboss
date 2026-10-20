//go:build !laneboss_e2e_authenticator

package identity

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestProdAttestation(t *testing.T) {
	for _, format := range []string{"none", "packed"} {
		t.Run(format, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			f := newRegistration(t, s.deps.Clock.Now(), "Ed25519", api.SoftwareAuthenticatorAAGUID, api.SoftwareAuthenticatorAttestationMarker)
			if format == "none" {
				f.statement = map[any]any{}
			} else {
				delete(f.statement, "x5c")
			}
			f.encode(t, format)
			store.ceremony = &f.challenge
			install, err := s.ValidateEnrollment(context.Background(), f.request)
			fixtureCode(t, err, api.CodeForbidden)
			if !reflect.DeepEqual(install, api.EnrollmentInstall{}) {
				t.Fatal("fixture check: production accepted simulated attestation")
			}
		})
	}
}

func TestProdInvitedAttestation(t *testing.T) {
	s, store, _ := serviceFixture(t)
	f := newRegistration(t, s.deps.Clock.Now(), "ES256", api.SoftwareAuthenticatorAAGUID, api.SoftwareAuthenticatorAttestationMarker)
	f.challenge.InviteID = "retained-invite"
	store.ceremony = &f.challenge
	install, err := s.ValidateEnrollment(context.Background(), f.request)
	fixtureCode(t, err, api.CodeForbidden)
	if !reflect.DeepEqual(install, api.EnrollmentInstall{}) {
		t.Fatal("invited test key entered a production build")
	}
}

func TestCredentialConsumerFixture(t *testing.T) {
	s, store, _ := serviceFixture(t)
	scope := fixtureHumanScope(t, s, store)
	f := newRegistration(t, s.deps.Clock.Now(), "Ed25519", api.SoftwareAuthenticatorAAGUID, api.SoftwareAuthenticatorAttestationMarker)
	store.ceremony = &f.challenge
	install, err := s.ValidateEnrollment(context.Background(), f.request)
	fixtureCode(t, err, api.CodeForbidden)
	if !reflect.DeepEqual(install, api.EnrollmentInstall{}) {
		t.Fatal("fixture check: production returned a marked registration")
	}
	store.enrollment.Credentials[0].AAGUID = api.SoftwareAuthenticatorAAGUID
	store.enrollment.Credentials[0].AttestationMarker = api.SoftwareAuthenticatorAttestationMarker
	store.enrollment.Credentials[0].SimulatedPresence = true
	store.enrollment.Credentials[0].Revoked = true
	fixtureCode(t, api.CheckHumanEnrollmentPolicy(context.Background(), store, scope.Config), api.CodeForbidden)
	_, err = s.humanEnrollment(context.Background(), scope)
	fixtureCode(t, err, api.CodeForbidden)
}
