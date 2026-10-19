//go:build !laneboss_e2e_authenticator

package admin

import (
	"laneboss.io/laneboss/internal/v2/api"
	"testing"
)

func TestRegistrationPresence(t *testing.T) {
	v, identity, _, ctx, _ := initialEnrollmentFixture(t)
	c := &identity.install.Enrollment.Credentials[0]
	c.ID, c.RawCredentialID = api.SoftwareAuthenticatorCredentialID, []byte(api.SoftwareAuthenticatorRawPrefix+"fixture")
	c.AAGUID, c.AttestationMarker, c.SimulatedPresence = api.SoftwareAuthenticatorAAGUID, api.SoftwareAuthenticatorAttestationMarker, true
	identity.request.AttestationMarker = api.SoftwareAuthenticatorAttestationMarker
	if _, err := v.ValidateInitialRegistration(ctx, identity.request); err == nil {
		t.Fatal("acceptance: production accepted simulated presence registration")
	}
}
