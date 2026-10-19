//go:build linux && !laneboss_e2e_authenticator

package store

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
	"testing"
)

func TestSoftwareInventoryRefused(t *testing.T) {
	s, deps := testStore(t)
	input := validatedEnrollmentInput(t, s)
	if _, err := commitEnrollmentFixture(context.Background(), s, input); err != nil {
		t.Fatal("unmarked enrollment control failed", err)
	}
	enrollment := input.Writes.Enrollments[0].Enrollment
	enrollment.Generation++
	key := &enrollment.Credentials[0]
	key.AAGUID, key.AttestationMarker, key.SimulatedPresence = api.SoftwareAuthenticatorAAGUID, api.SoftwareAuthenticatorAttestationMarker, true
	key.Revoked = true
	// A corruption/control fixture installs a pre-existing marked credential,
	// including revocation. Production must refuse this at read and reopen.
	fixtureProjection(t, s, "enrollment", enrollment.PrincipalID, enrollment.Generation, enrollment)
	if _, err := s.HumanEnrollments(context.Background(), deps.Config); err == nil {
		t.Fatal("production inventory accepted revoked software presence")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(deps)
	if err == nil {
		if closeErr := reopened.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("production store opened software presence inventory")
	}
}
