//go:build linux && laneboss_e2e_authenticator

package store

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
	"testing"
)

func TestTaggedInventoryRetainsPresence(t *testing.T) {
	s, deps := testStore(t)
	input := validatedEnrollmentInput(t, s)
	install := &input.Writes.Enrollments[0]
	key := &install.Enrollment.Credentials[0]
	key.AAGUID, key.AttestationMarker, key.SimulatedPresence = api.SoftwareAuthenticatorAAGUID, api.SoftwareAuthenticatorAttestationMarker, true
	var validated enrollmentValidation
	if err := storedProjection(context.Background(), s.db, "enrollment_validation", install.ValidationID, &validated); err != nil {
		t.Fatal(err)
	}
	validated.Request.AttestationMarker = key.AttestationMarker
	validated.Install = *install
	// This fixture is an already validated identity DTO. No software signer
	// is introduced into the production store or this component test.
	raw := enrollmentJSON(t, validated.Request)
	object := &input.Writes.Objects[0]
	object.Bytes, object.SHA256 = raw, testDigest(raw)
	install.CeremonyEvidence.SHA256, install.CeremonyEvidence.Bytes = object.SHA256, int64(len(raw))
	key.RegistrationEvidence = install.CeremonyEvidence
	validated.Install = *install
	input.Events[0].Payload = enrollmentJSON(t, install.CeremonyEvidence)
	fixtureProjection(t, s, "enrollment_validation", install.ValidationID, 1, validated)
	commit, err := commitEnrollmentFixture(context.Background(), s, input)
	if err != nil || !commit.Operation.SimulatedPresence {
		t.Fatal("tagged enrollment lost simulated operation provenance", err)
	}
	enrollment := install.Enrollment
	enrollment.Generation++
	enrollment.Credentials[0].Revoked = true
	fixtureProjection(t, s, "enrollment", enrollment.PrincipalID, enrollment.Generation, enrollment)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(deps)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	all, err := s.HumanEnrollments(context.Background(), deps.Config)
	if err != nil || len(all) != 1 || !all[0].Credentials[0].SimulatedPresence || !all[0].Credentials[0].Revoked || all[0].Credentials[0].AAGUID != key.AAGUID {
		t.Fatal("tagged inventory dropped revoked simulated registration provenance", err)
	}
}
