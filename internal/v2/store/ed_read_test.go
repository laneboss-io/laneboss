//go:build linux

package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity/input"
)

func TestEdLegacyRead(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	registration := testinput.EdRegistration(t, s.deps.Config, testID(t), s.deps.Clock)
	enrollment := registration.Install.Enrollment
	enrollment.Credentials[0].Algorithm = "Ed25519"
	fixtureProjection(t, s, "enrollment", enrollment.PrincipalID, enrollment.Generation, enrollment)
	var before []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='enrollment' AND id=?", string(enrollment.PrincipalID)).Scan(&before); err != nil {
		t.Fatal(err)
	}
	reader := inviteReader(t, s, enrollment)
	actual, err := s.Enrollment(ctx, reader)
	want := enrollment
	want.Credentials = append([]api.HumanCredential(nil), enrollment.Credentials...)
	want.Credentials[0].Algorithm = "EdDSA"
	if err != nil || !sameValue(actual, want) {
		t.Fatal("legacy read changed more than its canonical label", err)
	}
	all, err := s.HumanEnrollments(ctx, s.deps.Config)
	if err != nil || len(all) != 1 || !sameValue(all[0], want) {
		t.Fatal("startup inventory did not use the canonical read boundary", err)
	}
	var after []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='enrollment' AND id=?", string(enrollment.PrincipalID)).Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatal("compatibility read rewrote retained enrollment bytes", err)
	}
	// Compatibility is a read rule, not permission for a new legacy write.
	expectCode(t, validateEnrollment(enrollment), api.CodeInvalid)
}

func TestEdLabelFences(t *testing.T) {
	for _, mode := range []string{"ed-es", "ed-rs", "ec-ed", "ec-legacy"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := testStore(t)
			registration := testinput.EdRegistration(t, s.deps.Config, testID(t), s.deps.Clock)
			enrollment := registration.Install.Enrollment
			credential := &enrollment.Credentials[0]
			switch mode {
			case "ed-es":
				credential.Algorithm = "ES256"
			case "ed-rs":
				credential.Algorithm = "RS256"
			default:
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				credential.PublicKeyDER, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				credential.Algorithm = "EdDSA"
				if mode == "ec-legacy" {
					credential.Algorithm = "Ed25519"
				}
			}
			expectCode(t, validateEnrollment(enrollment), api.CodeInvalid)
			fixtureProjection(t, s, "enrollment", enrollment.PrincipalID, enrollment.Generation, enrollment)
			reader := inviteReader(t, s, enrollment)
			code := api.CodeInvalid
			if mode == "ec-legacy" {
				code = api.CodeIntegrity
			}
			actual, err := s.Enrollment(context.Background(), reader)
			expectCode(t, err, code)
			if len(actual.Credentials) != 0 {
				t.Fatal("mismatched key read returned a credential")
			}
			_, err = s.HumanEnrollments(context.Background(), s.deps.Config)
			if err == nil {
				t.Fatal("startup accepted mismatched key and algorithm")
			}
		})
	}
}

func TestEdEnrollmentWrite(t *testing.T) {
	s, _ := testStore(t)
	input := validatedEnrollmentInput(t, s)
	challenge, err := s.EnrollmentChallenge(context.Background(), s.deps.Config, input.Writes.Enrollments[0].ChallengeID)
	if err != nil {
		t.Fatal(err)
	}
	registration := testinput.EdFromChallenge(t, challenge, s.deps.Clock)
	install := registration.Install
	if err := s.retainEnrollmentValidation(context.Background(), registration.Request, install); err != nil {
		t.Fatal(err)
	}
	raw := enrollmentJSON(t, registration.Request)
	input.Internal.ID = install.ValidationID
	input.Writes.Enrollments = []api.EnrollmentInstall{install}
	object := &input.Writes.Objects[0]
	object.ObjectKey, object.Bytes, object.SHA256 = install.CeremonyEvidence.ID, raw, install.CeremonyEvidence.SHA256
	input.Events[0].Payload = enrollmentJSON(t, install.CeremonyEvidence)
	if _, err := commitEnrollmentFixture(context.Background(), s, input); err != nil {
		t.Fatal("identity-produced Ed25519 registration failed the real enrollment writer", err)
	}
	all, err := s.HumanEnrollments(context.Background(), s.deps.Config)
	if err != nil || len(all) != 1 || all[0].Credentials[0].Algorithm != "EdDSA" || !sameValue(all[0], install.Enrollment) {
		t.Fatal("enrollment commit lost the producer's canonical credential", err)
	}
}
