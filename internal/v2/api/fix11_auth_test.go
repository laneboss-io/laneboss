package api

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func contractNow() time.Time              { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
func contractStamp(t time.Time) Timestamp { return Timestamp(t.UTC().Format(time.RFC3339Nano)) }

// Projection fixtures exercise correlation only, never native authentication.
type refreshConnection struct {
	ConnectionContext
	id ID
}

func (c refreshConnection) ID() ID { return c.id }

func refreshFixture() (Scope, StoredReadSession, StoredReadSession) {
	now := contractNow()
	before := StoredReadSession{Session: HumanSession{ID: "read-session", Config: "demo", ExpiresAt: contractStamp(now.Add(30 * time.Minute)), IdleExpiresAt: contractStamp(now.Add(time.Minute))},
		PrincipalID: "human-one", CredentialID: "credential-one", ConnectionID: "connection-one", EndpointGeneration: 3, Generation: 1}
	after := before
	after.Generation++
	after.Session.IdleExpiresAt = contractStamp(now.Add(5 * time.Minute))
	return Scope{Config: "demo", Actor: Actor{Kind: "human", ID: before.PrincipalID}, EndpointGeneration: 3, Connection: refreshConnection{id: before.ConnectionID}}, before, after
}

func TestSessionRefresh(t *testing.T) {
	s, b, a := refreshFixture()
	if err := ValidateReadSessionRefresh(s, b, a, contractNow()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"expired", "absolute", "connection", "revision", "revoked"} {
		t.Run(fault, func(t *testing.T) {
			s, b, a := refreshFixture()
			switch fault {
			case "expired":
				b.Session.IdleExpiresAt = contractStamp(contractNow())
			case "absolute":
				a.Session.ExpiresAt = contractStamp(contractNow().Add(time.Hour))
			case "connection":
				a.ConnectionID = "foreign-connection"
			case "revision":
				a.Generation = b.Generation
			case "revoked":
				b.Revoked = true
			}
			requireLaunchInvalid(t, ValidateReadSessionRefresh(s, b, a, contractNow()), "read session refresh boundary was bypassed")
		})
	}
	t.Run("cap", func(t *testing.T) {
		s, b, a := refreshFixture()
		b.Session.ExpiresAt = contractStamp(contractNow().Add(2 * time.Minute))
		a.Session.ExpiresAt, a.Session.IdleExpiresAt = b.Session.ExpiresAt, b.Session.ExpiresAt
		if err := ValidateReadSessionRefresh(s, b, a, contractNow()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSessionAuthority(t *testing.T) {
	_, b, a := refreshFixture()
	current := ReadAuthorityFromSession(b)
	update := ReadAuthorityUpdate{Before: current, After: ReadAuthorityFromSession(a)}
	if err := ValidateReadAuthorityUpdate(current, update); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"connection", "absolute", "revision"} {
		t.Run(fault, func(t *testing.T) {
			changed := update
			switch fault {
			case "connection":
				changed.After.ConnectionID = "foreign-connection"
			case "absolute":
				changed.After.ExpiresAt = contractStamp(contractNow().Add(time.Hour))
			case "revision":
				changed.Before.Generation++
			}
			requireLaunchInvalid(t, ValidateReadAuthorityUpdate(current, changed), "same-connection authority refresh was bypassed")
		})
	}
}

func softwareCredentialFixture() HumanCredential {
	return HumanCredential{ID: SoftwareAuthenticatorCredentialID, RawCredentialID: []byte(SoftwareAuthenticatorRawPrefix + "fixture"),
		AAGUID: SoftwareAuthenticatorAAGUID, AttestationMarker: SoftwareAuthenticatorAttestationMarker, AttestationFormat: "packed",
		RegistrationEvidence: launchFixtureBlob("registration", "artifact"), SimulatedPresence: true, Generation: 1}
}

func TestCredentialBuild(t *testing.T) {
	c := softwareCredentialFixture()
	err := ValidateCredentialPresence(c)
	if softwareAuthenticatorBuild {
		if err != nil {
			t.Fatalf("tagged declared credential was refused: %v", err)
		}
	} else {
		var typed *Error
		if !errors.As(err, &typed) || typed.Code != CodeForbidden || typed.Owner != "lb-v2-identity" {
			t.Fatalf("production admitted software credential: %v", err)
		}
	}
	hardware := HumanCredential{ID: "hardware", RawCredentialID: []byte("hardware-public-id")}
	if err := ValidateCredentialPresence(hardware); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialMarkers(t *testing.T) {
	if !validCredentialMarkers(softwareCredentialFixture()) {
		t.Fatal("complete declared markers refused")
	}
	for _, fault := range []string{"marker", "aaguid", "presence"} {
		t.Run(fault, func(t *testing.T) {
			c := softwareCredentialFixture()
			switch fault {
			case "marker":
				c.AttestationMarker = ""
			case "aaguid":
				c.AAGUID = "00000000-0000-0000-0000-000000000001"
			case "presence":
				c.SimulatedPresence = false
			}
			if validCredentialMarkers(c) {
				t.Fatal("partial software registration markers accepted")
			}
		})
	}
}

func TestProofMark(t *testing.T) {
	c := HumanCredential{ID: "hardware"}
	if softwareAuthenticatorBuild {
		c = softwareCredentialFixture()
	}
	p := VerifiedHumanProof{CredentialID: c.ID, NonceID: "nonce", SimulatedPresence: c.SimulatedPresence,
		Ref: ProofRef{ID: "proof", SimulatedPresence: c.SimulatedPresence}}
	use := ProofUseReceipt{ProofID: p.Ref.ID, CredentialID: c.ID, NonceID: p.NonceID, OperationID: "operation", SimulatedPresence: c.SimulatedPresence}
	if err := ValidateProofPresence(c, p, use); err != nil {
		t.Fatal(err)
	}
	use.SimulatedPresence = !use.SimulatedPresence
	requireLaunchInvalid(t, ValidateProofPresence(c, p, use), "proof receipt changed verified presence mark")
}

func TestAtomicPresenceMark(t *testing.T) {
	tx := assertionTransaction(t)
	tx.Writes.Proofs[0].SimulatedPresence = true
	var typed *Error
	if err := ValidateTransactionShape(tx); !errors.As(err, &typed) || typed.Code != CodeInvalid {
		t.Fatalf("atomic confirmation lost presence mark: %v", err)
	}
}

type enrollmentInventory struct {
	values []HumanEnrollment
	err    error
	calls  int
}

func (i *enrollmentInventory) HumanEnrollments(context.Context, string) ([]HumanEnrollment, error) {
	i.calls++
	return i.values, i.err
}

func TestEnrollmentInventory(t *testing.T) {
	i := &enrollmentInventory{values: []HumanEnrollment{{Config: "demo", PrincipalID: "human-one", Generation: 1, Credentials: []HumanCredential{{ID: "hardware"}}}}}
	if err := CheckHumanEnrollmentPolicy(context.Background(), i, "demo"); err != nil || i.calls != 1 {
		t.Fatalf("inventory was not read: %v", err)
	}
	i.values[0].Config = "foreign"
	requireLaunchInvalid(t, CheckHumanEnrollmentPolicy(context.Background(), i, "demo"), "foreign enrollment inventory accepted")
	sentinel := errors.New("inventory unavailable")
	i.err = sentinel
	if err := CheckHumanEnrollmentPolicy(context.Background(), i, "demo"); !errors.Is(err, sentinel) {
		t.Fatalf("inventory error was replaced: %v", err)
	}
	i.err = nil
	i.values[0].Config = "demo"
	i.values[0].Credentials = []HumanCredential{softwareCredentialFixture()}
	i.values[0].Credentials[0].Revoked = true
	err := CheckHumanEnrollmentPolicy(context.Background(), i, "demo")
	if softwareAuthenticatorBuild {
		if err != nil {
			t.Fatal(err)
		}
	} else {
		var typed *Error
		if !errors.As(err, &typed) || typed.Code != CodeForbidden {
			t.Fatalf("revoked test credential bypassed production startup: %v", err)
		}
	}
}

func enrollmentFixture() (EnrollmentChallenge, EnrollmentValidationRequest, EnrollmentInstall) {
	ceremony := EnrollmentCeremonyRequest{Config: "demo", CeremonyID: "ceremony", PrincipalID: "human-one"}
	challenge := EnrollmentChallenge{ID: "registration-challenge", Ceremony: ceremony, Challenge: bytes.Repeat([]byte{1}, 32), Origin: "https://console.example", RPID: "console.example",
		EndpointGeneration: 1, InstallationGeneration: 1, ExpiresAt: contractStamp(contractNow().Add(time.Minute))}
	evidence := launchFixtureBlob("registration-evidence", "artifact")
	// Opaque attestation/key bytes exercise the already-verified handoff shape.
	// Actual registration crypto remains the EnrollmentValidator producer's gate.
	c := HumanCredential{ID: "hardware", RawCredentialID: []byte("public-credential-id"), Algorithm: "ES256", PublicKeyDER: []byte("opaque-public-key"), Generation: 1,
		AAGUID: "00000000-0000-0000-0000-000000000001", AttestationFormat: "packed", RegistrationEvidence: evidence}
	install := EnrollmentInstall{CeremonyID: ceremony.CeremonyID, ChallengeID: challenge.ID, ValidationID: "registration-validation", CeremonyEvidence: evidence,
		Enrollment: HumanEnrollment{Config: "demo", PrincipalID: ceremony.PrincipalID, Origin: challenge.Origin, RPID: challenge.RPID, Generation: 1, Credentials: []HumanCredential{c}}}
	request := EnrollmentValidationRequest{Ceremony: ceremony, ChallengeID: challenge.ID, ClientDataJSON: []byte("opaque-client-data"), AttestationObject: []byte("opaque-attestation")}
	return challenge, request, install
}

func TestEnrollmentCeremony(t *testing.T) {
	c, r, i := enrollmentFixture()
	if err := ValidateEnrollmentInstall(c, r, i, contractNow()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"origin", "used", "challenge", "generation", "evidence"} {
		t.Run(fault, func(t *testing.T) {
			c, r, i := enrollmentFixture()
			switch fault {
			case "origin":
				c.Origin = "https://foreign.example"
			case "used":
				c.Consumed = true
			case "challenge":
				r.ChallengeID = "foreign-challenge"
			case "generation":
				i.Enrollment.Generation++
			case "evidence":
				i.Enrollment.Credentials[0].RegistrationEvidence.ID = "foreign-evidence"
			}
			requireLaunchInvalid(t, ValidateEnrollmentInstall(c, r, i, contractNow()), "administrator enrollment handoff was bypassed")
		})
	}
}

func TestEnrollmentEndpoint(t *testing.T) {
	e := AdminEnrollmentEndpoint{Config: "demo", Socket: "/runtime/admin-enrollment.sock", ServiceUID: 11000, InstallationGeneration: 1,
		Origin: "https://console.example", RPID: "console.example", Helper: Executable{ID: "installed-helper", Version: "fixture", SHA256: launchFixtureBlob("helper", "manifest").SHA256}}
	if err := ValidateAdminEnrollmentEndpoint(e); err != nil {
		t.Fatal(err)
	}
	e.Socket = "caller-relative.sock"
	requireLaunchInvalid(t, ValidateAdminEnrollmentEndpoint(e), "administrator enrollment endpoint accepted a caller path")
}

func TestEnrollmentBaseline(t *testing.T) {
	c, r, i := enrollmentFixture()
	if err := ValidateInitialEnrollment(c, r, i, contractNow()); err != nil {
		t.Fatal(err)
	}
	c.Ceremony.ExpectedGeneration, r.Ceremony.ExpectedGeneration, i.ExpectedGeneration, i.Enrollment.Generation = 1, 1, 1, 2
	var typed *Error
	if err := ValidateInitialEnrollment(c, r, i, contractNow()); !errors.As(err, &typed) || typed.Code != CodeForbidden {
		t.Fatalf("administrator ceremony replaced an enrollment: %v", err)
	}
}
