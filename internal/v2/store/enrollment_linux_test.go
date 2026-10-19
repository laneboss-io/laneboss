//go:build linux

package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type enrollmentInventory interface {
	HumanEnrollments(context.Context, string) ([]api.HumanEnrollment, error)
}
type enrollmentInstaller interface {
	InstallHumanEnrollment(context.Context, api.Scope, api.InternalIntent, api.EnrollmentInstall, api.ObjectWrite) (api.Commit, error)
}

func enrollmentJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Component tests supply the already-verified private capability explicitly.
// The public entry still requires a genuine native administrator channel.
func commitEnrollmentFixture(ctx context.Context, s *Service, input api.Transaction) (api.Commit, error) {
	return s.Transact(enrollmentFixtureContext(ctx, s, input), input)
}

func enrollmentFixtureContext(ctx context.Context, s *Service, input api.Transaction) context.Context {
	capability := enrollmentCommitAuthority{Store: s, Intent: input.Internal.ID, Validation: input.Writes.Enrollments[0].ValidationID}
	return context.WithValue(ctx, enrollmentCommitKey{}, capability)
}

func enrollmentInput(t *testing.T) api.Transaction {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: "store-fixture", Actor: api.Actor{Kind: "service", ID: testID(t)}, Source: "worker"}
	enrollment := api.HumanEnrollment{Config: scope.Config, PrincipalID: testID(t), Origin: "https://ceremony.invalid", RPID: "ceremony.invalid", Generation: 1,
		Credentials: []api.HumanCredential{{ID: testID(t), RawCredentialID: []byte(testID(t)), Algorithm: "ES256", PublicKeyDER: public, Generation: 1}}}
	// The attestation is an opaque ceremony receipt in this store component
	// test. Cryptographic enrollment/UP/UV remains the fixed ceremony owner's
	// responsibility; this test exercises bytes, provenance and baseline CAS.
	evidence, err := json.Marshal(struct {
		Principal api.ID
		PublicKey []byte
	}{enrollment.PrincipalID, public})
	if err != nil {
		t.Fatal(err)
	}
	object := api.ObjectWrite{ObjectKey: testID(t), Class: "artifact", Bytes: evidence, SHA256: testDigest(evidence), Origin: "service", ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "owner", Generation: 1}}
	ref := api.BlobRef{ID: object.ObjectKey, Class: object.Class, Bytes: int64(len(evidence)), SHA256: object.SHA256}
	intent := api.InternalIntent{ID: testID(t), Kind: api.InternalAdminEnroll, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor}
	payload, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config, Kind: "blob.committed", Actor: scope.Actor, RequestedBy: scope.Actor, Origin: "service", StarterChain: []api.ID{}, Payload: payload}
	return api.Transaction{Scope: scope, Internal: &intent, Writes: api.StateWrites{Enrollments: []api.EnrollmentInstall{{Enrollment: enrollment, CeremonyEvidence: ref}}, Objects: []api.ObjectWrite{object}}, Events: []api.Event{event}}
}

func validatedEnrollmentInput(t *testing.T, s *Service) api.Transaction {
	t.Helper()
	input := enrollmentInput(t)
	s.deps.Enrollment = &api.AdminEnrollmentEndpoint{Config: s.deps.Config, Socket: filepath.Join(s.deps.Directory, "admin.sock"), ServiceUID: uint32(os.Geteuid()), InstallationGeneration: 1, Origin: input.Writes.Enrollments[0].Enrollment.Origin, RPID: input.Writes.Enrollments[0].Enrollment.RPID, Helper: api.Executable{ID: testID(t), SHA256: testDigest([]byte("installed helper fixture")), Version: "component-v1"}}
	ceremony := api.EnrollmentCeremonyRequest{Config: s.deps.Config, CeremonyID: testID(t), PrincipalID: input.Writes.Enrollments[0].Enrollment.PrincipalID}
	challenge, err := s.ReserveEnrollment(context.Background(), ceremony)
	if err != nil {
		t.Fatal("actual enrollment challenge setup failed", err)
	}
	clientData, err := json.Marshal(struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}{"webauthn.create", base64.RawURLEncoding.EncodeToString(challenge.Challenge), challenge.Origin})
	if err != nil {
		t.Fatal(err)
	}
	// Identity's already-validated attestation handoff is an explicit DTO
	// fixture here. This store test does not claim cryptographic/native entry.
	request := api.EnrollmentValidationRequest{Ceremony: ceremony, ChallengeID: challenge.ID, ClientDataJSON: clientData, AttestationObject: []byte("component validated attestation")}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	object := &input.Writes.Objects[0]
	object.Bytes, object.SHA256 = raw, testDigest(raw)
	install := &input.Writes.Enrollments[0]
	install.CeremonyID, install.ChallengeID, install.ValidationID = ceremony.CeremonyID, challenge.ID, input.Internal.ID
	install.CeremonyEvidence = api.BlobRef{ID: object.ObjectKey, Class: "artifact", SHA256: object.SHA256, Bytes: int64(len(raw))}
	key := &install.Enrollment.Credentials[0]
	key.AAGUID, key.AttestationFormat, key.RegistrationEvidence = "00000000-0000-0000-0000-000000000000", "none", install.CeremonyEvidence
	input.Events[0].Payload, err = json.Marshal(install.CeremonyEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.retainEnrollmentValidation(context.Background(), request, *install); err != nil {
		t.Fatal("validated registration handoff setup failed", err)
	}
	return input
}

func TestAdminEnrollmentAtomic(t *testing.T) {
	s, deps := testStore(t)
	input := validatedEnrollmentInput(t, s)
	ctx := context.Background()
	_, ok := any(s).(enrollmentInstaller)
	if !ok {
		t.Fatal("store initial enrollment port is absent")
	}
	commit, err := s.installHumanEnrollment(enrollmentFixtureContext(ctx, s, input), input.Scope, *input.Internal, input.Writes.Enrollments[0], input.Writes.Objects[0])
	if err != nil {
		t.Fatal("fixed initial enrollment transaction failed", err)
	}
	metadata, err := s.ObjectMetadata(ctx, input.Scope, input.Writes.Objects[0].ObjectKey)
	if err != nil || metadata.Ref != input.Writes.Enrollments[0].CeremonyEvidence || metadata.SourceOperationID != commit.Operation.ID || metadata.Origin != "service" {
		t.Fatal("ceremony attestation was not retained atomically", err)
	}
	replay, err := s.installHumanEnrollment(enrollmentFixtureContext(ctx, s, input), input.Scope, *input.Internal, input.Writes.Enrollments[0], input.Writes.Objects[0])
	if err != nil || !replay.Replayed || replay.Operation.ID != commit.Operation.ID {
		t.Fatal("initial ceremony replay changed its exact commit", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(deps)
	if err != nil {
		t.Fatal("enrollment evidence did not survive restart", err)
	}
	defer s.Close()
	inventory, ok := any(s).(enrollmentInventory)
	if !ok {
		t.Fatal("protected human credential inventory is absent")
	}
	all, err := inventory.HumanEnrollments(ctx, deps.Config)
	if err != nil || len(all) != 1 || !sameValue(all[0], input.Writes.Enrollments[0].Enrollment) {
		t.Fatal("restart changed the actual enrollment", err)
	}
	verification, err := s.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK || verification.Events != 1 {
		t.Fatal("enrollment transaction did not retain one real evidence event", err)
	}
}

func TestAdminEnrollmentGuards(t *testing.T) {
	for _, fault := range []string{"second_baseline", "missing_evidence", "changed_evidence", "wrong_acl", "foreign_config", "missing_blob_event", "changed_key", "origin", "wrong_actor", "later_change"} {
		t.Run(fault, func(t *testing.T) {
			s, _ := testStore(t)
			input := validatedEnrollmentInput(t, s)
			ctx := context.Background()
			want := api.CodeForbidden
			switch fault {
			case "second_baseline":
				second := validatedEnrollmentInput(t, s)
				if _, err := commitEnrollmentFixture(ctx, s, input); err != nil {
					t.Fatal("initial baseline control failed", err)
				}
				input = second
				want = api.CodeConflict
			case "missing_evidence":
				input.Writes.Objects = nil
			case "changed_evidence":
				input.Writes.Enrollments[0].CeremonyEvidence.SHA256 = testDigest([]byte("unrelated receipt"))
			case "wrong_acl":
				input.Writes.Objects[0].ACL.Audience = "config"
			case "foreign_config":
				input.Writes.Enrollments[0].Enrollment.Config = "other-config"
				want = api.CodeInvalid
			case "missing_blob_event":
				input.Events = nil
			case "changed_key":
				input.Writes.Enrollments[0].Enrollment.Credentials[0].PublicKeyDER = []byte("unparseable public key")
				want = api.CodeInvalid
			case "origin":
				input.Writes.Enrollments[0].Enrollment.Origin = "http://ceremony.invalid"
				want = api.CodeInvalid
			case "wrong_actor":
				input.Internal.Actor.ID = testID(t)
			case "later_change":
				input.Writes.Enrollments[0].ExpectedGeneration = 1
				input.Writes.Enrollments[0].Enrollment.Generation = 2
				want = api.CodeForbidden
			}
			_, err := commitEnrollmentFixture(ctx, s, input)
			if err == nil {
				t.Fatal("administrator enrollment accepted " + fault)
			}
			expectCode(t, err, want)
			if fault != "second_baseline" {
				var count int
				if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM objects").Scan(&count); err != nil || count != 0 {
					t.Fatal("refused enrollment partially retained evidence", err)
				}
			}
		})
	}
}

func TestHumanEnrollmentInventory(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	inventory, ok := any(s).(enrollmentInventory)
	if !ok {
		t.Fatal("protected human credential inventory is absent")
	}
	empty, err := inventory.HumanEnrollments(ctx, "store-fixture")
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("actual empty inventory was not read", err)
	}
	input := validatedEnrollmentInput(t, s)
	marked := &input.Writes.Enrollments[0].Enrollment.Credentials[0]
	if _, err := commitEnrollmentFixture(ctx, s, input); err != nil {
		t.Fatal(err)
	}
	enrollment := input.Writes.Enrollments[0].Enrollment
	enrollment.Generation++
	enrollment.Credentials[0].Revoked = true
	// This is a read-port fixture for a previously approved revocation. It
	// does not call or credit the unimplemented key-change ceremony.
	fixtureProjection(t, s, "enrollment", enrollment.PrincipalID, enrollment.Generation, enrollment)
	all, err := inventory.HumanEnrollments(ctx, "store-fixture")
	if err != nil || len(all) != 1 || len(all[0].Credentials) != 1 || !all[0].Credentials[0].Revoked || all[0].Credentials[0].ID != marked.ID || !bytes.Equal(all[0].Credentials[0].RawCredentialID, marked.RawCredentialID) || !bytes.Equal(all[0].Credentials[0].PublicKeyDER, marked.PublicKeyDER) {
		t.Fatal("inventory dropped revoked credentials or recorded registration bytes", err)
	}
	all[0].Credentials[0].RawCredentialID[0] ^= 1
	again, err := inventory.HumanEnrollments(ctx, "store-fixture")
	if err != nil || !bytes.Equal(again[0].Credentials[0].RawCredentialID, marked.RawCredentialID) {
		t.Fatal("inventory returned mutable retained credential storage", err)
	}
	if _, err := inventory.HumanEnrollments(ctx, "other-config"); err == nil {
		t.Fatal("inventory read another configuration")
	} else {
		expectCode(t, err, api.CodeForbidden)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := inventory.HumanEnrollments(cancelled, "store-fixture"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled inventory read continued", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := inventory.HumanEnrollments(ctx, "store-fixture"); err == nil {
		t.Fatal("closed store inferred an empty credential inventory")
	} else {
		expectCode(t, err, api.CodeUnavailable)
	}
}
