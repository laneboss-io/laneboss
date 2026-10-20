package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"net/url"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// HumanEnrollments matches assembly's protected startup inventory port. Only
// the concrete service-owned store exposes it; it is not in the public RPC
// catalog. Revocation never removes the recorded credential or its markers.
func (s *Service) HumanEnrollments(ctx context.Context, config string) ([]api.HumanEnrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.available(); err != nil {
		return nil, err
	}
	if config != s.deps.Config {
		return nil, fault(api.CodeForbidden, "human enrollment inventory belongs to another configuration")
	}
	if err := s.verifyFiles(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,data FROM projections WHERE kind='enrollment' ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []api.HumanEnrollment{}
	credentials, rawIDs := map[api.ID]bool{}, map[string]bool{}
	for rows.Next() {
		var id api.ID
		var data []byte
		var enrollment api.HumanEnrollment
		if err := rows.Scan(&id, &data); err != nil {
			return nil, err
		}
		if err := decodeStored(data, &enrollment); err != nil {
			return nil, err
		}
		if enrollment.Config != config || enrollment.PrincipalID != id || validateEnrollment(enrollment) != nil {
			return nil, fault(api.CodeIntegrity, "protected human enrollment inventory is malformed")
		}
		for _, credential := range enrollment.Credentials {
			if credentials[credential.ID] || rawIDs[string(credential.RawCredentialID)] {
				return nil, fault(api.CodeIntegrity, "human credential inventory has ambiguous ownership")
			}
			credentials[credential.ID], rawIDs[string(credential.RawCredentialID)] = true, true
		}
		result = append(result, enrollment)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// InstallHumanEnrollment is the fixed ceremony's in-process store entry. The
// ceremony owns authentication/attestation verification; this port owns the
// absent baseline, retained exact evidence, closed emitter and atomic commit.
func (s *Service) InstallHumanEnrollment(ctx context.Context, scope api.Scope, intent api.InternalIntent, install api.EnrollmentInstall, evidence api.ObjectWrite) (api.Commit, error) {
	if s.deps.Enrollment == nil {
		return api.Commit{}, api.NotImplemented("lb-v2-admin", "protected administrator enrollment endpoint")
	}
	if err := wire.VerifyAdministrator(ctx, *s.deps.Enrollment, scope.Connection, scope.Frame); err != nil {
		return api.Commit{}, err
	}
	ctx = context.WithValue(ctx, enrollmentCommitKey{}, enrollmentCommitAuthority{Store: s, Intent: intent.ID, Validation: install.ValidationID, NativeScope: scope})
	scope.Connection, scope.Frame = nil, nil
	scope.Actor = api.Actor{Kind: "service", ID: s.storeID}
	intent.Actor, intent.RequestedBy = scope.Actor, scope.Actor
	evidence.ACL.Owner = scope.Actor
	return s.installHumanEnrollment(ctx, scope, intent, install, evidence)
}

func (s *Service) installHumanEnrollment(ctx context.Context, scope api.Scope, intent api.InternalIntent, install api.EnrollmentInstall, evidence api.ObjectWrite) (api.Commit, error) {
	if intent.Kind != api.InternalAdminEnroll {
		return api.Commit{}, fault(api.CodeForbidden, "human enrollment requires the fixed administrator ceremony")
	}
	id := api.ID(hash([]byte("admin_enroll:" + string(intent.ID))))
	ref := api.BlobRef{ID: evidence.ObjectKey, Class: evidence.Class, Bytes: int64(len(evidence.Bytes)), SHA256: evidence.SHA256}
	data, err := json.Marshal(ref)
	if err != nil {
		return api.Commit{}, err
	}
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: scope.Config, Kind: "blob.committed", Actor: intent.Actor, RequestedBy: intent.RequestedBy,
		Origin: "service", StarterChain: []api.ID{}, Payload: data}
	return s.Transact(ctx, api.Transaction{Scope: scope, Internal: &intent, Writes: api.StateWrites{Enrollments: []api.EnrollmentInstall{install}, Objects: []api.ObjectWrite{evidence}}, Events: []api.Event{event}})
}

func validateEnrollment(enrollment api.HumanEnrollment) error {
	if !wire.ValidID(enrollment.Config) || !wire.ValidID(string(enrollment.PrincipalID)) || enrollment.Generation == 0 || len(enrollment.Credentials) == 0 {
		return wire.Invalid("enrollment requires a principal, generation and actual public credentials")
	}
	origin, err := url.Parse(enrollment.Origin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" && origin.Path != "/" ||
		enrollment.RPID == "" || strings.ContainsAny(enrollment.RPID, "/:@\\") || origin.Hostname() != enrollment.RPID && !strings.HasSuffix(origin.Hostname(), "."+enrollment.RPID) {
		return wire.Invalid("enrollment RP and origin are not a bound HTTPS relying party")
	}
	ids, raw := map[api.ID]bool{}, map[string]bool{}
	for _, credential := range enrollment.Credentials {
		if err := api.ValidateCredentialPresence(credential); err != nil {
			return err
		}
		if !wire.ValidID(string(credential.ID)) || ids[credential.ID] || len(credential.RawCredentialID) == 0 || len(credential.RawCredentialID) > 1024 || raw[string(credential.RawCredentialID)] || credential.Generation == 0 {
			return wire.Invalid("enrollment credential identity or generation is ambiguous")
		}
		key, err := x509.ParsePKIXPublicKey(credential.PublicKeyDER)
		if err != nil {
			return wire.Invalid("enrollment credential has no valid public key")
		}
		valid := false
		switch key := key.(type) {
		case *ecdsa.PublicKey:
			valid = credential.Algorithm == "ES256" && key.Curve == elliptic.P256() && key.Curve.IsOnCurve(key.X, key.Y)
		case ed25519.PublicKey:
			valid = credential.Algorithm == "EdDSA" && len(key) == ed25519.PublicKeySize
		case *rsa.PublicKey:
			valid = credential.Algorithm == "RS256" && key.N.BitLen() >= 2048 && key.E >= 65537
		}
		if !valid {
			return wire.Invalid("enrollment credential algorithm differs from its public key")
		}
		ids[credential.ID], raw[string(credential.RawCredentialID)] = true, true
	}
	return nil
}

func (s *Service) enrollmentWrites(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.ID) error {
	if input.Internal == nil || input.Internal.Kind != api.InternalAdminEnroll || !boundInternalActor(input) || input.Scope.Actor.Kind != "service" ||
		len(input.Writes.Enrollments) != 1 || len(input.Writes.Objects) != 1 {
		return fault(api.CodeForbidden, "enrollment requires the bound fixed administrator ceremony and one evidence object")
	}
	install := input.Writes.Enrollments[0]
	enrollment := install.Enrollment
	if enrollment.Config != s.deps.Config || enrollment.Generation != install.ExpectedGeneration+1 {
		return wire.Invalid("invalid enrollment configuration or generation")
	}
	if err := validateEnrollment(enrollment); err != nil {
		return err
	}
	metadata, data, err := objectRow(ctx, tx, install.CeremonyEvidence.ID)
	if err != nil {
		return err
	}
	object := input.Writes.Objects[0]
	if metadata.Ref != install.CeremonyEvidence || metadata.Ref.Class != "artifact" || metadata.Ref.Bytes == 0 || metadata.Ref.Bytes > api.MaxFrameBytes ||
		metadata.Origin != "service" || metadata.SourceOperationID != operation || metadata.ACL.Config != s.deps.Config || metadata.ACL.Owner != input.Scope.Actor ||
		metadata.ACL.Audience != "owner" || metadata.ACL.LifeID != "" || len(metadata.ACL.Participants) != 0 || object.ObjectKey != metadata.Ref.ID || !bytes.Equal(object.Bytes, data) {
		return fault(api.CodeForbidden, "enrollment lacks its exact private retained ceremony attestation")
	}
	challenge, err := s.checkedEnrollment(ctx, tx, install, data)
	if err != nil {
		return err
	}
	committed := false
	for _, event := range input.Events {
		if event.Kind != "blob.committed" {
			continue
		}
		var ref api.BlobRef
		if err := wire.Decode(event.Payload, &ref); err != nil {
			return err
		}
		committed = committed || ref == install.CeremonyEvidence
	}
	if !committed {
		return fault(api.CodeForbidden, "enrollment evidence lacks its atomic blob.committed event")
	}
	var invited inviteChallenge
	if err := storedProjection(ctx, tx, "invite_challenge", install.ChallengeID, &invited); err == nil {
		if len(input.Guards) != 0 {
			return fault(api.CodeForbidden, "pending registration cannot borrow an approval")
		}
		return s.pendingEnrollment(ctx, tx, install, challenge, invited)
	} else if !absent(err) {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='enrollment'").Scan(&count); err != nil {
		return err
	}
	if install.ExpectedGeneration == 0 {
		if count != 0 {
			return fault(api.CodeConflict, "initial administrator enrollment baseline already exists")
		}
		if len(input.Guards) != 0 {
			return fault(api.CodeForbidden, "initial enrollment cannot borrow another operation's approval")
		}
		for _, credential := range enrollment.Credentials {
			if credential.Counter != 0 || credential.Generation != 1 || credential.Revoked {
				return wire.Invalid("initial enrollment credential is not a fresh administrator baseline")
			}
		}
	} else {
		// A service label plus an approval ID does not prove the separately
		// approved current-key ceremony. Its typed handoff is not frozen here.
		return api.NotImplemented("lb-v2-identity", "approved current-key enrollment change ceremony")
	}
	if err := s.compare(ctx, tx, []api.Compare{{Kind: "enrollment", ID: enrollment.PrincipalID, Generation: install.ExpectedGeneration}}); err != nil {
		return err
	}
	challenge.Consumed = true
	if err := put(ctx, tx, "enrollment_challenge", challenge.ID, 2, challenge); err != nil {
		return err
	}
	if err := put(ctx, tx, "enrollment_ceremony", challenge.Ceremony.CeremonyID, 2, challenge); err != nil {
		return err
	}
	if err := put(ctx, tx, "human_rights", enrollment.PrincipalID, 1, humanRights{CanApprove: true}); err != nil {
		return err
	}
	return put(ctx, tx, "enrollment", enrollment.PrincipalID, enrollment.Generation, enrollment)
}
