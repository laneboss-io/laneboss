//go:build linux

package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func invitePort(t *testing.T, s *Service) api.HumanAdmissionStore {
	t.Helper()
	p, ok := any(s).(api.HumanAdmissionStore)
	if !ok {
		t.Fatal("later human invite/redeem/approve port is absent")
	}
	return p
}

// The proof is an explicit verified-identity input in this store component
// test. The real proof consumption, enrollment changes and reads are executed.
func inviteScope(t *testing.T, s *Service, scope api.Scope, r api.HumanAccessRequest) api.Scope {
	t.Helper()
	scope.ReadView = nil
	scope.Request = testRequest(t, "human.enroll", r)
	scope.Request.Config = scope.Config
	var err error
	scope.Request.RequestSHA256, err = wire.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame = &archFrame{raw: enrollmentJSON(t, scope.Request)}
	target, err := s.authorizationTarget(context.Background(), s.db, scope, scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	var enrollment api.HumanEnrollment
	if err := storedProjection(context.Background(), s.db, "enrollment", scope.Actor.ID, &enrollment); err != nil {
		t.Fatal(err)
	}
	proof := api.VerifiedHumanProof{Config: scope.Config, PrincipalID: scope.Actor.ID,
		CredentialID: enrollment.Credentials[0].ID, EndpointClass: api.EndpointHuman,
		EndpointGeneration: scope.EndpointGeneration, Target: target,
		NonceID: testID(t), ConnectionID: scope.Connection.ID(), VerifiedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)),
		Ref: api.ProofRef{ID: testID(t), RequestSHA256: scope.Request.RequestSHA256,
			ExpiresAt: api.Timestamp(s.deps.Clock.Now().Add(time.Minute).UTC().Format(timeFormat))}}
	fixtureProjection(t, s, "proof", proof.Ref.ID, 1, proof)
	scope.Request.Proof = &proof.Ref
	scope.Frame = &archFrame{raw: enrollmentJSON(t, scope.Request)}
	return scope
}

func inviteCommit(t *testing.T, s *Service, scope api.Scope, r api.HumanAccessRequest) (api.HumanAdmission, error) {
	t.Helper()
	p := invitePort(t, s)
	result, err := p.PrepareHumanChange(context.Background(), scope, r)
	if err != nil {
		return result, err
	}
	public := result
	public.Token = ""
	target, err := s.authorizationTarget(context.Background(), s.db, scope, scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	guards := []api.TransactionGuard{}
	if scope.Request.Proof != nil {
		guards = append(guards, api.TransactionGuard{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}})
	}
	event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config,
		Kind: "human.enrollment", Actor: scope.Actor, RequestedBy: scope.Actor,
		Origin: "service", StarterChain: []api.ID{}, Payload: enrollmentJSON(t, public)}
	_, err = s.Transact(context.Background(), api.Transaction{Scope: scope,
		RawRequest: scope.Frame.Bytes(), Reply: &api.RPCReply{Result: enrollmentJSON(t, result)},
		Writes: api.StateWrites{HumanChanges: []api.HumanAdmission{result}}, Events: []api.Event{event}, Guards: guards})
	return result, err
}

func inviteNew(t *testing.T, s *Service, scope api.Scope) api.HumanAdmission {
	t.Helper()
	r := api.HumanAccessRequest{Action: "invite", Role: "human"}
	result, err := inviteCommit(t, s, inviteScope(t, s, scope, r), r)
	if err != nil || result.State != "invited" || result.Token == "" || result.Generation != 1 {
		t.Fatal("actual human invitation failed", err)
	}
	expires, err := time.Parse(timeFormat, string(result.ExpiresAt))
	if err != nil || expires.Before(time.Now().Add(14*time.Minute)) || expires.After(time.Now().Add(15*time.Minute)) {
		t.Fatal("invite did not expire in fifteen minutes", err)
	}
	return result
}

func inviteRegister(t *testing.T, s *Service, invite api.HumanAdmission) (api.EnrollmentInstall, api.HumanAdmission) {
	t.Helper()
	input := enrollmentInput(t)
	input.Scope.Config, input.Internal.Config = s.deps.Config, s.deps.Config
	input.Writes.Objects[0].ACL.Config = s.deps.Config
	input.Events[0].Config = s.deps.Config
	install := &input.Writes.Enrollments[0]
	install.Enrollment.Config = s.deps.Config
	ceremony := api.EnrollmentCeremonyRequest{Config: s.deps.Config, CeremonyID: testID(t), PrincipalID: install.Enrollment.PrincipalID}
	challenge, err := invitePort(t, s).ReserveInvited(context.Background(), api.InvitedEnrollmentRequest{Token: invite.Token, Ceremony: ceremony})
	if err != nil {
		t.Fatal("invited create challenge failed", err)
	}
	client := enrollmentJSON(t, map[string]string{"type": "webauthn.create", "origin": challenge.Origin,
		"challenge": base64.RawURLEncoding.EncodeToString(challenge.Challenge)})
	request := api.EnrollmentValidationRequest{Ceremony: ceremony, ChallengeID: challenge.ID,
		ClientDataJSON: client, AttestationObject: []byte("explicit validated component attestation")}
	raw := enrollmentJSON(t, request)
	object := &input.Writes.Objects[0]
	object.Bytes, object.SHA256 = raw, testDigest(raw)
	install.CeremonyID, install.ChallengeID, install.ValidationID = ceremony.CeremonyID, challenge.ID, input.Internal.ID
	install.Enrollment.Origin, install.Enrollment.RPID = challenge.Origin, challenge.RPID
	install.CeremonyEvidence = api.BlobRef{ID: object.ObjectKey, Class: "artifact", SHA256: object.SHA256, Bytes: int64(len(raw))}
	credential := &install.Enrollment.Credentials[0]
	credential.AAGUID, credential.AttestationFormat = "00000000-0000-0000-0000-000000000000", "none"
	credential.RegistrationEvidence = install.CeremonyEvidence
	input.Events[0].Payload = enrollmentJSON(t, install.CeremonyEvidence)
	if err := s.retainEnrollmentValidation(context.Background(), request, *install); err != nil {
		t.Fatal("explicit identity validation handoff failed", err)
	}
	if _, err := commitEnrollmentFixture(context.Background(), s, input); err != nil {
		t.Fatal("pending registration did not commit", err)
	}
	var pending api.HumanAdmission
	if err := storedProjection(context.Background(), s.db, "human_admission", invite.ID, &pending); err != nil {
		t.Fatal(err)
	}
	if pending.State != "pending" || pending.Fingerprint != testDigest(credential.PublicKeyDER) || pending.PrincipalID != install.Enrollment.PrincipalID {
		t.Fatal("pending registration lost its actual public-key fingerprint")
	}
	return *install, pending
}

func inviteDecision(t *testing.T, s *Service, scope api.Scope, p api.HumanAdmission, action string) api.HumanAdmission {
	t.Helper()
	r := api.HumanAccessRequest{Action: action, InviteID: p.ID, Fingerprint: p.Fingerprint, ExpectedGeneration: p.Generation}
	result, err := inviteCommit(t, s, inviteScope(t, s, scope, r), r)
	if err != nil {
		t.Fatal("human decision failed", err)
	}
	return result
}

func inviteReader(t *testing.T, s *Service, enrollment api.HumanEnrollment) api.Scope {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	c := &scopeConnection{id: testID(t), conn: a, peer: &scopePeer{}, binding: api.InstalledBinding{Config: s.deps.Config, Class: api.EndpointHuman, EndpointGeneration: 7}}
	session := api.StoredReadSession{Session: api.HumanSession{ID: testID(t), Config: s.deps.Config,
		ExpiresAt:     api.Timestamp(time.Now().Add(time.Minute).UTC().Format(timeFormat)),
		IdleExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(timeFormat))},
		PrincipalID: enrollment.PrincipalID, CredentialID: enrollment.Credentials[0].ID, ConnectionID: c.id, EndpointGeneration: 7, Generation: 1}
	fixtureProjection(t, s, "read_session", session.Session.ID, 1, session)
	authority := api.ReadAuthorityFromSession(session)
	c.authority = &authority
	return api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "human", ID: enrollment.PrincipalID}, Connection: c, EndpointGeneration: 7}
}

func TestInvitePending(t *testing.T) {
	s, owner, _ := sessionFixture(t)
	invitePort(t, s)
	invite := inviteNew(t, s, owner)
	install, pending := inviteRegister(t, s, invite)
	page, err := invitePort(t, s).PendingHumans(context.Background(), owner)
	if err != nil || page.Config != s.deps.Config || len(page.Registrations) != 1 || page.Registrations[0].Fingerprint != pending.Fingerprint || page.Registrations[0].Token != "" {
		t.Fatal("D6 did not expose the exact pending fingerprint privately", err)
	}
	journal := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: s.storeID}, Source: "worker"}
	events, err := s.Events(context.Background(), journal, api.EventTailRequest{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events.Events {
		found = found || event.Kind == "human.enrollment"
		if bytes.Contains(event.Payload, []byte(invite.Token)) {
			t.Fatal("journal exposed the one-use invite token")
		}
	}
	if !found {
		t.Fatal("invitation did not reach its actual journal event")
	}
	all, err := s.HumanEnrollments(context.Background(), s.deps.Config)
	if err != nil || len(all) != 1 {
		t.Fatal("pending registration entered active inventory", err)
	}
	reader := inviteReader(t, s, install.Enrollment)
	read, raw := inviteOwnRead(t, s, reader)
	chunk, err := s.Blob(context.Background(), reader, read)
	expectCode(t, err, api.CodeNotFound)
	if len(chunk.Data) != 0 {
		t.Fatal("pending registration read its own private object", err)
	}
	if _, err := s.Policy(context.Background(), reader); err == nil {
		t.Fatal("pending registration read policy")
	}
	if _, err := invitePort(t, s).PendingHumans(context.Background(), reader); err == nil {
		t.Fatal("pending registration read the pending list")
	}
	inviteDecision(t, s, owner, pending, "approve")
	chunk, err = s.Blob(context.Background(), reader, read)
	if err != nil || !bytes.Equal(chunk.Data, raw) {
		t.Fatal("approval did not unlock the same owned object", err)
	}
}

func TestInviteExpiryAndReuse(t *testing.T) {
	for _, mode := range []string{"expired", "used"} {
		t.Run(mode, func(t *testing.T) {
			s, owner, _ := sessionFixture(t)
			invitePort(t, s)
			invite := inviteNew(t, s, owner)
			if mode == "expired" {
				var retained struct {
					Admission api.HumanAdmission
					TokenHash api.Digest
				}
				if err := storedProjection(context.Background(), s.db, "human_invite", invite.ID, &retained); err != nil {
					t.Fatal(err)
				}
				retained.Admission.ExpiresAt = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(timeFormat))
				fixtureProjection(t, s, "human_invite", invite.ID, 1, retained)
			} else {
				inviteRegister(t, s, invite)
			}
			request := api.InvitedEnrollmentRequest{Token: invite.Token, Ceremony: api.EnrollmentCeremonyRequest{Config: s.deps.Config, CeremonyID: testID(t), PrincipalID: testID(t)}}
			if _, err := invitePort(t, s).ReserveInvited(context.Background(), request); err == nil {
				t.Fatal("invitation accepted " + mode)
			}
		})
	}
}

func TestInviteWorkerFence(t *testing.T) {
	s, owner, _ := sessionFixture(t)
	invitePort(t, s)
	_, p := inviteRegister(t, s, inviteNew(t, s, owner))
	for _, action := range []string{"invite", "approve"} {
		r := api.HumanAccessRequest{Action: action, Role: "human"}
		if action == "approve" {
			r = api.HumanAccessRequest{Action: action, InviteID: p.ID, Fingerprint: p.Fingerprint, ExpectedGeneration: p.Generation}
		}
		scope := inviteScope(t, s, owner, r)
		scope.Actor.Kind = "worker"
		if _, err := invitePort(t, s).PrepareHumanChange(context.Background(), scope, r); err == nil {
			t.Fatal("worker reached human " + action)
		}
	}
}

func TestInviteRejected(t *testing.T) {
	s, owner, _ := sessionFixture(t)
	invitePort(t, s)
	install, p := inviteRegister(t, s, inviteNew(t, s, owner))
	rejected := inviteDecision(t, s, owner, p, "reject")
	if rejected.State != "rejected" {
		t.Fatal("rejection was not retained")
	}
	r := api.HumanAccessRequest{Action: "approve", InviteID: p.ID, Fingerprint: p.Fingerprint, ExpectedGeneration: rejected.Generation}
	if _, err := inviteCommit(t, s, inviteScope(t, s, owner, r), r); err == nil {
		t.Fatal("rejected registration later approved")
	}
	reader := inviteReader(t, s, install.Enrollment)
	if _, err := s.Enrollment(context.Background(), reader); err == nil {
		t.Fatal("rejected human became enrolled")
	}
	read, _ := inviteOwnRead(t, s, reader)
	chunk, err := s.Blob(context.Background(), reader, read)
	expectCode(t, err, api.CodeNotFound)
	if len(chunk.Data) != 0 {
		t.Fatal("rejected human read private bytes", err)
	}
}

func TestInviteRevocation(t *testing.T) {
	s, owner, _ := sessionFixture(t)
	invitePort(t, s)
	install, p := inviteRegister(t, s, inviteNew(t, s, owner))
	inviteDecision(t, s, owner, p, "approve")
	reader := inviteReader(t, s, install.Enrollment)
	if _, err := s.Enrollment(context.Background(), reader); err != nil {
		t.Fatal("approved human has no current enrollment", err)
	}
	// The immutable object is genuinely readable before revocation.
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	raw := []byte("new human's own private data")
	object := api.ObjectWrite{ObjectKey: testID(t), Class: "artifact", Bytes: raw, SHA256: testDigest(raw), Origin: "service", ACL: api.ObjectACL{Config: s.deps.Config, Owner: reader.Actor, Audience: "owner", Generation: 1}}
	if _, err := s.retain(ctx, tx, api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}}, object, testID(t), archStamp()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	read := api.BlobReadRequest{ObjectID: object.ObjectKey, Limit: len(raw)}
	chunk, err := s.Blob(ctx, reader, read)
	if err != nil || !bytes.Equal(chunk.Data, raw) {
		t.Fatal("active read control failed", err)
	}
	r := api.HumanAccessRequest{Action: "revoke", PrincipalID: install.Enrollment.PrincipalID, ExpectedGeneration: 1}
	if _, err := inviteCommit(t, s, inviteScope(t, s, owner, r), r); err != nil {
		t.Fatal("revocation failed", err)
	}
	chunk, err = s.Blob(ctx, reader, read)
	if err == nil || len(chunk.Data) != 0 {
		t.Fatal("revocation left an existing session readable", err)
	}
}

func TestInviteDecisionFences(t *testing.T) {
	for _, mode := range []string{"fingerprint", "generation", "missing_proof", "worker_role", "lane_actor"} {
		t.Run(mode, func(t *testing.T) {
			s, owner, _ := sessionFixture(t)
			invitePort(t, s)
			_, p := inviteRegister(t, s, inviteNew(t, s, owner))
			r := api.HumanAccessRequest{Action: "approve", InviteID: p.ID, Fingerprint: p.Fingerprint, ExpectedGeneration: p.Generation}
			if mode == "fingerprint" {
				r.Fingerprint = testDigest([]byte(testID(t)))
			}
			if mode == "generation" {
				r.ExpectedGeneration++
			}
			if mode == "worker_role" {
				r = api.HumanAccessRequest{Action: "invite", Role: "worker"}
			}
			// Invalid role requests are rejected before a proof target exists.
			if mode == "worker_role" {
				if api.ValidateHumanAccess(r) == nil {
					t.Fatal("worker role invitation accepted")
				}
				return
			}
			scope := inviteScope(t, s, owner, r)
			if mode == "lane_actor" {
				scope.Actor.Kind = "lane"
			}
			if mode == "missing_proof" {
				scope.Request.Proof = nil
				scope.Frame = &archFrame{raw: enrollmentJSON(t, scope.Request)}
			}
			_, err := inviteCommit(t, s, scope, r)
			if mode == "lane_actor" {
				expectCode(t, err, api.CodeForbidden)
			} else if err == nil {
				t.Fatal("human decision accepted " + mode)
			}
			all, err := s.HumanEnrollments(context.Background(), s.deps.Config)
			if err != nil || len(all) != 1 {
				t.Fatal("refused decision changed active inventory", err)
			}
		})
	}
}

func TestInviteApproveRights(t *testing.T) {
	s, root, _ := sessionFixture(t)
	invitePort(t, s)
	e, p := inviteRegister(t, s, inviteNew(t, s, root))
	inviteDecision(t, s, root, p, "approve")
	ordinary := inviteReader(t, s, e.Enrollment)
	r := api.HumanAccessRequest{Action: "invite", Role: "human", CanApprove: true}
	if _, err := inviteCommit(t, s, inviteScope(t, s, ordinary, r), r); err == nil {
		t.Fatal("ordinary human delegated the approve right")
	}
	_, pending := inviteRegister(t, s, inviteNew(t, s, ordinary))
	e2, p2 := inviteRegister(t, s, inviteNew(t, s, root))
	inviteDecision(t, s, root, p2, "approve")
	unrelated := inviteReader(t, s, e2.Enrollment)
	r = api.HumanAccessRequest{Action: "approve", InviteID: pending.ID, Fingerprint: pending.Fingerprint, ExpectedGeneration: pending.Generation}
	if _, err := inviteCommit(t, s, inviteScope(t, s, unrelated, r), r); err == nil {
		t.Fatal("unrelated human approved without the approve right")
	}
	approved := inviteDecision(t, s, root, pending, "approve")
	if approved.State != "active" {
		t.Fatal("approve-right holder could not decide another inviter's registration")
	}
}

func TestInviteNativeSelection(t *testing.T) {
	s, root, _ := sessionFixture(t)
	invitePort(t, s)
	install, p := inviteRegister(t, s, inviteNew(t, s, root))
	reader := inviteReader(t, s, install.Enrollment)
	reader.Connection.(*scopeConnection).authority = nil
	request := testRequest(t, "human.challenge", api.HumanChallengeRequest{CredentialID: install.Enrollment.Credentials[0].ID,
		Method: "human.session", TargetID: install.Enrollment.PrincipalID, RequestSHA256: testDigest([]byte("session body"))})
	frame := &archFrame{raw: enrollmentJSON(t, request)}
	ctx := api.WithHumanEntryFrame(context.Background(), frame)
	staging := reader
	staging.Actor.ID = ""
	if _, err := s.Enrollment(ctx, staging); err == nil {
		t.Fatal("pending credential selected an active native principal")
	}
	inviteDecision(t, s, root, p, "approve")
	selected, err := s.Enrollment(ctx, staging)
	if err != nil || selected.PrincipalID != install.Enrollment.PrincipalID {
		t.Fatal("approved key did not select its own native principal", err)
	}
	chunk, err := s.Blob(ctx, reader, api.BlobReadRequest{ObjectID: install.CeremonyEvidence.ID, Limit: 20})
	if err == nil || len(chunk.Data) != 0 {
		t.Fatal("staging selector granted read authority", err)
	}
	r := api.HumanAccessRequest{Action: "revoke", PrincipalID: selected.PrincipalID, ExpectedGeneration: selected.Generation}
	if _, err := inviteCommit(t, s, inviteScope(t, s, root, r), r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enrollment(ctx, staging); err == nil {
		t.Fatal("revoked credential still selected a native principal")
	}
}

// These exports exist only in the Linux test build. The external capture test
// supplies its verified identity/attestation inputs at the same private store
// boundary as this file; capture production and read authorization stay real.
func InviteForTest(t *testing.T, s *Service, owner api.Scope) (api.HumanEnrollment, api.HumanAdmission) {
	t.Helper()
	invitePort(t, s)
	if s.deps.Enrollment == nil {
		s.deps.Enrollment = &api.AdminEnrollmentEndpoint{Config: s.deps.Config,
			Socket: filepath.Join(s.deps.Directory, "admin.sock"), ServiceUID: uint32(os.Geteuid()),
			InstallationGeneration: 1, Origin: "https://ceremony.invalid", RPID: "ceremony.invalid",
			Helper: api.Executable{ID: testID(t), SHA256: testDigest([]byte("component helper")), Version: "component-v1"}}
	}
	install, p := inviteRegister(t, s, inviteNew(t, s, owner))
	return install.Enrollment, p
}

func DecideForTest(t *testing.T, s *Service, owner api.Scope, p api.HumanAdmission, action string) api.HumanAdmission {
	t.Helper()
	return inviteDecision(t, s, owner, p, action)
}
