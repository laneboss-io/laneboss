package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func newID() (api.ID, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", refusal(api.CodeIntegrity, "identity entropy is unavailable")
	}
	return api.ID(hex.EncodeToString(bytes[:])), nil
}

func timestamp(now time.Time) api.Timestamp { return api.Timestamp(now.UTC().Format(time.RFC3339Nano)) }

func (s *Service) mutationScope(ctx context.Context, scope api.Scope, method api.Method, body any) error {
	if err := mutationBody(scope, method, body); err != nil {
		return err
	}
	return s.Authorize(ctx, scope, scope.Request)
}

func (s *Service) issueChallenge(ctx context.Context, scope api.Scope, request api.HumanChallengeRequest) (api.HumanChallenge, error) {
	enrollment, err := s.humanEnrollment(ctx, scope)
	if err != nil {
		return api.HumanChallenge{}, err
	}
	if err := s.mutationScope(ctx, scope, "human.challenge", request); err != nil {
		return api.HumanChallenge{}, err
	}
	if len(enrollment.Credentials) == 0 {
		return api.HumanChallenge{}, refusal(api.CodePrerequisite, "no administrator-enrolled human credential")
	}
	id, err := newID()
	if err != nil {
		return api.HumanChallenge{}, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return api.HumanChallenge{}, refusal(api.CodeIntegrity, "challenge entropy is unavailable")
	}
	challenge := api.HumanChallenge{ID: id, Challenge: nonce, Config: scope.Config,
		Method: request.Method, TargetID: request.TargetID, RequestSHA256: request.RequestSHA256,
		BaseGeneration: request.BaseGeneration, Origin: enrollment.Origin, RPID: enrollment.RPID,
		ExpiresAt: timestamp(s.deps.Clock.Now().Add(120 * time.Second))}
	stored := api.StoredChallenge{EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration,
		Challenge: challenge, PrincipalID: scope.Actor.ID, ConnectionID: scope.Connection.ID(), Generation: 1}
	var retained api.HumanChallenge
	err = s.commitHuman(ctx, scope, "human.challenge", challenge,
		api.StateWrites{Challenges: []api.StoredChallenge{stored}}, nil, &retained)
	if err != nil {
		return api.HumanChallenge{}, err
	}
	if !validID(retained.ID) || len(retained.Challenge) < 32 || len(retained.Challenge) > 128 ||
		retained.Config != scope.Config || retained.Method != request.Method || retained.TargetID != request.TargetID ||
		retained.RequestSHA256 != request.RequestSHA256 || retained.BaseGeneration != request.BaseGeneration ||
		retained.Origin != enrollment.Origin || retained.RPID != enrollment.RPID {
		return api.HumanChallenge{}, refusal(api.CodeIntegrity, "challenge receipt differs from its confirmed intent")
	}
	return retained, nil
}

func credentialAlgorithm(credential api.HumanCredential) error {
	key, err := x509.ParsePKIXPublicKey(credential.PublicKeyDER)
	if err != nil {
		return refusal(api.CodeIntegrity, "enrolled credential key cannot be parsed")
	}
	valid := false
	switch key.(type) {
	case *ecdsa.PublicKey:
		valid = credential.Algorithm == "ES256"
	case *rsa.PublicKey:
		valid = credential.Algorithm == "RS256"
	case ed25519.PublicKey:
		valid = credential.Algorithm == "EdDSA"
	}
	if !valid {
		return refusal(api.CodeUnsupported, "enrolled algorithm differs from its supported key")
	}
	return nil
}

func (s *Service) confirmAssertion(ctx context.Context, scope api.Scope, request api.HumanConfirmRequest) (api.ProofRef, error) {
	enrollment, err := s.humanEnrollment(ctx, scope)
	if err != nil {
		return api.ProofRef{}, err
	}
	if err := s.mutationScope(ctx, scope, "human.confirm", request); err != nil {
		return api.ProofRef{}, err
	}
	stored, err := s.deps.Store.Challenge(ctx, scope, request.ChallengeID)
	if err != nil {
		return api.ProofRef{}, err
	}
	challenge := stored.Challenge
	if stored.Consumed || stored.Generation == 0 || stored.PrincipalID != scope.Actor.ID ||
		stored.EndpointClass != api.EndpointHuman || stored.EndpointGeneration != scope.EndpointGeneration ||
		!validID(stored.ConnectionID) || challenge.Config != scope.Config || challenge.ID != request.ChallengeID ||
		challenge.Origin != enrollment.Origin || challenge.RPID != enrollment.RPID {
		return api.ProofRef{}, refusal(api.CodeUnauthenticated, "challenge is consumed or belongs to another principal or endpoint")
	}
	var credential *api.HumanCredential
	for i := range enrollment.Credentials {
		if enrollment.Credentials[i].ID == request.CredentialID {
			if credential != nil {
				return api.ProofRef{}, refusal(api.CodeIntegrity, "duplicate enrolled credential identity")
			}
			credential = &enrollment.Credentials[i]
		}
	}
	if credential == nil || credential.Revoked || credential.Generation == 0 || len(credential.RawCredentialID) == 0 {
		return api.ProofRef{}, refusal(api.CodeUnauthenticated, "credential is not currently enrolled")
	}
	if err := credentialAlgorithm(*credential); err != nil {
		return api.ProofRef{}, err
	}
	counter, err := VerifyAssertion(challenge, credential.ID, credential.PublicKeyDER, credential.Counter, request, s.deps.Clock.Now())
	if err != nil {
		return api.ProofRef{}, err
	}
	proofID, err := newID()
	if err != nil {
		return api.ProofRef{}, err
	}
	evidenceID, err := newID()
	if err != nil {
		return api.ProofRef{}, err
	}
	assertion, err := json.Marshal(request)
	if err != nil {
		return api.ProofRef{}, refusal(api.CodeIntegrity, "verified assertion cannot be retained")
	}
	evidence := api.BlobRef{ID: evidenceID, SHA256: digestBytes(assertion), Bytes: int64(len(assertion)), Class: "artifact"}
	ref := api.ProofRef{ID: proofID, RequestSHA256: challenge.RequestSHA256, ExpiresAt: challenge.ExpiresAt, SimulatedPresence: credential.SimulatedPresence}
	proof := api.VerifiedHumanProof{SimulatedPresence: credential.SimulatedPresence, EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration,
		AssertionEvidence: evidence, Ref: ref, Config: scope.Config, PrincipalID: scope.Actor.ID,
		CredentialID: credential.ID, NonceID: challenge.ID,
		Target: api.HumanChallengeRequest{Method: challenge.Method, TargetID: challenge.TargetID,
			RequestSHA256: challenge.RequestSHA256, BaseGeneration: challenge.BaseGeneration},
		ConnectionID: scope.Connection.ID(), VerifiedAt: timestamp(s.deps.Clock.Now())}
	// Store validates the original generation/unused challenge and counter under
	// the same lock as these writes. No nonce is consumed before that commit.
	stored.Consumed = true
	stored.Generation++
	writes := api.StateWrites{Challenges: []api.StoredChallenge{stored}, Proofs: []api.VerifiedHumanProof{proof},
		Counters: []api.CredentialCounterChange{{CredentialID: credential.ID, ExpectedGeneration: credential.Generation,
			Before: credential.Counter, After: counter}},
		Objects: []api.ObjectWrite{{ObjectKey: evidence.ID, Class: evidence.Class, Bytes: assertion, SHA256: evidence.SHA256,
			ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "private", Generation: 1}, Origin: "identity"}}}
	var retained api.ProofRef
	err = s.commitHuman(ctx, scope, "human.confirmed", ref, writes, nil, &retained)
	if err != nil {
		return api.ProofRef{}, err
	}
	if !validID(retained.ID) || retained.RequestSHA256 != challenge.RequestSHA256 || retained.ExpiresAt != challenge.ExpiresAt || retained.SimulatedPresence != credential.SimulatedPresence {
		return api.ProofRef{}, refusal(api.CodeIntegrity, "proof receipt differs from its verified challenge")
	}
	return retained, nil
}

func (s *Service) operationProof(ctx context.Context, scope api.Scope) (api.VerifiedHumanProof, api.TransactionGuard, error) {
	if scope.Request.Proof == nil {
		return api.VerifiedHumanProof{}, api.TransactionGuard{}, refusal(api.CodeUnauthenticated, "operation proof is required")
	}
	target, err := s.deps.Store.AuthorizationTarget(ctx, scope, scope.Request)
	if err != nil {
		return api.VerifiedHumanProof{}, api.TransactionGuard{}, err
	}
	if target.Method != scope.Request.Method || target.RequestSHA256 != scope.Request.RequestSHA256 {
		return api.VerifiedHumanProof{}, api.TransactionGuard{}, refusal(api.CodeIntegrity, "proof target differs from the authenticated operation")
	}
	proof, err := s.CheckProof(ctx, scope, *scope.Request.Proof, target)
	if err != nil {
		return api.VerifiedHumanProof{}, api.TransactionGuard{}, err
	}
	return proof, api.TransactionGuard{Proof: &api.ProofUse{Proof: proof.Ref, Target: target}}, nil
}

func (s *Service) issueTicket(ctx context.Context, scope api.Scope, request api.TicketIssueRequest) (api.Ticket, error) {
	if _, err := s.humanEnrollment(ctx, scope); err != nil {
		return api.Ticket{}, err
	}
	if err := s.mutationScope(ctx, scope, "ticket.issue", request); err != nil {
		return api.Ticket{}, err
	}
	grants, err := s.deps.Store.Grants(ctx, request.GrantSetID)
	if err != nil {
		return api.Ticket{}, err
	}
	grantExpiry, err := utcTime(grants.ExpiresAt)
	ticketExpiry, ticketErr := utcTime(request.ExpiresAt)
	if err != nil || ticketErr != nil || grants.ID != request.GrantSetID || grants.Revoked || grants.Generation == 0 ||
		grants.ParentLifeID != "" || !s.deps.Clock.Now().Before(grantExpiry) || ticketExpiry.After(grantExpiry) {
		return api.Ticket{}, refusal(api.CodeForbidden, "ticket requires current root grants through its expiry")
	}
	proof, guard, err := s.operationProof(ctx, scope)
	if err != nil {
		return api.Ticket{}, err
	}
	id, err := newID()
	if err != nil {
		return api.Ticket{}, err
	}
	ticket := api.Ticket{SimulatedPresence: proof.SimulatedPresence, ID: id, PrincipalID: scope.Actor.ID, Config: scope.Config, EndpointGeneration: scope.EndpointGeneration,
		Level: request.Level, Role: request.Role, GrantSetID: request.GrantSetID, ExpiresAt: request.ExpiresAt}
	var retained api.Ticket
	err = s.commitHuman(ctx, scope, "ticket.issued", ticket, api.StateWrites{Tickets: []api.Ticket{ticket}},
		[]api.TransactionGuard{guard}, &retained)
	if err != nil {
		return api.Ticket{}, err
	}
	if !validID(retained.ID) || retained.PrincipalID != scope.Actor.ID || retained.Config != scope.Config ||
		retained.EndpointGeneration != scope.EndpointGeneration || retained.Level != request.Level || retained.Role != request.Role ||
		retained.GrantSetID != request.GrantSetID || retained.ExpiresAt != request.ExpiresAt || retained.Redeemed || retained.SimulatedPresence != proof.SimulatedPresence {
		return api.Ticket{}, refusal(api.CodeIntegrity, "ticket receipt differs from the approved scope")
	}
	return retained, nil
}

func (s *Service) issueReadSession(ctx context.Context, scope api.Scope) (api.HumanSession, error) {
	if nilDependency(s.deps.Sessions) {
		return api.HumanSession{}, api.NotImplemented("lb-v2-service", "private committed session read-back")
	}
	if _, err := s.humanEnrollment(ctx, scope); err != nil {
		return api.HumanSession{}, err
	}
	if err := s.mutationScope(ctx, scope, "human.session", api.HumanSessionRequest{}); err != nil {
		return api.HumanSession{}, err
	}
	proof, guard, err := s.operationProof(ctx, scope)
	if err != nil {
		return api.HumanSession{}, err
	}
	id, err := newID()
	if err != nil {
		return api.HumanSession{}, err
	}
	now := s.deps.Clock.Now()
	session := api.HumanSession{SimulatedPresence: proof.SimulatedPresence, ID: id, Config: scope.Config,
		ExpiresAt: timestamp(now.Add(30 * time.Minute)), IdleExpiresAt: timestamp(now.Add(5 * time.Minute))}
	stored := api.StoredReadSession{Session: session, PrincipalID: scope.Actor.ID, CredentialID: proof.CredentialID,
		ConnectionID: scope.Connection.ID(), EndpointGeneration: scope.EndpointGeneration, Generation: 1}
	var retained api.HumanSession
	err = s.commitHuman(ctx, scope, "human.session", session, api.StateWrites{ReadSessions: []api.StoredReadSession{stored}},
		[]api.TransactionGuard{guard}, &retained)
	if err != nil {
		return api.HumanSession{}, err
	}
	expires, expiryErr := utcTime(retained.ExpiresAt)
	idle, idleErr := utcTime(retained.IdleExpiresAt)
	if !validID(retained.ID) || retained.Config != scope.Config || retained.SimulatedPresence != proof.SimulatedPresence || expiryErr != nil || idleErr != nil || idle.After(expires) ||
		expires.After(now.Add(30*time.Minute)) || idle.After(now.Add(5*time.Minute)) {
		return api.HumanSession{}, refusal(api.CodeIntegrity, "read session receipt exceeds its connection authority")
	}
	return s.finalizeHumanSession(ctx, scope, &retained)
}

func (s *Service) bindReadSession(ctx context.Context, scope api.Scope, retained api.HumanSession, proof api.VerifiedHumanProof, storedSession api.StoredReadSession) (api.HumanSession, error) {
	expires, expiryErr := utcTime(retained.ExpiresAt)
	idle, idleErr := utcTime(retained.IdleExpiresAt)
	liveNow := s.deps.Clock.Now()
	if storedSession.Session != retained || storedSession.PrincipalID != scope.Actor.ID || storedSession.CredentialID != proof.CredentialID ||
		storedSession.ConnectionID != scope.Connection.ID() || storedSession.EndpointGeneration != scope.EndpointGeneration ||
		storedSession.Revoked || storedSession.Generation == 0 || expiryErr != nil || idleErr != nil || !liveNow.Before(expires) || !liveNow.Before(idle) {
		return api.HumanSession{}, refusal(api.CodeUnauthenticated, "session receipt is not bound to this live connection")
	}
	if err := scope.Connection.Peer().Alive(ctx); err != nil {
		return api.HumanSession{}, err
	}
	want := api.ReadAuthorityFromSession(storedSession)
	current, readErr := scope.Connection.ReadAuthority(ctx)
	if readErr == nil {
		if current != want {
			return api.HumanSession{}, refusal(api.CodeConflict, "connection already has another read authority")
		}
		return retained, nil
	}
	var unbound *api.Error
	if !errors.As(readErr, &unbound) || unbound.Code != api.CodeUnauthenticated {
		return api.HumanSession{}, readErr
	}
	if err := scope.Connection.BindReadAuthority(api.ReadAuthorityFromSession(storedSession)); err != nil {
		return api.HumanSession{}, err
	}
	current, err := scope.Connection.ReadAuthority(ctx)
	if err != nil || current != want {
		return api.HumanSession{}, errors.Join(refusal(api.CodeIntegrity, "transport did not retain finalized session authority"), err, scope.Connection.Close())
	}
	return retained, nil
}

func (s *Service) checkReadSession(ctx context.Context, scope api.Scope) error {
	return s.withReadSession(ctx, scope, nil)
}

func (s *Service) withReadSession(ctx context.Context, scope api.Scope, use func(api.ReadAuthority, api.StoredReadSession) error) error {
	authority, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return err
	}
	stored, err := s.deps.Store.ReadSession(ctx, scope, authority.SessionID)
	if err != nil {
		return err
	}
	now := s.deps.Clock.Now()
	expiry, expiryErr := utcTime(stored.Session.ExpiresAt)
	idle, idleErr := utcTime(stored.Session.IdleExpiresAt)
	if expiryErr != nil || idleErr != nil || !now.Before(expiry) || !now.Before(idle) ||
		authority.ConnectionID != scope.Connection.ID() || scope.ReadAuthority != nil && *scope.ReadAuthority != authority ||
		expiry.After(now.Add(30*time.Minute)) || idle.After(now.Add(5*time.Minute)) || stored.Revoked || stored.Generation == 0 ||
		stored.ConnectionID != scope.Connection.ID() || stored.PrincipalID != scope.Actor.ID ||
		stored.Session.Config != scope.Config || stored.EndpointGeneration != scope.EndpointGeneration ||
		authority.SessionID != stored.Session.ID || authority.PrincipalID != stored.PrincipalID ||
		authority.CredentialID != stored.CredentialID || authority.Config != scope.Config ||
		authority.EndpointGeneration != stored.EndpointGeneration || authority.ExpiresAt != stored.Session.ExpiresAt ||
		authority.IdleExpiresAt != stored.Session.IdleExpiresAt || authority.Generation != stored.Generation ||
		authority.SimulatedPresence != stored.Session.SimulatedPresence {
		return refusal(api.CodeUnauthenticated, "read session is expired, revoked or belongs to another connection")
	}
	enrollment, err := s.humanEnrollment(ctx, scope)
	if err != nil {
		return err
	}
	for _, credential := range enrollment.Credentials {
		if credential.ID == stored.CredentialID && !credential.Revoked && credential.Generation > 0 {
			if credential.SimulatedPresence != stored.Session.SimulatedPresence {
				return refusal(api.CodeUnauthenticated, "read session lost verified presence provenance")
			}
			if use != nil {
				return use(authority, stored)
			}
			return nil
		}
	}
	return refusal(api.CodeUnauthenticated, "read session credential is revoked")
}

func (s *Service) commitHuman(ctx context.Context, scope api.Scope, kind api.EventKind, proposed any,
	writes api.StateWrites, guards []api.TransactionGuard, retained any) error {
	if nilDependency(scope.Frame) {
		return refusal(api.CodeUnauthenticated, "human mutation requires the verified request frame")
	}
	payload, err := json.Marshal(proposed)
	if err != nil {
		return refusal(api.CodeIntegrity, "human result cannot be encoded")
	}
	id, err := newID()
	if err != nil {
		return err
	}
	// Identity emits these authoritative events after verifying the human frame.
	// Scope.Source identifies the request transport (for example, cli), not the
	// event's trust origin. Preserve the authenticated requester independently.
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: scope.Config, Kind: kind,
		Actor: scope.Actor, RequestedBy: scope.Actor, RequestID: scope.Request.RequestID,
		StarterChain: []api.ID{}, Origin: "service", Payload: payload}
	transaction := api.Transaction{Scope: scope, RawRequest: append([]byte(nil), scope.Frame.Bytes()...),
		Reply: &api.RPCReply{Result: payload}, Events: []api.Event{event}, Writes: writes, Guards: guards}
	if err := api.ValidateTransactionShape(transaction); err != nil {
		return err
	}
	commit, err := s.deps.Store.Transact(ctx, transaction)
	if err != nil {
		return err
	}
	if commit.Reply == nil || !validID(commit.Operation.ID) || commit.FirstSeq == 0 || commit.LastSeq < commit.FirstSeq ||
		(commit.Reply.Error == nil) == (len(commit.Reply.Result) == 0) {
		return refusal(api.CodeIntegrity, "human mutation has no completed durable receipt")
	}
	if commit.Reply.Error != nil {
		return commit.Reply.Error
	}
	if commit.Operation.Error != nil {
		return commit.Operation.Error
	}
	if commit.Operation.Status != "succeeded" {
		return refusal(api.CodeIntegrity, "human mutation did not complete durably")
	}
	presence := false
	for _, proof := range writes.Proofs {
		presence = presence || proof.SimulatedPresence
	}
	for _, guard := range guards {
		if guard.Proof != nil {
			presence = presence || guard.Proof.Proof.SimulatedPresence
		}
	}
	if commit.Operation.SimulatedPresence != presence {
		return refusal(api.CodeIntegrity, "human operation receipt lost verified presence provenance")
	}
	if err := strictObject(commit.Reply.Result, retained); err != nil {
		return refusal(api.CodeIntegrity, "human mutation returned an invalid typed receipt")
	}
	// A replay may retain different random IDs/nonces from this proposal. The
	// committed reply, rather than the in-memory proposal, is authoritative.
	return nil
}
