package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type inviteChallenge struct{ InviteID api.ID }

func (s *Service) ReserveInvited(ctx context.Context, request api.InvitedEnrollmentRequest) (api.EnrollmentChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result api.EnrollmentChallenge
	if err := s.available(); err != nil {
		return result, err
	}
	if s.deps.Enrollment == nil {
		return result, api.NotImplemented("lb-v2-admin", "protected invited enrollment endpoint")
	}
	e := *s.deps.Enrollment
	if err := api.ValidateAdminEnrollmentEndpoint(e); err != nil {
		return result, err
	}
	r := request.Ceremony
	id, _, ok := strings.Cut(request.Token, ".")
	if !ok || len(request.Token) > 256 || !wire.ValidID(id) || r.Config != s.deps.Config || r.Config != e.Config ||
		r.ExpectedGeneration != 0 || !wire.ValidID(string(r.CeremonyID)) || !wire.ValidID(string(r.PrincipalID)) {
		return result, wire.Invalid("invited enrollment requires its token and fresh human principal")
	}
	invite, err := s.liveInvite(ctx, s.db, api.ID(id))
	if err != nil {
		return result, err
	}
	digest := hash([]byte(request.Token))
	if subtle.ConstantTimeCompare([]byte(digest), []byte(invite.TokenHash)) != 1 {
		return result, fault(api.CodeForbidden, "invite token differs")
	}
	err = storedProjection(ctx, s.db, "enrollment_ceremony", r.CeremonyID, &result)
	if err == nil {
		var link inviteChallenge
		if err := storedProjection(ctx, s.db, "invite_challenge", result.ID, &link); err != nil {
			return api.EnrollmentChallenge{}, err
		}
		if link.InviteID != invite.Admission.ID || result.Ceremony != r {
			return api.EnrollmentChallenge{}, fault(api.CodeIdempotencyConflict, "invited ceremony changed its principal or invite")
		}
		return result, api.ValidateEnrollmentChallenge(result, r, s.deps.Clock.Now())
	}
	if !absent(err) {
		return result, err
	}
	result.ID, err = wire.NewID()
	if err != nil {
		return result, err
	}
	result.Ceremony, result.Origin, result.RPID = r, e.Origin, e.RPID
	result.InviteID = invite.Admission.ID
	result.EndpointGeneration, result.InstallationGeneration = e.InstallationGeneration, e.InstallationGeneration
	expires, err := time.Parse(timeFormat, string(invite.Admission.ExpiresAt))
	if err != nil {
		return result, err
	}
	result.ExpiresAt = api.Timestamp(minTime(s.deps.Clock.Now().Add(5*time.Minute), expires).UTC().Format(timeFormat))
	result.Challenge = make([]byte, 32)
	if _, err := rand.Read(result.Challenge); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if err := api.ValidateEnrollmentChallenge(result, r, s.deps.Clock.Now()); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return api.EnrollmentChallenge{}, err
	}
	defer tx.Rollback()
	if err := put(ctx, tx, "enrollment_ceremony", r.CeremonyID, 1, result); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if err := put(ctx, tx, "enrollment_challenge", result.ID, 1, result); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if err := put(ctx, tx, "invite_challenge", result.ID, 1, inviteChallenge{invite.Admission.ID}); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	return result, tx.Commit()
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *Service) liveInvite(ctx context.Context, db queryer, id api.ID) (humanInvite, error) {
	var invite humanInvite
	if err := storedProjection(ctx, db, "human_invite", id, &invite); err != nil {
		return invite, err
	}
	a := invite.Admission
	if a.Config != s.deps.Config || a.ID != id || a.State != "invited" || a.Generation != 1 || a.Role != "human" || a.Token != "" || !future(a.ExpiresAt, s.deps.Clock.Now()) {
		return humanInvite{}, fault(api.CodeForbidden, "invitation is expired, used or no longer valid")
	}
	var inviter api.HumanEnrollment
	if err := storedProjection(ctx, db, "enrollment", a.InviterID, &inviter); err != nil {
		return humanInvite{}, err
	}
	if inviter.Config != s.deps.Config || inviter.PrincipalID != a.InviterID {
		return humanInvite{}, fault(api.CodeForbidden, "invite lost its enrolled human inviter")
	}
	for _, key := range inviter.Credentials {
		if !key.Revoked {
			return invite, nil
		}
	}
	return humanInvite{}, fault(api.CodeForbidden, "invite's human inviter is revoked")
}

// The native helper may validate and retain a registration proposal. Only the
// separate human.enroll approval can write it into the active inventory.
func (s *Service) RecordInviteValidation(ctx context.Context, scope api.Scope, request api.EnrollmentValidationRequest, install api.EnrollmentInstall) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if s.deps.Enrollment == nil {
		return api.NotImplemented("lb-v2-admin", "protected invited enrollment endpoint")
	}
	if err := wire.VerifyAdministrator(ctx, *s.deps.Enrollment, scope.Connection, scope.Frame); err != nil {
		return err
	}
	if err := checkEnrollMethod(scope.Frame.Bytes(), *s.deps.Enrollment, request, "invite_complete"); err != nil {
		return err
	}
	var link inviteChallenge
	if err := storedProjection(ctx, s.db, "invite_challenge", request.ChallengeID, &link); err != nil {
		return err
	}
	if _, err := s.liveInvite(ctx, s.db, link.InviteID); err != nil {
		return err
	}
	return s.retainEnrollmentValidation(ctx, request, install)
}

func (s *Service) pendingEnrollment(ctx context.Context, tx *sql.Tx, install api.EnrollmentInstall, challenge api.EnrollmentChallenge, link inviteChallenge) error {
	invite, err := s.liveInvite(ctx, tx, link.InviteID)
	if err != nil {
		return err
	}
	if challenge.InviteID != link.InviteID {
		return fault(api.CodeIntegrity, "invited challenge lost its retained invitation")
	}
	if err := s.uniqueHuman(ctx, tx, install.Enrollment, ""); err != nil {
		return err
	}
	if install.ExpectedGeneration != 0 || install.Enrollment.Generation != 1 || install.Enrollment.PrincipalID == invite.Admission.InviterID {
		return fault(api.CodeForbidden, "invited registration must be a fresh separate human")
	}
	for _, credential := range install.Enrollment.Credentials {
		if credential.Counter != 0 || credential.Generation != 1 || credential.Revoked {
			return wire.Invalid("invited enrollment credential is not a fresh human baseline")
		}
	}
	pending := invite.Admission
	pending.PrincipalID, pending.State, pending.Generation = install.Enrollment.PrincipalID, "pending", 2
	pending.Fingerprint = api.Digest(hash(install.Enrollment.Credentials[0].PublicKeyDER))
	invite.Admission.State, invite.Admission.Generation = "used", 2
	if err := put(ctx, tx, "human_invite", pending.ID, 2, invite); err != nil {
		return err
	}
	if err := put(ctx, tx, "human_admission", pending.ID, 2, pending); err != nil {
		return err
	}
	if err := put(ctx, tx, "pending_human", pending.ID, 1, install); err != nil {
		return err
	}
	challenge.Consumed = true
	if err := put(ctx, tx, "enrollment_challenge", challenge.ID, 2, challenge); err != nil {
		return err
	}
	return put(ctx, tx, "enrollment_ceremony", challenge.Ceremony.CeremonyID, 2, challenge)
}

func (s *Service) ReplayInvite(ctx context.Context, scope api.Scope, request api.EnrollmentValidationRequest) (api.EnrollmentReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.EnrollmentReceipt{}, err
	}
	if s.deps.Enrollment == nil {
		return api.EnrollmentReceipt{}, api.NotImplemented("lb-v2-admin", "protected invited enrollment endpoint")
	}
	if err := wire.VerifyAdministrator(ctx, *s.deps.Enrollment, scope.Connection, scope.Frame); err != nil {
		return api.EnrollmentReceipt{}, err
	}
	return s.replayEnrollMethod(ctx, scope.Frame.Bytes(), request, "invite_complete")
}
