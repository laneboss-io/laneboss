package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type enrollmentValidation struct {
	Request api.EnrollmentValidationRequest
	Install api.EnrollmentInstall
}
type enrollmentCommitKey struct{}
type enrollmentCommitAuthority struct {
	Store       *Service
	Intent      api.ID
	Validation  api.ID
	NativeScope api.Scope
}

func (s *Service) ReserveEnrollment(ctx context.Context, request api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result api.EnrollmentChallenge
	if err := s.available(); err != nil {
		return result, err
	}
	if s.deps.Enrollment == nil {
		return result, api.NotImplemented("lb-v2-admin", "protected administrator enrollment installation")
	}
	e := *s.deps.Enrollment
	if err := api.ValidateAdminEnrollmentEndpoint(e); err != nil {
		return result, err
	}
	if request.Config != s.deps.Config || request.Config != e.Config || request.ExpectedGeneration != 0 || !wire.ValidID(string(request.CeremonyID)) || !wire.ValidID(string(request.PrincipalID)) {
		return result, fault(api.CodeForbidden, "initial enrollment ceremony differs from installed configuration")
	}
	err := storedProjection(ctx, s.db, "enrollment_ceremony", request.CeremonyID, &result)
	if err == nil {
		if result.Ceremony != request {
			return api.EnrollmentChallenge{}, fault(api.CodeIdempotencyConflict, "enrollment ceremony ID changed its principal or baseline")
		}
		return result, api.ValidateEnrollmentChallenge(result, request, s.deps.Clock.Now())
	}
	if !absent(err) {
		return result, err
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='enrollment'").Scan(&count); err != nil {
		return result, err
	}
	if count != 0 {
		return result, fault(api.CodeConflict, "initial enrollment baseline is already installed")
	}
	result.ID, err = wire.NewID()
	if err != nil {
		return result, err
	}
	result.Ceremony, result.Origin, result.RPID = request, e.Origin, e.RPID
	result.EndpointGeneration, result.InstallationGeneration = e.InstallationGeneration, e.InstallationGeneration
	result.ExpiresAt = api.Timestamp(s.deps.Clock.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano))
	result.Challenge = make([]byte, 32)
	if _, err := rand.Read(result.Challenge); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if err := api.ValidateEnrollmentChallenge(result, request, s.deps.Clock.Now()); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return api.EnrollmentChallenge{}, err
	}
	defer tx.Rollback()
	if err := put(ctx, tx, "enrollment_ceremony", request.CeremonyID, 1, result); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if err := put(ctx, tx, "enrollment_challenge", result.ID, 1, result); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	return result, tx.Commit()
}

func (s *Service) EnrollmentChallenge(ctx context.Context, config string, id api.ID) (api.EnrollmentChallenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result api.EnrollmentChallenge
	if err := s.available(); err != nil {
		return result, err
	}
	if config != s.deps.Config {
		return result, fault(api.CodeForbidden, "enrollment challenge belongs to another configuration")
	}
	if err := storedProjection(ctx, s.db, "enrollment_challenge", id, &result); err != nil {
		return result, err
	}
	return result, api.ValidateEnrollmentChallenge(result, result.Ceremony, s.deps.Clock.Now())
}

// Called only after the real identity validator has returned. This retains
// its exact private handoff; the native administrator socket is checked again.
func (s *Service) RecordEnrollmentValidation(ctx context.Context, scope api.Scope, request api.EnrollmentValidationRequest, install api.EnrollmentInstall) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if s.deps.Enrollment == nil {
		return api.NotImplemented("lb-v2-admin", "protected administrator endpoint")
	}
	if err := wire.VerifyAdministrator(ctx, *s.deps.Enrollment, scope.Connection, scope.Frame); err != nil {
		return err
	}
	if err := checkEnrollmentFrame(scope.Frame.Bytes(), *s.deps.Enrollment, request); err != nil {
		return err
	}
	return s.retainEnrollmentValidation(ctx, request, install)
}

// Schema/parameter binding is separate from native authority. The caller above
// must verify the real administrator connection before retaining any result.
func checkEnrollmentFrame(raw []byte, endpoint api.AdminEnrollmentEndpoint, request api.EnrollmentValidationRequest) error {
	var frame api.AdminEnrollmentFrame
	if err := wire.DecodeAdminEnrollmentFrame(raw, &frame); err != nil {
		return err
	}
	if err := api.ValidateAdminEnrollmentFrame(frame, endpoint); err != nil {
		return err
	}
	exact, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if frame.Method != "enroll_complete" || !wire.SameJSON(exact, frame.Params) {
		return fault(api.CodeForbidden, "identity validation differs from the native administrator frame")
	}
	return nil
}

func (s *Service) retainEnrollmentValidation(ctx context.Context, request api.EnrollmentValidationRequest, install api.EnrollmentInstall) error {
	var challenge api.EnrollmentChallenge
	if err := storedProjection(ctx, s.db, "enrollment_challenge", request.ChallengeID, &challenge); err != nil {
		return err
	}
	if err := api.ValidateInitialEnrollment(challenge, request, install, s.deps.Clock.Now()); err != nil {
		return err
	}
	value := enrollmentValidation{Request: request, Install: install}
	var prior enrollmentValidation
	err := storedProjection(ctx, s.db, "enrollment_validation", install.ValidationID, &prior)
	if err == nil {
		if !sameValue(prior, value) {
			return fault(api.CodeIdempotencyConflict, "enrollment validation ID changed bytes")
		}
		return nil
	}
	if !absent(err) {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := put(ctx, tx, "enrollment_validation", install.ValidationID, 1, value); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) checkedEnrollment(ctx context.Context, db queryer, install api.EnrollmentInstall, evidence []byte) (api.EnrollmentChallenge, error) {
	var validation enrollmentValidation
	var challenge api.EnrollmentChallenge
	if err := storedProjection(ctx, db, "enrollment_validation", install.ValidationID, &validation); err != nil {
		return challenge, err
	}
	if err := storedProjection(ctx, db, "enrollment_challenge", install.ChallengeID, &challenge); err != nil {
		return challenge, err
	}
	if !sameValue(validation.Install, install) {
		return challenge, fault(api.CodeForbidden, "enrollment install differs from identity validation")
	}
	exact, err := json.Marshal(validation.Request)
	if err != nil {
		return challenge, err
	}
	if !bytes.Equal(exact, evidence) {
		return challenge, fault(api.CodeForbidden, "enrollment evidence differs from exact validated registration bytes")
	}
	return challenge, api.ValidateInitialEnrollment(challenge, validation.Request, install, s.deps.Clock.Now())
}

func (s *Service) stampEnrollment(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.ID) error {
	if len(input.Writes.Enrollments) != 1 {
		return fault(api.CodeForbidden, "enrollment receipt requires one install")
	}
	install := input.Writes.Enrollments[0]
	event, err := authorityEvent(ctx, tx, operation, "blob.committed", install.CeremonyEvidence.ID)
	if err != nil {
		return err
	}
	var ref api.BlobRef
	if err := wire.Decode(event.Payload, &ref); err != nil {
		return err
	}
	if ref != install.CeremonyEvidence {
		return fault(api.CodeIntegrity, "enrollment receipt lost its actual evidence event")
	}
	receipt := api.EnrollmentReceipt{CeremonyID: install.CeremonyID, ChallengeID: install.ChallengeID, PrincipalID: install.Enrollment.PrincipalID, Config: s.deps.Config, Generation: install.Enrollment.Generation, Evidence: ref, OperationID: operation, EventID: event.ID, CommittedSeq: event.Seq}
	for _, credential := range install.Enrollment.Credentials {
		receipt.SimulatedPresence = receipt.SimulatedPresence || credential.SimulatedPresence
	}
	return put(ctx, tx, "enrollment_receipt", install.CeremonyID, 1, receipt)
}

func (s *Service) ReplayEnrollment(ctx context.Context, scope api.Scope, request api.EnrollmentValidationRequest) (api.EnrollmentReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result api.EnrollmentReceipt
	if err := s.available(); err != nil {
		return result, err
	}
	if s.deps.Enrollment == nil {
		return result, api.NotImplemented("lb-v2-admin", "protected enrollment endpoint")
	}
	if err := wire.VerifyAdministrator(ctx, *s.deps.Enrollment, scope.Connection, scope.Frame); err != nil {
		return result, err
	}
	return s.replayEnrollment(ctx, scope.Frame.Bytes(), request)
}

// The public store port above first verifies its native administrator peer.
// This private continuation binds that exact frame before reading any receipt.
func (s *Service) replayEnrollment(ctx context.Context, raw []byte, request api.EnrollmentValidationRequest) (api.EnrollmentReceipt, error) {
	var result api.EnrollmentReceipt
	if err := checkEnrollmentFrame(raw, *s.deps.Enrollment, request); err != nil {
		return result, err
	}
	if err := storedProjection(ctx, s.db, "enrollment_receipt", request.Ceremony.CeremonyID, &result); err != nil {
		return result, err
	}
	var validation enrollmentValidation
	if err := storedProjection(ctx, s.db, "enrollment_validation", result.OperationID, &validation); err != nil {
		return result, err
	}
	if !sameValue(validation.Request, request) {
		return api.EnrollmentReceipt{}, fault(api.CodeIdempotencyConflict, "enrollment replay changed its exact registration bytes")
	}
	return result, nil
}
