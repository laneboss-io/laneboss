package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type administratorCall struct {
	context.Context
	scope api.Scope
}

type enrollmentStore interface {
	ReplayEnrollment(context.Context, api.Scope, api.EnrollmentValidationRequest) (api.EnrollmentReceipt, error)
	RecordEnrollmentValidation(context.Context, api.Scope, api.EnrollmentValidationRequest, api.EnrollmentInstall) error
	InstallHumanEnrollment(context.Context, api.Scope, api.InternalIntent, api.EnrollmentInstall, api.ObjectWrite) (api.Commit, error)
}

func (s *Server) administratorScope(ctx context.Context) (api.Scope, error) {
	call, ok := ctx.(*administratorCall)
	if !ok || s.options.AdminEnrollment == nil {
		return api.Scope{}, serviceError(api.CodeForbidden, "administrator ceremony requires its verified private connection")
	}
	if err := wire.VerifyAdministrator(ctx, *s.options.AdminEnrollment, call.scope.Connection, call.scope.Frame); err != nil {
		return api.Scope{}, err
	}
	if call.scope.Config != s.options.Config || call.scope.Actor.Kind != "service" || call.scope.Actor.ID != s.controller {
		return api.Scope{}, serviceError(api.CodeForbidden, "administrator channel has a foreign service identity")
	}
	return call.scope, nil
}

func (s *Server) BeginHumanEnrollment(ctx context.Context, request api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	if _, err := s.administratorScope(ctx); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if s.deps.Enrollment == nil {
		return api.EnrollmentChallenge{}, api.NotImplemented("lb-v2-identity", "registration challenge validator")
	}
	if request.Config != s.options.Config || request.ExpectedGeneration != 0 {
		return api.EnrollmentChallenge{}, serviceError(api.CodeForbidden, "administrator baseline ceremony cannot replace registration")
	}
	challenge, err := s.deps.Enrollment.BeginEnrollment(ctx, request)
	if err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if err := api.ValidateEnrollmentChallenge(challenge, request, s.deps.Clock.Now()); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	actual, err := s.deps.Store.EnrollmentChallenge(ctx, request.Config, challenge.ID)
	if err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if !reflect.DeepEqual(challenge, actual) {
		return api.EnrollmentChallenge{}, serviceError(api.CodeIntegrity, "identity returned an unretained enrollment challenge")
	}
	return challenge, nil
}

func (s *Server) CompleteHumanEnrollment(ctx context.Context, request api.EnrollmentValidationRequest) (api.EnrollmentReceipt, error) {
	var receipt api.EnrollmentReceipt
	scope, err := s.administratorScope(ctx)
	if err != nil {
		return receipt, err
	}
	if s.deps.Enrollment == nil {
		return receipt, api.NotImplemented("lb-v2-identity", "WebAuthn registration validation")
	}
	store, ok := s.deps.Store.(enrollmentStore)
	if !ok {
		return receipt, api.NotImplemented("lb-v2-service", "validated administrator commit port")
	}
	prior, err := store.ReplayEnrollment(ctx, scope, request)
	if err == nil {
		return prior, nil
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
		return receipt, err
	}
	// The identity owner verifies the actual create attestation. No local
	// signature/UP/UV substitute or success-on-label path is provided.
	install, err := s.deps.Enrollment.ValidateEnrollment(ctx, request)
	if err != nil {
		return receipt, err
	}
	if err := store.RecordEnrollmentValidation(ctx, scope, request, install); err != nil {
		return receipt, err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return receipt, err
	}
	ref := install.CeremonyEvidence
	if ref.SHA256 != digestBytes(raw) || ref.Bytes != int64(len(raw)) || ref.Class != "artifact" {
		return receipt, serviceError(api.CodeForbidden, "validated registration evidence differs from exact complete bytes")
	}
	object := api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: raw, SHA256: ref.SHA256, Origin: "service", ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "owner", Generation: 1}}
	// Stable ceremony/validation identities make a lost reply replay the same
	// commit; changed input under either retained identity conflicts.
	cause := api.InternalIntent{ID: install.ValidationID, Kind: api.InternalAdminEnroll, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor}
	commit, err := store.InstallHumanEnrollment(ctx, scope, cause, install, object)
	if err != nil {
		return receipt, err
	}
	receipt, err = store.ReplayEnrollment(ctx, scope, request)
	if err != nil {
		return api.EnrollmentReceipt{}, err
	}
	if receipt.OperationID != commit.Operation.ID || receipt.CommittedSeq != commit.LastSeq {
		return api.EnrollmentReceipt{}, serviceError(api.CodeIntegrity, "enrollment reply differs from its committed receipt")
	}
	return receipt, nil
}
