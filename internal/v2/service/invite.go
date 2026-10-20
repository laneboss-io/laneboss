package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

type invitedStore interface {
	api.HumanAdmissionStore
	ReplayInvite(context.Context, api.Scope, api.EnrollmentValidationRequest) (api.EnrollmentReceipt, error)
	RecordInviteValidation(context.Context, api.Scope, api.EnrollmentValidationRequest, api.EnrollmentInstall) error
	InstallHumanEnrollment(context.Context, api.Scope, api.InternalIntent, api.EnrollmentInstall, api.ObjectWrite) (api.Commit, error)
}

func (s *Server) BeginInvitedHuman(ctx context.Context, request api.InvitedEnrollmentRequest) (api.EnrollmentChallenge, error) {
	if _, err := s.administratorScope(ctx); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	store, ok := s.deps.Store.(invitedStore)
	if !ok {
		return api.EnrollmentChallenge{}, api.NotImplemented("lb-v2-service", "invited human registration store")
	}
	if request.Ceremony.Config != s.options.Config || request.Ceremony.ExpectedGeneration != 0 {
		return api.EnrollmentChallenge{}, serviceError(api.CodeForbidden, "invited registration requires a new human in this configuration")
	}
	challenge, err := store.ReserveInvited(ctx, request)
	if err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if err := api.ValidateEnrollmentChallenge(challenge, request.Ceremony, s.deps.Clock.Now()); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	actual, err := s.deps.Store.EnrollmentChallenge(ctx, request.Ceremony.Config, challenge.ID)
	if err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if !reflect.DeepEqual(challenge, actual) {
		return api.EnrollmentChallenge{}, serviceError(api.CodeIntegrity, "invited challenge was not retained exactly")
	}
	return challenge, nil
}

func (s *Server) CompleteInvitedHuman(ctx context.Context, request api.EnrollmentValidationRequest) (api.EnrollmentReceipt, error) {
	var receipt api.EnrollmentReceipt
	scope, err := s.administratorScope(ctx)
	if err != nil {
		return receipt, err
	}
	store, ok := s.deps.Store.(invitedStore)
	if !ok || s.deps.Enrollment == nil {
		return receipt, api.NotImplemented("lb-v2-service", "invited human registration validator and store")
	}
	prior, err := store.ReplayInvite(ctx, scope, request)
	if err == nil {
		return prior, nil
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
		return receipt, err
	}
	install, err := s.deps.Enrollment.ValidateEnrollment(ctx, request)
	if err != nil {
		return receipt, err
	}
	if err := store.RecordInviteValidation(ctx, scope, request, install); err != nil {
		return receipt, err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return receipt, err
	}
	ref := install.CeremonyEvidence
	if ref.SHA256 != digestBytes(raw) || ref.Bytes != int64(len(raw)) || ref.Class != "artifact" {
		return receipt, serviceError(api.CodeForbidden, "invited registration lost its exact validated bytes")
	}
	object := api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: raw, SHA256: ref.SHA256, Origin: "service",
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, Audience: "owner", Generation: 1}}
	intent := api.InternalIntent{ID: install.ValidationID, Kind: api.InternalAdminEnroll, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor}
	commit, err := store.InstallHumanEnrollment(ctx, scope, intent, install, object)
	if err != nil {
		return receipt, err
	}
	receipt, err = store.ReplayInvite(ctx, scope, request)
	if err != nil {
		return api.EnrollmentReceipt{}, err
	}
	if receipt.OperationID != commit.Operation.ID || receipt.CommittedSeq != commit.LastSeq {
		return api.EnrollmentReceipt{}, serviceError(api.CodeIntegrity, "pending registration receipt differs from its exact commit")
	}
	return receipt, nil
}
