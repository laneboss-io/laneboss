package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// This runs inside the same writer transaction, after its projections and
// journal append. A proposed result is never its own completion evidence.
func (s *Service) humanReply(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.Operation, raw json.RawMessage) error {
	scope := input.Scope
	if scope.Actor.Kind != "human" || scope.Config != s.deps.Config || scope.Connection == nil || scope.Request.Proof == nil ||
		scope.Connection.Binding().Class != api.EndpointHuman || scope.Connection.Binding().Config != scope.Config ||
		scope.Connection.Binding().EndpointGeneration != scope.EndpointGeneration {
		return fault(api.CodeForbidden, "enrollment reply requires its bound human endpoint and proof")
	}
	var value api.HumanAdmission
	var request api.HumanAccessRequest
	if err := wire.Decode(raw, &value); err != nil {
		return err
	}
	if err := wire.Decode(scope.Request.Params, &request); err != nil {
		return err
	}
	if err := api.ValidateHumanAccess(request); err != nil {
		return err
	}
	if value.Config != scope.Config || value.Role != "human" {
		return fault(api.CodeIntegrity, "enrollment reply has a foreign configuration or role")
	}
	public := value
	public.Token = ""
	switch request.Action {
	case "invite":
		var retained humanInvite
		if err := storedProjection(ctx, tx, "human_invite", value.ID, &retained); err != nil {
			return err
		}
		if value.InviterID != scope.Actor.ID || value.State != "invited" || value.Generation != 1 || value.Token == "" ||
			retained.TokenHash != api.Digest(hash([]byte(value.Token))) || !sameValue(public, retained.Admission) {
			return fault(api.CodeIntegrity, "invite reply differs from its committed inviter, token or projection")
		}
	case "approve", "reject", "revoke":
		var retained api.HumanAdmission
		if err := storedProjection(ctx, tx, "human_admission", value.ID, &retained); err != nil {
			return err
		}
		if value.Token != "" || !sameValue(value, retained) {
			return fault(api.CodeIntegrity, "human decision reply differs from its committed projection")
		}
		if request.Action == "revoke" {
			if value.State != "revoked" || value.PrincipalID != request.PrincipalID || value.EnrollmentGeneration != request.ExpectedGeneration+1 {
				return fault(api.CodeIntegrity, "revocation reply differs from its requested principal or generation")
			}
			if err := s.revokedHumanReply(ctx, tx, value); err != nil {
				return err
			}
		} else {
			if value.ID != request.InviteID || value.Fingerprint != request.Fingerprint || value.Generation != request.ExpectedGeneration+1 ||
				request.Action == "approve" && value.State != "active" || request.Action == "reject" && value.State != "rejected" {
				return fault(api.CodeIntegrity, "decision reply differs from its reviewed key, action or generation")
			}
			var install api.EnrollmentInstall
			if err := storedProjection(ctx, tx, "pending_human", value.ID, &install); err != nil {
				return err
			}
			e := install.Enrollment
			if e.Config != scope.Config || e.PrincipalID != value.PrincipalID || len(e.Credentials) != 1 ||
				api.Digest(hash(e.Credentials[0].PublicKeyDER)) != value.Fingerprint {
				return fault(api.CodeIntegrity, "decision reply lost its validated pending key")
			}
			var active api.HumanEnrollment
			err := storedProjection(ctx, tx, "enrollment", value.PrincipalID, &active)
			if request.Action == "approve" {
				if err != nil {
					return err
				}
				var rights humanRights
				if err := storedProjection(ctx, tx, "human_rights", value.PrincipalID, &rights); err != nil {
					return err
				}
				if !sameValue(active, e) || value.EnrollmentGeneration != active.Generation || rights.CanApprove != value.CanApprove {
					return fault(api.CodeIntegrity, "approval reply differs from its activated enrollment or rights")
				}
			} else if !absent(err) {
				if err != nil {
					return err
				}
				return fault(api.CodeIntegrity, "rejected registration has an active enrollment")
			}
		}
	}
	var facts api.VerifiedHumanProof
	var used api.ProofUseReceipt
	if err := storedProjection(ctx, tx, "proof", scope.Request.Proof.ID, &facts); err != nil {
		return err
	}
	if err := storedProjection(ctx, tx, "proof_use", scope.Request.Proof.ID, &used); err != nil {
		return err
	}
	target, err := s.authorizationTarget(ctx, tx, scope, scope.Request)
	if err != nil {
		return err
	}
	if facts.Config != scope.Config || facts.PrincipalID != scope.Actor.ID || facts.Ref != *scope.Request.Proof || facts.Target != target ||
		facts.EndpointClass != api.EndpointHuman || facts.EndpointGeneration != scope.EndpointGeneration || facts.ConsumedBy != operation.ID ||
		used.OperationID != operation.ID || used.ProofID != facts.Ref.ID || used.CredentialID != facts.CredentialID || used.NonceID != facts.NonceID ||
		used.SimulatedPresence != facts.SimulatedPresence || facts.Ref.SimulatedPresence != facts.SimulatedPresence {
		return fault(api.CodeIntegrity, "enrollment reply lacks its exact consumed human proof")
	}
	event, err := authorityEvent(ctx, tx, operation.ID, "human.enrollment", value.ID)
	if err != nil {
		return err
	}
	var journal api.HumanAdmission
	if wire.Decode(event.Payload, &journal) != nil || !sameValue(journal, public) || event.Actor != scope.Actor || event.RequestedBy != scope.Actor ||
		event.Config != scope.Config || event.RequestID != scope.Request.RequestID || event.Origin != "service" || event.LifeID != "" || event.Run != 0 {
		return fault(api.CodeIntegrity, "enrollment reply differs from its committed human journal event")
	}
	return nil
}

func (s *Service) revokedHumanReply(ctx context.Context, tx *sql.Tx, value api.HumanAdmission) error {
	var active api.HumanEnrollment
	var rights humanRights
	if err := storedProjection(ctx, tx, "enrollment", value.PrincipalID, &active); err != nil {
		return err
	}
	if err := storedProjection(ctx, tx, "human_rights", value.PrincipalID, &rights); err != nil {
		return err
	}
	if active.Config != value.Config || active.PrincipalID != value.PrincipalID || active.Generation != value.EnrollmentGeneration || rights.CanApprove || value.CanApprove || len(active.Credentials) == 0 {
		return fault(api.CodeIntegrity, "revocation reply differs from its revoked enrollment or rights")
	}
	for _, credential := range active.Credentials {
		if !credential.Revoked {
			return fault(api.CodeIntegrity, "revocation reply retained an active credential")
		}
	}
	return nil
}
