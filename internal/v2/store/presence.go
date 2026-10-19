package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) proofCredential(ctx context.Context, db queryer, proof api.VerifiedHumanProof) (api.HumanCredential, error) {
	var enrollment api.HumanEnrollment
	if err := storedProjection(ctx, db, "enrollment", proof.PrincipalID, &enrollment); err != nil {
		return api.HumanCredential{}, err
	}
	if enrollment.Config != s.deps.Config {
		return api.HumanCredential{}, fault(api.CodeForbidden, "proof enrollment belongs to another configuration")
	}
	for _, key := range enrollment.Credentials {
		if key.ID != proof.CredentialID {
			continue
		}
		if key.Revoked {
			return key, fault(api.CodeUnauthenticated, "proof credential was revoked")
		}
		if err := api.ValidateCredentialPresence(key); err != nil {
			return key, err
		}
		if key.SimulatedPresence != proof.SimulatedPresence || proof.Ref.SimulatedPresence != proof.SimulatedPresence {
			return key, fault(api.CodeForbidden, "proof changed enrolled presence provenance")
		}
		return key, nil
	}
	return api.HumanCredential{}, fault(api.CodeUnauthenticated, "proof credential is not enrolled")
}

// Presence comes from retained authority, never a caller-supplied boolean.
func (s *Service) transactionPresence(ctx context.Context, db queryer, input api.Transaction) (bool, error) {
	simulated := false
	for _, install := range input.Writes.Enrollments {
		for _, credential := range install.Enrollment.Credentials {
			if err := api.ValidateCredentialPresence(credential); err != nil {
				return false, err
			}
			simulated = simulated || credential.SimulatedPresence
		}
	}
	proofs := append([]api.VerifiedHumanProof{}, input.Writes.Proofs...)
	for _, guard := range input.Guards {
		if guard.Proof != nil {
			var proof api.VerifiedHumanProof
			if err := storedProjection(ctx, db, "proof", guard.Proof.Proof.ID, &proof); err != nil {
				return false, err
			}
			proofs = append(proofs, proof)
		}
		if guard.Ticket != nil {
			var ticket ticketRecord
			if err := storedProjection(ctx, db, "ticket", guard.Ticket.TicketID, &ticket); err != nil {
				return false, err
			}
			simulated = simulated || ticket.Ticket.SimulatedPresence
		}
		if guard.Approval != nil {
			var approval api.ChangeApproval
			if err := storedProjection(ctx, db, "approval", guard.Approval.ApprovalID, &approval); err != nil {
				return false, err
			}
			simulated = simulated || approval.SimulatedPresence
		}
	}
	for _, proof := range proofs {
		if _, err := s.proofCredential(ctx, db, proof); err != nil {
			return false, err
		}
		simulated = simulated || proof.SimulatedPresence
	}
	for _, application := range input.Writes.Applications {
		var approval api.ChangeApproval
		if err := storedProjection(ctx, db, "approval", application.ApprovalID, &approval); err != nil {
			return false, err
		}
		if application.SimulatedPresence != approval.SimulatedPresence {
			return false, fault(api.CodeForbidden, "application dropped approval presence provenance")
		}
		simulated = simulated || approval.SimulatedPresence
	}
	launchID := input.Scope.LaunchID
	if launchID == "" && input.Internal != nil && input.Internal.Target.LifeID != "" {
		var lane api.Lane
		if err := storedProjection(ctx, db, "lane", input.Internal.Target.LifeID, &lane); err != nil && !absent(err) {
			return false, err
		}
		launchID = lane.LaunchID
	}
	if launchID != "" {
		var data []byte
		err := db.QueryRowContext(ctx, "SELECT operations.data FROM projections JOIN operations ON operations.id=json_extract(projections.data,'$.reservation.operation_id') WHERE kind='launch_plan' AND json_extract(projections.data,'$.reservation.launch_id')=?", string(launchID)).Scan(&data)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if err == nil {
			var origin api.Operation
			if err := json.Unmarshal(data, &origin); err != nil {
				return false, err
			}
			simulated = simulated || origin.SimulatedPresence
		}
	}
	for _, ticket := range input.Writes.Tickets {
		if ticket.SimulatedPresence != simulated {
			return false, fault(api.CodeForbidden, "ticket dropped verified presence provenance")
		}
	}
	for _, session := range input.Writes.ReadSessions {
		if session.Session.SimulatedPresence != simulated {
			return false, fault(api.CodeForbidden, "session dropped verified presence provenance")
		}
	}
	for _, approval := range input.Writes.Approvals {
		if approval.SimulatedPresence != simulated {
			return false, fault(api.CodeForbidden, "approval dropped verified presence provenance")
		}
	}
	return simulated, nil
}

func (s *Service) operationPolicy(ctx context.Context, db queryer) (api.Generation, error) {
	var current api.EffectivePolicy
	err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &current)
	if absent(err) {
		return 0, nil
	} // Primitive configuration/enrollment precedes approved policy.
	return current.Generation, err
}
