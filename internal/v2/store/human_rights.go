package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// Both preflight and the writer transaction must retain another active
// approving human before revoking an approver. Pending and revoked keys do
// not preserve that authority; legacy baselines use the same rights lookup.
func (s *Service) keepHumanApprover(ctx context.Context, db readDatabase, principal api.ID) error {
	right, err := humanApproveRight(ctx, db, principal)
	if err != nil || !right {
		return err
	}
	rows, err := db.QueryContext(ctx, "SELECT id,data FROM projections WHERE kind='enrollment' AND id<>?", string(principal))
	if err != nil {
		return err
	}
	defer rows.Close()
	var candidates []api.HumanEnrollment
	for rows.Next() {
		var id api.ID
		var raw []byte
		var enrollment api.HumanEnrollment
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		if err := decodeStored(raw, &enrollment); err != nil {
			return err
		}
		if enrollment.Config != s.deps.Config || enrollment.PrincipalID != id || validateEnrollment(enrollment) != nil {
			return fault(api.CodeIntegrity, "approver inventory has a malformed human enrollment")
		}
		for _, credential := range enrollment.Credentials {
			if !credential.Revoked {
				candidates = append(candidates, enrollment)
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, candidate := range candidates {
		right, err := humanApproveRight(ctx, db, candidate.PrincipalID)
		if err != nil {
			return err
		}
		if right {
			return nil
		}
	}
	return fault(api.CodeForbidden, "revocation would remove the last active human approver")
}
