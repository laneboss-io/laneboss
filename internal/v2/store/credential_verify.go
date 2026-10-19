package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) verifyCredentialProjections(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM projections WHERE kind='credential_projection' ORDER BY id")
	if err != nil {
		return err
	}
	var ids []api.ID
	for rows.Next() {
		var id api.ID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, id := range ids {
		if _, err := s.credentialRow(ctx, s.db, id); err != nil {
			return err
		}
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='credential_projection_id'").Scan(&count); err != nil {
		return err
	}
	if count != len(ids) {
		return fault(api.CodeIntegrity, "credential projection reverse index contains an orphan")
	}
	return nil
}
