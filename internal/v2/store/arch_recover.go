package store

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

// Reconcile the retained native freeze after interruption. No new operation,
// proof, job, receipt, grant set or worker identity is allocated on this path.
func (s *Service) RecoverArchives(ctx context.Context) error {
	s.mu.RLock()
	if err := s.available(); err != nil {
		s.mu.RUnlock()
		return err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='archive_job' AND json_extract(data,'$.Phase')='freezing' ORDER BY id")
	if err != nil {
		s.mu.RUnlock()
		return err
	}
	records := []archiveRecord{}
	for rows.Next() {
		var raw []byte
		var r archiveRecord
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			s.mu.RUnlock()
			return err
		}
		if err := decodeStored(raw, &r); err != nil {
			rows.Close()
			s.mu.RUnlock()
			return err
		}
		records = append(records, r)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	s.mu.RUnlock()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, r := range records {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if future(r.NextFreeze, s.deps.Clock.Now()) {
			continue
		}
		if _, err := s.attemptArchive(ctx, r); err != nil {
			// Expected native/fence failures are either terminal or durably
			// backed off. Only failure to retain that outcome is store-fatal.
			var retained *archiveAttemptOutcome
			if !errors.As(err, &retained) {
				return err
			}
		}
	}
	return nil
}

func (s *Service) ArchiveOutcome(ctx context.Context, scope api.Scope, id api.ID) (api.EffectOutcome, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return api.EffectOutcome{}, err
	}
	var r archiveRecord
	if err := storedProjection(ctx, s.db, "archive_job", id, &r); err != nil {
		return api.EffectOutcome{}, err
	}
	if r.Commit == nil {
		return api.EffectOutcome{}, fault(api.CodeNotFound, "archive outcome awaits verified completion")
	}
	record, err := effectRow(ctx, s.db, r.Job.Lease.EffectID)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	if record.Outcome == nil || record.Outcome.Status != "succeeded" && record.Outcome.Status != "failed" {
		return api.EffectOutcome{}, fault(api.CodeIntegrity, "verified archive lost its completed original effect")
	}
	return *record.Outcome, nil
}
