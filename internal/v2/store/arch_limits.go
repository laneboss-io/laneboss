package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// ArchiveLimits is installation configuration, never worker/request input.
// Zero count limits derive from the approved memory/disk budget. Existing
// 4096-object and 60-second preparation allowances remain minimum floors.
type ArchiveLimits struct {
	SnapshotObjects   uint64
	CollectionObjects uint64
	PreparationMS     int64
}

func (l ArchiveLimits) validate() error {
	if l.SnapshotObjects != 0 && l.SnapshotObjects < 4096 || l.CollectionObjects != 0 && l.CollectionObjects < 4096 || l.PreparationMS != 0 && l.PreparationMS < 60000 || l.SnapshotObjects > 1<<53-1 || l.CollectionObjects > 1<<53-1 || l.PreparationMS > int64((1<<63-1)/int64(time.Millisecond))/2 {
		return fault(api.CodeInvalid, "installation archive limits must retain their minimum floors and finite ceilings")
	}
	return nil
}
func (l ArchiveLimits) resolved(b api.Budget) ArchiveLimits {
	parts := b.DiskBytes/uint64(api.MaxChunkBytes) + 1
	if l.SnapshotObjects == 0 {
		l.SnapshotObjects = max(uint64(4096), b.MemoryBytes/256, parts+4096)
	}
	if l.CollectionObjects == 0 {
		l.CollectionObjects = max(uint64(4096), b.MemoryBytes/512, 2*parts+l.SnapshotObjects)
	}
	if l.PreparationMS == 0 {
		l.PreparationMS = 60000
	}
	return l
}
func archiveDeadline(now time.Time, b api.Budget, l ArchiveLimits) (time.Time, error) {
	l = l.resolved(b)
	if err := l.validate(); err != nil {
		return time.Time{}, err
	}
	maximum := int64((1<<63 - 1) / int64(time.Millisecond))
	if b.WallMS <= 0 || b.WallMS > maximum-l.PreparationMS {
		return time.Time{}, fault(api.CodeBudget, "archive wall/preparation budget exceeds a finite deadline")
	}
	return now.Add(time.Duration(max(int64(60000), b.WallMS)+l.PreparationMS) * time.Millisecond), nil
}

// A new optional service port sizes the original claim to its retained archive
// budget. It grants no renewal or extension of the worker/source grant expiry.
func (s *Service) OwnedEffectDeadline(ctx context.Context, scope api.Scope, id api.ID) (api.Timestamp, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return "", err
	}
	effect, err := effectRow(ctx, s.db, id)
	if err != nil {
		return "", err
	}
	now := s.deps.Clock.Now()
	floor := now.Add(30 * time.Second)
	var r archiveRecord
	if effect.Effect.Worker != nil && effect.Effect.Worker.Kind == "archive" {
		if err := storedProjection(ctx, s.db, "archive_job", effect.Effect.OperationID, &r); err != nil {
			return "", err
		}
		end, err := time.Parse(time.RFC3339Nano, string(r.Job.Lease.ExpiresAt))
		if err != nil {
			return "", err
		}
		if floor.After(end) {
			end = floor
		}
		return api.Timestamp(end.UTC().Format(timeFormat)), nil
	}
	if effect.Effect.Clean != nil {
		var raw []byte
		if err := s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='archive_job' AND json_extract(data,'$.Input.receipt_id')=?", string(effect.Effect.Clean.ArchiveReceiptID)).Scan(&raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return api.Timestamp(floor.UTC().Format(timeFormat)), nil
			}
			return "", err
		}
		if err := decodeStored(raw, &r); err != nil {
			return "", err
		}
		end, err := archiveDeadline(now, r.Job.Plan.Budget, r.Limits)
		if err != nil {
			return "", err
		}
		return api.Timestamp(end.UTC().Format(timeFormat)), nil
	}
	return api.Timestamp(floor.UTC().Format(timeFormat)), nil
}
