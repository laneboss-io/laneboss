package store

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// HealthSnapshot exposes only protocol head metadata to the installed host.
// It is not a scoped read port or another state-opening route.
func (s *Service) HealthSnapshot(ctx context.Context) (api.ReadSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.ReadSnapshot{}, err
	}
	snapshot := api.ReadSnapshot{Config: s.deps.Config, AsOf: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))}
	err := s.db.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&snapshot.LastSeq)
	return snapshot, err
}
