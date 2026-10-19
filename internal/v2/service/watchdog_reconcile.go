package service

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// The installed service owns scheduling. The watchdog has no background loop
// or public swap endpoint. Admission participates in the same freeze/drain
// barrier as effects; a deployment cannot admit a new quota assessment.
func (s *Server) reconcileWatchdog(ctx context.Context) error {
	s.mu.RLock()
	watchdog, paused := s.runtime.Watchdog, s.dispatchPaused
	s.mu.RUnlock()
	if !usableDependency(watchdog) || paused {
		return nil
	}
	driver, ok := watchdog.(interface {
		ReconcileAutomatic(context.Context) error
	})
	if !ok {
		return serviceError(api.CodePrerequisite, "installed watchdog has no automatic reconciliation port")
	}
	release, err := s.admitDispatch(ctx)
	if err != nil {
		s.mu.RLock()
		paused = s.dispatchPaused
		s.mu.RUnlock()
		if paused {
			return nil // The durable freeze owns the next dispatch decision.
		}
		return err
	}
	defer release()
	return driver.ReconcileAutomatic(ctx)
}
