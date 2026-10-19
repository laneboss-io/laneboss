// Draft.3 runtime dependency binding.
package lifecycle

import (
	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.WatchdogBinder = (*Service)(nil)

func (s *Service) BindWatchdog(watchdog api.Watchdog) error {
	if err := s.ready(); err != nil {
		return err
	}
	if absent(watchdog) {
		return problem(api.CodePrerequisite, "watchdog binding is missing",
			"Bind the constructed service watchdog before dispatch is enabled.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !absent(s.watchdog) {
		return problem(api.CodeConflict, "watchdog is already bound",
			"Keep the original runtime dependency for this service lifetime.")
	}
	s.watchdog = watchdog
	return nil
}
