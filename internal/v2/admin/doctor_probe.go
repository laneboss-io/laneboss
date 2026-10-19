package admin

import (
	"context"
	"errors"
	"reflect"
	"runtime"

	"laneboss.io/laneboss/internal/v2/api"
)

// BindIsolationProbe is a one-time composition dependency. Binding the probe
// never starts a process or upgrades an unavailable launcher to a ready one.
func (s *Service) BindIsolationProbe(launcher api.Launcher) error {
	if launcher == nil || reflect.ValueOf(launcher).Kind() == reflect.Pointer && reflect.ValueOf(launcher).IsNil() {
		return failure(api.CodeInvalid, "doctor requires a concrete installed launcher probe")
	}
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if s.probe != nil {
		return failure(api.CodeConflict, "the installed isolation probe is already bound")
	}
	s.probe = launcher
	return nil
}

func (s *Service) isolationCapability(parent context.Context) api.Capability {
	check := api.Capability{Name: "isolation.selected_backend", Reason: "installed launcher probe is not bound"}
	s.probeMu.RLock()
	launcher := s.probe
	s.probeMu.RUnlock()
	if launcher == nil {
		return check
	}
	ctx, cancel := context.WithTimeout(parent, isolationProbeTimeout)
	defer cancel()
	result, err := launcher.Probe(ctx)
	if result.Backend != "linux-bwrap-landlock" && result.Backend != "darwin-seatbelt" {
		check.Reason = "installed launcher returned an unknown backend"
		return check
	}
	check.Name = "isolation." + result.Backend
	if err != nil {
		check.Reason = "installed isolation probe failed"
		var typed *api.Error
		if errors.As(err, &typed) {
			check.Reason = typed.Message
		}
		return check
	}
	if ctx.Err() != nil {
		check.Reason = "installed isolation probe deadline or cancellation"
		return check
	}
	if runtime.GOOS != "linux" && result.Backend == "linux-bwrap-landlock" ||
		runtime.GOOS != "darwin" && result.Backend == "darwin-seatbelt" {
		check.Reason = "selected isolation backend is unavailable on this operating system"
		return check
	}
	check.Available = result.Available && len(result.Checks) > 0
	check.Reason = "installed launcher capability checks passed"
	names := map[string]bool{}
	for _, observed := range result.Checks {
		if observed.Name == "" || names[observed.Name] || !observed.Available {
			check.Available = false
		}
		names[observed.Name] = true
	}
	if !check.Available {
		check.Reason = "installed launcher reports unavailable, incomplete or inconsistent capability checks"
	}
	return check
}
