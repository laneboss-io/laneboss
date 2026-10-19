package admin

import (
	"context"
	"runtime"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// The embedded interface deliberately has no launch implementation. A doctor
// probe must only call Probe; it cannot prepare/open a gate as a health check.
type observedProbe struct {
	api.Launcher
	result api.IsolationCapabilities
	err    error
	calls  int
}

func (p *observedProbe) Probe(context.Context) (api.IsolationCapabilities, error) {
	p.calls++
	return p.result, p.err
}

func TestProbeBinding(t *testing.T) {
	s := &Service{}
	if s.isolationCapability(context.Background()).Available {
		t.Fatal("unbound probe claims readiness")
	}
	var empty *observedProbe
	requireCode(t, s.BindIsolationProbe(empty), api.CodeInvalid)
	requireCode(t, s.BindIsolationProbe(nil), api.CodeInvalid)
	probe := &observedProbe{}
	if err := s.BindIsolationProbe(probe); err != nil {
		t.Fatal(err)
	}
	if probe.calls != 0 {
		t.Fatal("binding ran a probe before a doctor request")
	}
	requireCode(t, s.BindIsolationProbe(&observedProbe{}), api.CodeConflict)
}

func TestProbeReadiness(t *testing.T) {
	backend := "linux-bwrap-landlock"
	if runtime.GOOS == "darwin" {
		backend = "darwin-seatbelt"
	}
	probe := &observedProbe{result: api.IsolationCapabilities{Backend: backend, Available: true,
		Checks: []api.Capability{{Name: "kernel-check", Available: true, Reason: "observed"}}}}
	s := &Service{}
	if err := s.BindIsolationProbe(probe); err != nil {
		t.Fatal(err)
	}
	check := s.isolationCapability(context.Background())
	if !check.Available || check.Name != "isolation."+backend || probe.calls != 1 {
		t.Fatal("doctor did not project the actual installed probe")
	}
	probe.result.Checks[0].Available = false
	if s.isolationCapability(context.Background()).Available {
		t.Fatal("acceptance: failed probe is ready")
	}
	probe.result.Checks[0].Available = true
	probe.err = failure(api.CodePrerequisite, "injected unavailable primitive")
	if s.isolationCapability(context.Background()).Available {
		t.Fatal("failed launcher probe claims readiness")
	}
	probe.err = nil
	probe.result.Checks = []api.Capability{}
	if s.isolationCapability(context.Background()).Available {
		t.Fatal("empty launcher checks claim readiness")
	}
	probe.result.Checks = []api.Capability{{Name: "same", Available: true}, {Name: "same", Available: true}}
	if s.isolationCapability(context.Background()).Available {
		t.Fatal("duplicate launcher checks claim readiness")
	}
}

func TestProbePlatform(t *testing.T) {
	backend := "darwin-seatbelt"
	if runtime.GOOS == "darwin" {
		backend = "linux-bwrap-landlock"
	}
	probe := &observedProbe{result: api.IsolationCapabilities{Backend: backend, Available: true,
		Checks: []api.Capability{{Name: "claimed", Available: true}}}}
	s := &Service{}
	if err := s.BindIsolationProbe(probe); err != nil {
		t.Fatal(err)
	}
	check := s.isolationCapability(context.Background())
	if check.Available || check.Name != "isolation."+backend {
		t.Fatal("acceptance: OS mismatch is ready")
	}
}
