package service

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type publicHealthKey struct{}

func buildCapability() api.Capability {
	var modes []string
	if compiledFaults {
		modes = append(modes, "laneboss_faults")
	}
	if compiledAuthenticator {
		modes = append(modes, "laneboss_e2e_authenticator")
	}
	if len(modes) == 0 {
		modes = append(modes, "normal")
	}
	return api.Capability{Name: "build-variant", Available: !compiledFaults && !compiledAuthenticator, Reason: strings.Join(modes, "+")}
}

// These facts exist only after transport has read one native pinned frame.
// They confer no identity, scope, read authority or object access.
type publicHealthObservation struct {
	snapshot api.ReadSnapshot
	peer     wire.SocketPeer
	frame    api.FrameContext
}

func (s *Server) publicHealth(ctx context.Context, request api.Request, frame api.FrameContext, peer wire.SocketPeer) (json.RawMessage, api.Sequence, error) {
	if request.Method != "health" || request.Proof != nil {
		return nil, 0, wire.Invalid("public health accepts only HealthRequest without a proof")
	}
	if request.Config != s.options.Config {
		return nil, 0, serviceError(api.CodeForbidden, "request conflicts with installed configuration")
	}
	if frame == nil || peer.PID <= 0 {
		return nil, 0, serviceError(api.CodeUnsupported, "public health requires native per-message writer evidence")
	}
	s.mu.RLock()
	handler := s.handlers["health"]
	s.mu.RUnlock()
	if handler == nil {
		return nil, 0, api.NotImplemented("lb-v2-service", "health")
	}
	observer, ok := s.deps.Store.(interface {
		HealthSnapshot(context.Context) (api.ReadSnapshot, error)
	})
	if !ok {
		return nil, 0, serviceError(api.CodePrerequisite, "public health requires the service-owned health snapshot")
	}
	snapshot, err := observer.HealthSnapshot(ctx)
	if err != nil {
		return nil, 0, err
	}
	if snapshot.Config != s.options.Config || snapshot.LastSeq >= 1<<53 {
		return nil, 0, serviceError(api.CodeIntegrity, "health snapshot differs from installed configuration or bounds")
	}
	if _, err := time.Parse(time.RFC3339Nano, string(snapshot.AsOf)); err != nil {
		return nil, 0, serviceError(api.CodeIntegrity, "health snapshot has no valid observation time")
	}
	observation := publicHealthObservation{snapshot: snapshot, peer: peer, frame: frame}
	result, err := handler(context.WithValue(ctx, publicHealthKey{}, observation), api.Scope{}, request.Params)
	if err != nil {
		return nil, 0, err
	}
	result, err = s.observedHealth(ctx, result)
	if err != nil {
		return nil, 0, err
	}
	if err := wire.ValidateResult("health", result); err != nil {
		return nil, 0, serviceError(api.CodeIntegrity, "health handler returned an invalid result schema")
	}
	return result, snapshot.LastSeq, nil
}

func (s *Server) observedHealth(ctx context.Context, encoded json.RawMessage) (json.RawMessage, error) {
	var health api.Health
	if err := wire.Decode(encoded, &health); err != nil {
		return nil, err
	}
	s.mu.RLock()
	verified, bound, serving, closed, fault := s.verified, s.bound, s.serving, s.closed, s.fault
	reconciling := s.reconciling
	paused := s.dispatchPaused
	launchReady := s.launchConfigured && s.launchJobsActive && s.launchJobsHealthy
	launcher := s.runtime.Launcher
	routes := true
	for method := range api.Methods {
		if s.handlers[method] == nil {
			routes = false
		}
	}
	for _, method := range []api.Method{"event.tail", "lane.attach"} {
		if s.streams[method] == nil {
			routes = false
		}
	}
	s.mu.RUnlock()
	capabilities := []api.Capability{
		{Name: "launch-recovery-capture", Available: launchReady, Reason: "observed bound LaunchPlanner and active retained launch/capture recovery jobs"},
		{Name: "dispatch", Available: !paused, Reason: "observed durable deployment dispatch barrier"},
		{Name: "installed-transport", Available: verified && bound && serving && !closed, Reason: "observed host binding, runtime and listener state"},
		{Name: "registered-methods", Available: routes, Reason: "observed closed method registry"},
		{Name: "reconciler", Available: fault == nil && bound && reconciling, Reason: "observed active reconciler and runtime fault state"},
	}
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	probe := api.Capability{Name: "isolation", Reason: "installed launcher probe is unavailable"}
	if launcher != nil {
		observed, err := launcher.Probe(probeCtx)
		probe.Available = err == nil && observed.Available && observed.Backend == s.deps.Binding.Backend && len(observed.Checks) != 0
		for _, check := range observed.Checks {
			probe.Available = probe.Available && check.Available
		}
		probe.Reason = "observed installed launcher checks"
	}
	capabilities = append(capabilities, probe)
	health.Capabilities = append(health.Capabilities, capabilities...)
	for _, capability := range health.Capabilities {
		health.Ready = health.Ready && capability.Available
	}
	return json.Marshal(health)
}
