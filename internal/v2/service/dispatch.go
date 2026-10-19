package service

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Server) admitDispatch(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.dispatchPaused {
		err := serviceError(api.CodeUnavailable, "installed dispatch is closed or frozen")
		if s.freeze != nil {
			err.OperationID = s.freeze.OperationID
		}
		return nil, err
	}
	if s.activityChanged == nil {
		s.activityChanged = make(chan struct{})
	}
	s.activeDispatches++
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.activeDispatches--
		close(s.activityChanged)
		s.activityChanged = make(chan struct{})
	}, nil
}

func (s *Server) dispatchControl(scope api.Scope) (dispatchStore, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if scope.Config != s.options.Config || scope.Actor.Kind != "service" || scope.Connection != nil || scope.Request.Method != "" || !wire.ValidID(string(scope.Actor.ID)) {
		return nil, serviceError(api.CodeForbidden, "dispatch control requires the internal deployment service")
	}
	if !s.verified || !s.bound || s.closed {
		return nil, serviceError(api.CodePrerequisite, "dispatch host is not bound or is closed")
	}
	control, ok := s.deps.Store.(dispatchStore)
	if !ok {
		return nil, serviceError(api.CodePrerequisite, "store has no durable dispatch controls")
	}
	return control, nil
}

func (s *Server) FreezeDispatch(ctx context.Context, scope api.Scope, request api.FreezeRequest) (api.FreezeReceipt, error) {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	control, err := s.dispatchControl(scope)
	if err != nil {
		return api.FreezeReceipt{}, err
	}
	s.mu.Lock()
	if request.ExpectedInstallationGeneration != s.deps.Binding.InstallationGeneration {
		s.mu.Unlock()
		return api.FreezeReceipt{}, serviceError(api.CodeConflict, "freeze installation generation changed")
	}
	s.dispatchPaused = true // Stop admission before the durable writer barrier.
	s.mu.Unlock()
	receipt, freezeErr := control.FreezeDispatch(ctx, scope, request)
	active, readErr := control.ActiveDispatchFreeze(ctx)
	s.mu.Lock()
	s.freeze, s.dispatchPaused = active, active != nil || readErr != nil
	watchdog := s.runtime.Watchdog
	s.mu.Unlock()
	if freezeErr != nil || readErr != nil {
		return receipt, errors.Join(freezeErr, readErr)
	}
	if active == nil || *active != receipt {
		s.mu.Lock()
		s.dispatchPaused = true
		s.mu.Unlock()
		return receipt, serviceError(api.CodeIntegrity, "committed freeze is not the active barrier")
	}
	targets, err := control.DispatchTargets(ctx)
	if err != nil {
		return receipt, err
	}
	if len(targets) != 0 && watchdog == nil {
		return receipt, serviceError(api.CodePrerequisite, "freeze cannot cancel the bound watchdog")
	}
	for _, target := range targets {
		if err := watchdog.Cancel(ctx, target); err != nil {
			return receipt, err // Durable barrier remains closed for recovery.
		}
	}
	return receipt, nil
}

func (s *Server) DrainDispatch(ctx context.Context, scope api.Scope, receipt api.FreezeReceipt) (api.QuiescenceReceipt, error) {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	control, err := s.dispatchControl(scope)
	if err != nil {
		return api.QuiescenceReceipt{}, err
	}
	active, err := control.ActiveDispatchFreeze(ctx)
	if err != nil {
		return api.QuiescenceReceipt{}, err
	}
	if active == nil || *active != receipt {
		return api.QuiescenceReceipt{}, serviceError(api.CodeConflict, "drain requires the active retained freeze")
	}
	for {
		s.mu.RLock()
		count, changed := s.activeDispatches, s.activityChanged
		s.mu.RUnlock()
		if count == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return api.QuiescenceReceipt{}, contextError(ctx.Err())
		case <-changed:
		}
	}
	requests, err := control.DispatchRequests(ctx)
	if err != nil {
		return api.QuiescenceReceipt{}, err
	}
	if len(requests) != 0 {
		return api.QuiescenceReceipt{}, serviceError(api.CodeUnavailable, "drain still has reserved requests requiring reconciliation")
	}
	effects, err := control.DispatchEffects(ctx)
	if err != nil {
		return api.QuiescenceReceipt{}, err
	}
	if len(effects) != 0 {
		return api.QuiescenceReceipt{}, serviceError(api.CodeUnavailable, "drain still has incomplete or claimed effects")
	}
	// No runtime port exposes the outside capture supervisor's backlog and its
	// complete process inventory. An empty dispatch queue proves neither fact.
	return api.QuiescenceReceipt{}, api.NotImplemented("lb-v2-service", "measured capture and process drain inventory")
}

func (s *Server) ThawDispatch(ctx context.Context, scope api.Scope, receipt api.FreezeReceipt) error {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	control, err := s.dispatchControl(scope)
	if err != nil {
		return err
	}
	// Revalidate executors before allowing any deferred work to start.
	effects, err := control.DispatchEffects(ctx)
	if err != nil {
		return err
	}
	for _, record := range effects {
		if err := supportsEffect(s.runtime, record.Effect); err != nil {
			return err
		}
	}
	if err := control.ThawDispatch(ctx, scope, receipt); err != nil {
		return err
	}
	active, err := control.ActiveDispatchFreeze(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.freeze, s.dispatchPaused = active, active != nil
	s.mu.Unlock()
	return nil
}
