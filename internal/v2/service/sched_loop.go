package service

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type loopCoordinator interface {
	LoopDue(context.Context, api.Scope, api.LifeRef) (api.LoopRequest, bool, error)
	ReserveLoop(context.Context, api.Scope, api.LifeRef) (api.LaunchReservation, error)
}

func (s *Server) reserveDueLoops(ctx context.Context, scope api.Scope, driver loopCoordinator) error {
	if err := api.CheckSchedulerScope(ctx, scope, s.deps.Clock.Now()); err != nil {
		return err
	}
	if !usableDependency(driver) {
		return api.NotImplemented("lb-v2-lifecycle", "private loop reservation coordinator")
	}
	read := api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: s.controller}}
	request := api.ListRequest{Limit: 200}
	for page := 0; page < 32; page++ {
		lanes, err := s.deps.Store.Lanes(ctx, read, request)
		if err != nil {
			return err
		}
		for _, lane := range lanes.Lanes {
			if lane.Cleaned || lane.State != "idle" && lane.State != "verifying" || lane.BudgetRemaining.WallMS <= 0 {
				continue
			}
			target := api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}
			_, due, err := driver.LoopDue(ctx, scope, target)
			if err != nil {
				return err
			}
			if !due {
				continue
			}
			if _, err := driver.ReserveLoop(ctx, scope, target); err != nil {
				return err
			}
		}
		if lanes.Cursor == "" {
			return nil
		}
		if lanes.Cursor == request.Cursor {
			return serviceError(api.CodeIntegrity, "scheduler inventory cursor did not advance")
		}
		request.Cursor = lanes.Cursor
	}
	return serviceError(api.CodeBudget, "scheduler inventory exceeds its bounded tick")
}

func (s *Server) schedulerTick(ctx context.Context) error {
	s.mu.RLock()
	paused, closed, source := s.dispatchPaused, s.closed, s.scheduler
	driver, ok := s.runtime.Lifecycle.(loopCoordinator)
	s.mu.RUnlock()
	if paused || closed {
		return nil // No admission past the installed freeze or close barrier.
	}
	if source == nil || !ok {
		return api.NotImplemented("lb-v2-service", "installed scheduler and private lifecycle ports")
	}
	release, err := s.admitDispatch(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := s.refreshScheduler(ctx); err != nil {
		return err
	}
	source.mu.RLock()
	idle := source.stamp.PolicyGeneration == 0
	source.mu.RUnlock()
	if idle {
		return nil // Wait for policy publication or service cancellation.
	}
	scope, err := api.BindSchedulerScope(ctx, source, s.deps.Clock.Now())
	if err != nil {
		return err
	}
	return s.reserveDueLoops(ctx, scope, driver)
}

func (s *Server) schedulerLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		tick, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := s.schedulerTick(tick)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				s.recordFault(err)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
