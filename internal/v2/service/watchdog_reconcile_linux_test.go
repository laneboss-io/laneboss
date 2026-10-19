//go:build linux

package service

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type automaticWatchdogProbe struct {
	api.Watchdog
	calls int
	stop  context.CancelFunc
}

func (p *automaticWatchdogProbe) ReconcileAutomatic(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.calls++
	p.stop()
	return nil
}

func TestReconcilerDrivesWatchdog(t *testing.T) {
	f := fx.New(t)
	host := fixtureServer(t)
	host.options.Config = f.Deps.Config
	host.deps.Store, host.deps.Clock = f.State, f.Deps.Clock
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	probe := &automaticWatchdogProbe{stop: stop}
	host.runtime.Watchdog = probe
	host.reconcileLoop(ctx)
	if probe.calls != 1 || host.fault != nil {
		t.Fatal("installed reconciler did not drive the watchdog independently of pending effects", probe.calls, host.fault)
	}
}

func TestFrozenReconcilerNoWatchdog(t *testing.T) {
	f := fx.New(t)
	host := fixtureServer(t)
	host.options.Config = f.Deps.Config
	host.deps.Store, host.deps.Clock = f.State, f.Deps.Clock
	host.dispatchPaused = true
	ctx, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stop()
	probe := &automaticWatchdogProbe{stop: stop}
	host.runtime.Watchdog = probe
	host.reconcileLoop(ctx)
	if probe.calls != 0 || host.fault != nil {
		t.Fatal("frozen dispatch ran the watchdog", probe.calls, host.fault)
	}
}
