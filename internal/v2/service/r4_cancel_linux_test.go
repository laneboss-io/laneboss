//go:build linux

package service

import (
	"context"
	"errors"
	"testing"
)

func TestReconcileStopsCanceledPage(t *testing.T) {
	host, state, scope, ctx, active := reconcileFixture(t, "", nil)
	other := state.blocked
	// Deterministic ordering: completing the first effect cancels the loop's
	// parent while a second real effect is still in the fetched page.
	state.blocked = state.next
	host.reconcileLoop(ctx)
	host.mu.RLock()
	fault := host.fault
	host.mu.RUnlock()
	if !errors.Is(ctx.Err(), context.Canceled) || fault != nil || !*active {
		t.Fatal("reconciler read beyond its canceled effect page", fault)
	}
	unstarted, err := state.Service.Effect(context.Background(), scope, other)
	if err != nil || unstarted.Outcome != nil {
		t.Fatal("canceled page fabricated another effect completion", err)
	}
}
