package lifecycle

import (
	"context"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPlanWorkerCancellation(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	ready, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	done := make(chan struct{})
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("planner left a worker wait after cancellation")
		}
	})
	f.ports.onStage = func(stage string) {
		if stage == "materialize" {
			close(ready)
			<-release
		}
	}
	result := make(chan error, 1)
	go func() {
		defer close(done)
		_, err := f.service.PlanLaunch(context.Background(), scope, request)
		result <- err
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("planner never reached its fixed worker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	unlock, err := f.service.lockLife(ctx, record.Reservation.Target.LifeID)
	if err != nil {
		t.Fatal("planner held the life gate while waiting for a worker")
	}
	// Model manual stop's committed epoch while the original worker is still
	// waiting. No replacement run or credential may pass that durable fence.
	f.store.mu.Lock()
	f.store.fences[record.Reservation.Target.LifeID]++
	f.store.mu.Unlock()
	unlock()
	unblock()
	select {
	case err := <-result:
		if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || f.ports.calls["acquire"] != 0 ||
			f.ports.calls["capture"] != 0 || f.store.plans[record.Reservation.ID].Phase != "sourced" {
			t.Fatalf("cancelled worker advanced or released its launch plan: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled planner did not release its worker wait")
	}
}
