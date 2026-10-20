package pollgate

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestLeaseFairness(t *testing.T) {
	var gate Gate
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var held []func()
	defer func() {
		for _, retire := range held {
			retire()
		}
	}()
	// A slow hot lease retains every grant. It must not be allowed to consume
	// all admission capacity before a different lease asks for a fresh check.
	for range pending {
		turn, end := context.WithTimeout(ctx, 100*time.Millisecond)
		retire, err := gate.Enter(turn, "hot-lease")
		end()
		if errors.Is(err, context.DeadlineExceeded) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, retire)
	}
	if len(held) == 0 {
		t.Fatal("hot lease did not establish an active check")
	}
	began := time.Now()
	cold, end := context.WithTimeout(ctx, 250*time.Millisecond)
	defer end()
	retire, err := gate.Enter(cold, "cold-lease")
	if err != nil {
		t.Fatal("hot lease starved a second lease", err)
	}
	retire()
	retire() // Retirement may race cancellation; it must be idempotent.
	t.Logf("hot_active=%d cold_us=%d", len(held), time.Since(began).Microseconds())
	for _, release := range held {
		release()
	}
	held = nil
	// A cancelled hot waiter and retired work must leave no stale owner.
	retire, err = gate.Enter(ctx, "hot-lease")
	if err != nil {
		t.Fatal("cancelled or retired lease retained admission", err)
	}
	retire()

	// Fill the remaining queue behind an active hot check. A cold lease must
	// displace one unstarted hot turn even when all 32 slots are occupied.
	active, err := gate.Enter(ctx, "hot-lease")
	if err != nil {
		t.Fatal(err)
	}
	defer active()
	waitCtx, stopWaiters := context.WithCancel(ctx)
	defer stopWaiters()
	ended := make(chan error, pending-1)
	for range pending - 1 {
		go func() {
			release, err := gate.Enter(waitCtx, "hot-lease")
			if err == nil {
				release()
			}
			ended <- err
		}()
	}
	for {
		gate.mu.Lock()
		used, changed := gate.used, gate.changed
		gate.mu.Unlock()
		if used == pending {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("hot waiters did not fill admission", ctx.Err())
		}
	}
	began = time.Now()
	queuedCold, endCold := context.WithTimeout(ctx, 250*time.Millisecond)
	defer endCold()
	retire, err = gate.Enter(queuedCold, "cold-lease")
	if err != nil {
		t.Fatal("queued hot work starved a cold lease", err)
	}
	retire()
	select {
	case err := <-ended:
		if !errors.Is(err, ErrBusy) {
			t.Fatal("cold lease displaced active work", err)
		}
	case <-ctx.Done():
		t.Fatal("displaced hot waiter did not return", ctx.Err())
	}
	t.Logf("full_queue=%d cold_us=%d evicted=1", pending, time.Since(began).Microseconds())
	stopWaiters()
	for range pending - 2 {
		if err := <-ended; !errors.Is(err, context.Canceled) {
			t.Fatal("hot waiter escaped cancellation", err)
		}
	}
	active()

	// Distinct active leases consume the global bound; none may be evicted.
	for i := range pending {
		release, err := gate.Enter(ctx, fmt.Sprintf("lease-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, release)
	}
	if release, err := gate.Enter(ctx, "overflow-lease"); !errors.Is(err, ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("global admission bound lost", err)
	}
}
