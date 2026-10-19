//go:build linux

package service

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// Done is evaluated only after workerTurn has found a live holder and begun
// waiting. This handshake orders arrivals without sleeps or scheduler guesses.
type turnWaitCtx struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *turnWaitCtx) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

type turnResult struct {
	operation string
	finish    func()
	err       error
	waited    time.Duration
}

func queueTurn(t *testing.T, host *Server, ctx context.Context, lease api.ID, operation string, results chan<- turnResult) {
	t.Helper()
	waitCtx := &turnWaitCtx{Context: ctx, waiting: make(chan struct{})}
	go func() {
		started := time.Now()
		finish, err := host.workerTurn(waitCtx, lease, operation)
		if finish != nil {
			release := finish
			var once sync.Once
			finish = func() { once.Do(release) }
		}
		results <- turnResult{operation, finish, err, time.Since(started)}
	}()
	select {
	case <-waitCtx.waiting:
	case <-ctx.Done():
		t.Fatal("worker did not begin waiting behind its holder")
	}
}

func takeTurn(t *testing.T, ctx context.Context, results <-chan turnResult) turnResult {
	t.Helper()
	select {
	case result := <-results:
		if result.finish != nil {
			t.Cleanup(result.finish)
		}
		return result
	case <-ctx.Done():
		t.Fatal("worker turn did not drain", ctx.Err())
		return turnResult{}
	}
}

type turnObserver struct {
	archiveHelper
	run func(context.Context) error
}

func (h *turnObserver) ObserveArchiveWorker(ctx context.Context, _ archivejob.Job, _ api.EffectLease) (api.ProcessObservation, error) {
	return api.ProcessObservation{}, h.run(ctx)
}

func TestWorkerTurnFair(t *testing.T) {
	// Yield during observation, then release and immediately reacquire on the
	// same P. A broadcast lets this observer steal every turn from the worker.
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	t.Run("observe_loop", func(t *testing.T) {
		host := &Server{}
		lease := api.ID("turn-lease")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		finish, err := host.workerTurn(ctx, lease, "archive_observe")
		if err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		release := func() { once.Do(finish) }
		defer release()
		results := make(chan turnResult, 1)
		queueTurn(t, host, ctx, lease, string(api.WorkerPrincipalRead), results)
		// Release the worker in its own goroutine so an observer blocked behind
		// the reserved turn can continue immediately after the worker finishes.
		completed := make(chan turnResult, 1)
		go func() {
			result := <-results
			if result.finish != nil {
				result.finish()
			}
			completed <- result
		}()
		observations := 0
		helper := &turnObserver{run: func(ctx context.Context) error {
			observations++
			runtime.Gosched()
			return ctx.Err()
		}}
		job := archivejob.Job{Lease: api.WorkerLease{ID: lease}}
		const bound = 100 * time.Millisecond
		started := time.Now()
		release()
		var result turnResult
		stopped := false
	loop:
		for time.Since(started) < bound {
			if _, err := host.observeArchive(ctx, helper, job, api.EffectLease{}); err != nil {
				t.Fatal(err)
			}
			select {
			case result = <-completed:
				break loop
			default:
			}
		}
		if result.finish == nil && result.err == nil {
			stopped = true
			result = takeTurn(t, ctx, completed)
		}
		t.Logf("worker wait %s; observations %d; loop stopped %t", result.waited, observations, stopped)
		if result.err != nil || result.finish == nil || result.waited > bound || stopped {
			t.Fatal("observer starved its waiting worker past 100 ms", result.err)
		}
	})

	for _, cancelled := range []bool{false, true} {
		name := "arrival_order"
		if cancelled {
			name = "cancel_waiter"
		}
		t.Run(name, func(t *testing.T) {
			host := &Server{}
			lease := api.ID("turn-lease")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			finish, err := host.workerTurn(ctx, lease, "archive_observe")
			if err != nil {
				t.Fatal(err)
			}
			var once sync.Once
			release := func() { once.Do(finish) }
			defer release()
			results := make(chan turnResult, 3)
			first, cancelFirst := context.WithCancel(ctx)
			defer cancelFirst()
			operations := []string{string(api.WorkerPrincipalRead), "archive_observe", string(api.WorkerInputRead)}
			queueTurn(t, host, first, lease, operations[0], results)
			for _, operation := range operations[1:] {
				queueTurn(t, host, ctx, lease, operation, results)
			}
			if cancelled {
				cancelFirst()
				result := takeTurn(t, ctx, results)
				var typed *api.Error
				if result.operation != operations[0] || result.finish != nil || !errors.As(result.err, &typed) || typed.Code != api.CodeCancelled {
					t.Fatal("waiting cancellation changed its result", result.err)
				}
				operations = operations[1:]
			}
			select {
			case result := <-results:
				if result.finish != nil {
					result.finish()
				}
				t.Fatal("two holders acquired the same lease")
			default:
			}
			// Another lease must progress while this lease remains occupied.
			other, err := host.workerTurn(ctx, api.ID("other-lease"), "archive_observe")
			if err != nil {
				t.Fatal("one lease blocked another", err)
			}
			other()
			release()
			for _, operation := range operations {
				result := takeTurn(t, ctx, results)
				if result.err != nil || result.finish == nil {
					t.Fatal("queued turn failed", result.err)
				}
				if result.operation != operation {
					t.Errorf("arrival order: got %s, want %s", result.operation, operation)
				}
				runtime.Gosched()
				select {
				case extra := <-results:
					if extra.finish != nil {
						extra.finish()
					}
					t.Fatal("two holders acquired the same lease")
				default:
				}
				result.finish()
			}
			host.mu.RLock()
			turns, flights := len(host.workerTurns), len(host.flights)
			host.mu.RUnlock()
			if turns != 0 || flights != 0 {
				t.Fatal("completed or cancelled waiter leaked its turn")
			}
		})
	}

	for _, failure := range []string{"error", "panic", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			host := &Server{}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			owner, stop := context.WithCancel(ctx)
			defer stop()
			lease := api.ID("turn-lease")
			job := archivejob.Job{Lease: api.WorkerLease{ID: lease}}
			results := make(chan turnResult, 1)
			want := errors.New("observer failed")
			helper := &turnObserver{run: func(context.Context) error {
				queueTurn(t, host, ctx, lease, string(api.WorkerPrincipalRead), results)
				switch failure {
				case "panic":
					panic(want)
				case "cancel":
					stop()
					return owner.Err()
				default:
					return want
				}
			}}
			var recovered any
			var observed error
			func() {
				defer func() { recovered = recover() }()
				_, observed = host.observeArchive(owner, helper, job, api.EffectLease{})
			}()
			if failure == "panic" {
				if recovered != want {
					t.Fatal("observer panic was swallowed or changed", recovered)
				}
			} else {
				if failure == "cancel" {
					want = context.Canceled
				}
				if !errors.Is(observed, want) || recovered != nil {
					t.Fatal("observer failure was swallowed or changed", observed, recovered)
				}
			}
			result := takeTurn(t, ctx, results)
			if result.err != nil || result.finish == nil {
				t.Fatal("failed observer retained the turn", result.err)
			}
			result.finish()
		})
	}
}
