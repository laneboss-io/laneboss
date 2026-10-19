//go:build linux

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestExecutionRefusalTerminal(t *testing.T) {
	for _, mode := range []string{"plain", "wrapped", "joined"} {
		t.Run(mode, func(t *testing.T) {
			refusal := serviceError(api.CodeForbidden, "component execution permission revoked")
			var failure error = refusal
			if mode == "wrapped" {
				failure = fmt.Errorf("execution boundary: %w", refusal)
			}
			if mode == "joined" {
				failure = errors.Join(serviceError(api.CodeConflict, "component sibling claim changed"), refusal)
			}
			host, state, scope, ctx, _ := reconcileFixture(t, "run", failure)
			host.reconcileLoop(ctx)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("execution refusal fixture exceeded its bound")
			}
			blocked, err := state.Service.Effect(context.Background(), scope, state.blocked)
			if err != nil {
				t.Fatal("execution refusal lookup failed", err)
			}
			operation, err := state.Service.Operation(context.Background(), scope, blocked.Effect.OperationID)
			if err != nil {
				t.Fatal("refused operation lookup failed", err)
			}
			if blocked.Outcome == nil || blocked.State != "failed" || operation.Status != "failed" {
				t.Fatal("execution refusal remained pending")
			}
			if blocked.Outcome.Error == nil || operation.Error == nil || operation.Error.Code != api.CodeForbidden || operation.Error.Message != refusal.Message {
				t.Fatal("execution refusal lost its owning error")
			}
			pending, err := state.Service.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
			if err != nil || len(pending) != 1 || pending[0].HelperRelease == nil || pending[0].OperationID == blocked.Effect.OperationID {
				t.Fatal("terminal refusal was eligible for another attempt", err)
			}
			page, err := state.Service.Events(context.Background(), scope, api.EventTailRequest{LifeID: blocked.Effect.Context.Target.LifeID, Run: blocked.Effect.Context.Target.Run})
			if err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, event := range page.Events {
				if event.Kind == "operation.failed" && event.OperationID == operation.ID {
					var payload api.OperationEvent
					if err := wire.Decode(event.Payload, &payload); err != nil {
						t.Fatal(err)
					}
					if payload.Operation.Status != "failed" || payload.Operation.Error == nil || payload.Operation.Error.Code != api.CodeForbidden {
						t.Fatal("refusal failure event changed its outcome")
					}
					found++
				}
			}
			if found != 1 {
				t.Fatal("execution refusal did not retain one failure event")
			}
			host.mu.RLock()
			fault := host.fault
			host.mu.RUnlock()
			if fault != nil {
				t.Fatal("terminal refusal retired the reconciler", fault)
			}
		})
	}
}

type reservationRecoveryProbe struct {
	*store.Service
	mu    sync.Mutex
	calls int
}

func (p *reservationRecoveryProbe) RecoverReservations(ctx context.Context) error {
	if err := p.Service.RecoverReservations(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	return nil
}

func TestFrozenReservationRecovery(t *testing.T) {
	host := fixtureServer(t)
	actual, err := store.New(store.Dependencies{Config: host.options.Config, Directory: privateHostDirectory(t), Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := actual.Close(); err != nil {
			t.Error(err)
		}
	})
	probe := &reservationRecoveryProbe{Service: actual}
	host.deps.Store, host.dispatchPaused = probe, true
	paused, err := host.prepareReconcile(context.Background())
	if err != nil || !paused {
		t.Fatal("frozen recovery preparation failed", err)
	}
	probe.mu.Lock()
	calls := probe.calls
	probe.mu.Unlock()
	if calls != 1 {
		t.Fatal("deployment freeze prevented reservation recovery")
	}
}

func TestReservationRecoveryFault(t *testing.T) {
	host := fixtureServer(t)
	actual, err := store.New(store.Dependencies{Config: host.options.Config, Directory: privateHostDirectory(t), Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	host.deps.Store = actual
	if err := actual.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = host.prepareReconcile(context.Background())
	if err == nil {
		t.Fatal("reservation recovery discarded its store failure")
	}
	codeIs(t, err, api.CodeUnavailable)
}

type serviceRecoveryClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *serviceRecoveryClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *serviceRecoveryClock) advance(d time.Duration) {
	c.mu.Lock()
	c.at = c.at.Add(d)
	c.mu.Unlock()
}

func TestMutationRetirementRecovery(t *testing.T) {
	host := fixtureServer(t)
	clock := &serviceRecoveryClock{at: time.Now().UTC()}
	actual, err := store.New(store.Dependencies{Config: host.options.Config, Directory: privateHostDirectory(t), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := actual.Close(); err != nil {
			t.Error(err)
		}
	})
	host.deps.Store, host.deps.Clock = actual, clock
	request := requestFor(t, "blob.begin", api.BlobBeginRequest{Class: "report", SHA256: fx.Digest(nil)})
	scope := api.Scope{Config: request.Config, Actor: api.Actor{Kind: "service", ID: fixtureID(t)}, Source: "worker", Request: request}
	called := false
	if err := host.Register(request.Method, func(_ context.Context, actual api.Scope, _ json.RawMessage) (json.RawMessage, error) {
		called = true
		// Deliberately omit the required commit. The dispatcher must refuse this
		// handler result, then retire its invocation so recovery can seal it.
		return json.Marshal(api.BlobUpload{ObjectID: actual.Request.RequestID, MaxChunkBytes: 1024, ExpiresAt: api.Timestamp(clock.Now().Add(time.Minute).Format(time.RFC3339Nano))})
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err = host.dispatchMutation(context.Background(), scope, request)
	if !called {
		t.Fatal("mutation retirement fixture did not reach its handler")
	}
	codeIs(t, err, api.CodeIntegrity)
	clock.advance(31 * time.Second)
	if err := actual.RecoverReservations(context.Background()); err != nil {
		t.Fatal(err)
	}
	key := api.RequestKey{Method: request.Method, IdempotencyKey: request.IdempotencyKey, RequestSHA256: request.RequestSHA256}
	receipt, err := actual.LookupReceipt(context.Background(), scope, key)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Reply == nil || receipt.Operation.Status != "failed" {
		t.Fatal("returned mutation kept its reservation live")
	}
}

func TestEffectRetryBackoff(t *testing.T) {
	retries := make(effectRetries)
	id, other := fixtureID(t), fixtureID(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !retries.ready(id, now) {
		t.Fatal("new effect was delayed without a refusal")
	}
	retries.refused(id, now)
	if retries.ready(id, now.Add(time.Millisecond)) {
		t.Fatal("refused effect retried before its backoff")
	}
	if !retries.ready(other, now) {
		t.Fatal("one effect delayed an unrelated effect")
	}
	if !retries.ready(id, now.Add(time.Second)) {
		t.Fatal("first retry never became eligible")
	}
	for i := 0; i < 20; i++ {
		retries.refused(id, now)
	}
	if retries.ready(id, now.Add(time.Second)) || !retries.ready(id, now.Add(30*time.Second)) {
		t.Fatal("effect retry backoff did not grow to its bounded cap")
	}
	retries.completed(id)
	if !retries.ready(id, now) {
		t.Fatal("completed effect retained its backoff")
	}
}
