//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Both dispatchers first observe the genuine absent receipt. The barrier only
// controls scheduling; the store's writer decides the one actual winner.
type reservationRaceStore struct {
	*store.Service
	misses         atomic.Int32
	bothMissed     chan struct{}
	releaseLookups chan struct{}
	awaited        chan struct{}
}

type withoutAtomicStore struct{ api.StateStore }

type changedAtomicStore struct {
	*store.Service
	problem string
}

func (s changedAtomicStore) ReserveMutation(ctx context.Context, request api.RequestReservation) (api.MutationReceipt, bool, error) {
	receipt, won, err := s.Service.ReserveMutation(ctx, request)
	if err == nil && won {
		if s.problem == "foreign_config" {
			receipt.Config = "other-fixture"
		} else {
			receipt.RawRequest = []byte("{}")
		}
	}
	return receipt, won, err
}

func TestMutationReservationPins(t *testing.T) {
	for _, problem := range []string{"foreign_config", "foreign_frame"} {
		t.Run(problem, func(t *testing.T) {
			directory := privateHostDirectory(t)
			state, err := store.New(store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := state.Close(); err != nil {
					t.Error(err)
				}
			}()
			host := fixtureServer(t)
			host.deps.Store = changedAtomicStore{Service: state, problem: problem}
			request := requestFor(t, "blob.begin", api.BlobBeginRequest{Class: "report", SHA256: fx.Digest(nil)})
			scope := api.Scope{Config: request.Config, Actor: api.Actor{Kind: "service", ID: fixtureID(t)}, Source: "worker", Request: request}
			called := false
			if err := host.Register(request.Method, func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
				called = true
				return nil, serviceError(api.CodeIntegrity, "unbound reservation reached preflight")
			}); err != nil {
				t.Fatal(err)
			}
			_, _, err = host.dispatchMutation(context.Background(), scope, request)
			if called {
				t.Fatal("mutation reservation accepted " + problem)
			}
			codeIs(t, err, api.CodeIntegrity)
		})
	}
}

func TestMutationNeedsAtomicStore(t *testing.T) {
	t.Run("missing_port", func(t *testing.T) {
		directory := privateHostDirectory(t)
		state, err := store.New(store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := state.Close(); err != nil {
				t.Error(err)
			}
		}()
		host := fixtureServer(t)
		host.deps.Store = withoutAtomicStore{state}
		request := requestFor(t, "blob.begin", api.BlobBeginRequest{Class: "report", SHA256: fx.Digest(nil)})
		scope := api.Scope{Config: request.Config, Actor: api.Actor{Kind: "service", ID: fixtureID(t)}, Source: "worker", Request: request}
		called := false
		if err := host.Register(request.Method, func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
			called = true
			return nil, serviceError(api.CodeIntegrity, "unowned preflight ran")
		}); err != nil {
			t.Fatal(err)
		}
		_, _, err = host.dispatchMutation(context.Background(), scope, request)
		if called {
			t.Fatal("dispatcher without atomic winner ran preflight")
		}
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-service" || typed.Message != "atomic mutation reservation ownership is not implemented" {
			t.Fatal("missing atomic reservation support lost its typed refusal", err)
		}
	})
}

func (s *reservationRaceStore) LookupReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	receipt, err := s.Service.LookupReceipt(ctx, scope, key)
	var typed *api.Error
	if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
		n := s.misses.Add(1)
		if n == 2 {
			close(s.bothMissed)
		}
		if n <= 2 {
			select {
			case <-ctx.Done():
				return receipt, ctx.Err()
			case <-s.releaseLookups:
			}
		}
	}
	return receipt, err
}

func (s *reservationRaceStore) AwaitReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	select {
	case s.awaited <- struct{}{}:
	default:
	}
	return s.Service.AwaitReceipt(ctx, scope, key)
}

func TestMutationRetryAwaitsWinner(t *testing.T) {
	t.Run("same_request", func(t *testing.T) {
		f := fx.Ready(t, true)
		f.Opened(t)
		scope := f.LaneScope(t)
		request := requestFor(t, "lane.stop", api.StopRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation, Reason: f.Start.Task})
		request.Config = f.Deps.Config
		var err error
		request.RequestSHA256, err = wire.RequestDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		scope.Request = request
		scope.Frame = &fx.Frame{Raw: fx.JSON(t, request)}
		key := api.RequestKey{Method: request.Method, IdempotencyKey: request.IdempotencyKey, RequestSHA256: request.RequestSHA256}
		ledger := &reservationRaceStore{Service: f.State, bothMissed: make(chan struct{}), releaseLookups: make(chan struct{}), awaited: make(chan struct{}, 1)}
		left, right := fixtureServer(t), fixtureServer(t)
		workRelease := make(chan struct{})
		var workOnce, lookupOnce sync.Once
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var workers sync.WaitGroup
		done := make(chan struct{})
		t.Cleanup(func() {
			cancel()
			lookupOnce.Do(func() { close(ledger.releaseLookups) })
			workOnce.Do(func() { close(workRelease) })
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("mutation retry workers did not drain")
			}
		})
		var preflight atomic.Int32
		type result struct {
			body json.RawMessage
			err  error
		}
		results := make(chan result, 2)
		started := make(chan struct{}, 2)
		for _, host := range []*Server{left, right} {
			host.options.Config = scope.Config
			host.deps.Store = ledger
			host.deps.Authenticator = &authFixture{scope: scope, store: f.State}
			if err := host.Register(request.Method, func(call context.Context, actual api.Scope, _ json.RawMessage) (json.RawMessage, error) {
				receipt, err := f.State.LookupReceipt(call, actual, key)
				if err != nil {
					return nil, err
				}
				owned, err := host.OwnsMutation(call, actual, key, receipt.Operation.ID)
				if err != nil || !owned {
					return nil, serviceError(api.CodeIntegrity, "reservation winner lacks invocation ownership")
				}
				if reused, err := host.OwnsMutation(ctx, actual, key, receipt.Operation.ID); err != nil || reused {
					return nil, serviceError(api.CodeIntegrity, "identical frame granted a fresh context ownership")
				}
				preflight.Add(1)
				started <- struct{}{}
				select {
				case <-call.Done():
					return nil, call.Err()
				case <-workRelease:
				}
				// A real typed error receipt completes the reserved operation.
				// This fixture executes no lifecycle helper or external process.
				return nil, serviceError(api.CodeUnavailable, "component mutation completed with retained refusal")
			}); err != nil {
				t.Fatal(err)
			}
		}
		for _, host := range []*Server{left, right} {
			workers.Add(1)
			go func(host *Server) {
				defer workers.Done()
				body, _, err := host.dispatchMutation(ctx, scope, request)
				results <- result{body, err}
			}(host)
		}
		go func() { workers.Wait(); close(done) }()
		select {
		case <-ledger.bothMissed:
			lookupOnce.Do(func() { close(ledger.releaseLookups) })
		case <-ctx.Done():
			t.Fatal("dispatchers did not observe the same absent receipt")
		}
		select {
		case <-started:
		case first := <-results:
			t.Fatal("winner returned before its pending work", first.err)
		case <-ctx.Done():
			t.Fatal("reservation winner never reached preflight")
		}
		select {
		case <-ledger.awaited:
		case <-started:
			t.Fatal("same request ran mutation preflight twice")
		case first := <-results:
			t.Fatal("retry returned without awaiting the winner", first.err)
		case <-ctx.Done():
			t.Fatal("same request did not await the reservation winner")
		}
		if preflight.Load() != 1 {
			t.Fatal("same request ran mutation preflight twice")
		}
		workOnce.Do(func() { close(workRelease) })
		for i := 0; i < 2; i++ {
			select {
			case result := <-results:
				var typed *api.Error
				if !errors.As(result.err, &typed) || typed.Message != "component mutation completed with retained refusal" || len(result.body) != 0 {
					t.Fatal("retry did not replay the actual winner result", result.err)
				}
			case <-ctx.Done():
				t.Fatal("retry did not wake after winner completion")
			}
		}
		if preflight.Load() != 1 {
			t.Fatal("same request ran mutation preflight twice")
		}
		stored, err := f.State.LookupReceipt(ctx, scope, key)
		if err != nil || stored.Reply == nil || stored.Reply.Error == nil || !bytes.Equal(stored.RawRequest, scope.Frame.Bytes()) {
			t.Fatal("retry changed the original exact reservation bytes", err)
		}
	})
}

func TestMutationOwnerFences(t *testing.T) {
	for _, problem := range []string{"fresh_context", "foreign_operation", "foreign_actor", "foreign_key", "retired"} {
		t.Run(problem, func(t *testing.T) {
			directory := privateHostDirectory(t)
			state, err := store.New(store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := state.Close(); err != nil {
					t.Error(err)
				}
			}()
			host := fixtureServer(t)
			host.deps.Store = state
			request := requestFor(t, "blob.begin", api.BlobBeginRequest{Class: "report", SHA256: fx.Digest(nil)})
			scope := api.Scope{Config: request.Config, Actor: api.Actor{Kind: "service", ID: fixtureID(t)}, Source: "worker", Request: request}
			raw := fx.JSON(t, request)
			receipt, won, err := state.ReserveMutation(context.Background(), api.RequestReservation{Scope: scope, RawRequest: raw, Deadline: fx.Expiry()})
			if err != nil || !won {
				t.Fatal("owner fence reservation control failed", err)
			}
			var saved context.Context
			_, err = host.invokeOwnedMutation(context.Background(), scope, receipt, func(call context.Context, actual api.Scope, _ json.RawMessage) (json.RawMessage, error) {
				saved = call
				if owned, err := host.OwnsMutation(call, actual, receipt.Key, receipt.Operation.ID); err != nil || !owned {
					return nil, serviceError(api.CodeIntegrity, "live owner control failed")
				}
				if problem == "retired" {
					return nil, nil
				}
				key, operation := receipt.Key, receipt.Operation.ID
				if problem == "fresh_context" {
					call = context.Background()
				}
				if problem == "foreign_operation" {
					operation = fixtureID(t)
				}
				if problem == "foreign_actor" {
					actual.Actor.ID = fixtureID(t)
				}
				if problem == "foreign_key" {
					key.IdempotencyKey = fixtureID(t)
				}
				if owned, err := host.OwnsMutation(call, actual, key, operation); err != nil {
					return nil, err
				} else if owned {
					t.Fatal("mutation ownership accepted " + problem)
				}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if problem == "retired" {
				if owned, err := host.OwnsMutation(saved, scope, receipt.Key, receipt.Operation.ID); err != nil {
					t.Fatal(err)
				} else if owned {
					t.Fatal("mutation ownership accepted retired")
				}
			}
		})
	}
}
