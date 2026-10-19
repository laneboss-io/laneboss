//go:build linux

package service

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type planReconcileClock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *planReconcileClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *planReconcileClock) advance(duration time.Duration) {
	c.mu.Lock()
	c.offset += duration
	c.mu.Unlock()
}

// This is a refusal at the grants port, never a planner replacement. Every
// earlier claim, original-frame, object, policy and logical-turn check runs in
// the real lifecycle planner against real store-issued bytes and identities.
type planReconcileGrants struct {
	api.GrantResolver
	state  *store.Service
	clock  *planReconcileClock
	mode   string
	scopes []api.Scope
}

func (g *planReconcileGrants) Resolve(ctx context.Context, scope api.Scope, request api.GrantResolveRequest) (_ api.GrantSet, resultErr error) {
	input, err := lstate.Load(ctx, g.state, scope.Config, scope, request.ReservationID)
	if err != nil {
		return api.GrantSet{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
	policy, err := g.state.Policy(ctx, scope)
	if err != nil {
		return api.GrantSet{}, err
	}
	if input.Record.Reservation.ID != request.ReservationID || input.Request.Method != "lane.start" || scope.PolicyGeneration != policy.Generation || scope.Actor.Kind != "service" {
		return api.GrantSet{}, serviceError(api.CodeIntegrity, "component grants received a foreign planning scope")
	}
	g.scopes = append(g.scopes, scope)
	if g.mode == "attempt_deadline" && len(g.scopes) == 1 {
		// A cooperative blocked port must receive the durable claim deadline,
		// return, and leave that same effect available to a fresh claimant.
		<-ctx.Done()
		return api.GrantSet{}, ctx.Err()
	}
	if g.mode == "integrity_control" {
		return api.GrantSet{}, serviceError(api.CodeIntegrity, "component grants detected changed retained bytes")
	}
	if g.mode == "expired_claim" && len(g.scopes) == 1 {
		// Expire the real durable lease without a wall-clock sleep or changing
		// its bytes. The next attempt must discover and reclaim the same effect.
		g.clock.advance(31 * time.Second)
		return api.GrantSet{}, &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-grants", Message: "component grant source unavailable", Retryable: true}
	}
	return api.GrantSet{}, api.NotImplemented("lb-v2-grants", "component grant source")
}

type planReconcileStore struct {
	*store.Service
	effect     api.ID
	stop       context.CancelFunc
	clock      api.Clock
	shortFirst bool
	claims     []api.EffectLease
}

func (s *planReconcileStore) ClaimEffect(ctx context.Context, scope api.Scope, request api.EffectClaimRequest) (api.EffectLease, error) {
	if request.EffectID == s.effect && s.shortFirst && len(s.claims) == 0 {
		// Shorten only this test's actual durable lease; no fabricated claim
		// or raised deadline can make the blocked-port control pass.
		request.Deadline = api.Timestamp(s.clock.Now().Add(time.Second).UTC().Format(time.RFC3339Nano))
	}
	lease, err := s.Service.ClaimEffect(ctx, scope, request)
	if err == nil && request.EffectID == s.effect {
		s.claims = append(s.claims, lease)
	}
	return lease, err
}

func (s *planReconcileStore) CompleteEffect(ctx context.Context, scope api.Scope, outcome api.EffectOutcome) (api.Commit, error) {
	commit, err := s.Service.CompleteEffect(ctx, scope, outcome)
	if err == nil && outcome.EffectID == s.effect {
		s.stop()
	}
	return commit, err
}

func TestPlanLaunchRealReconciler(t *testing.T) {
	for _, mode := range []string{"terminal_refusal", "expired_claim", "attempt_deadline", "integrity_control"} {
		t.Run(mode, func(t *testing.T) {
			clock := &planReconcileClock{}
			deps := store.Dependencies{Config: "launch-fixture", Directory: privateHostDirectory(t), Clock: clock}
			actual, err := store.New(deps)
			if err != nil {
				t.Fatal(err)
			}
			f := fx.NewIn(t, actual, deps)
			t.Cleanup(func() {
				if err := f.State.Close(); err != nil {
					t.Error(err)
				}
			})
			// The fixture supplies an enrolled ticket and authenticated frame;
			// admission and its sole PlanLaunch effect use the real lane.start
			// ReserveRequest/ReserveLaunch paths, never inserted effect records.
			reservation, err := f.State.ReserveLaunch(context.Background(), f.Human, f.ReservationRequest(t))
			if err != nil {
				t.Fatal("lane.start reservation failed", err)
			}
			effects, err := f.State.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
			if err != nil || len(effects) != 1 || effects[0].PlanLaunch == nil || effects[0].PlanLaunch.ReservationID != reservation.ID || effects[0].Context.LogicalTurnID == "" {
				t.Fatal("lane.start did not retain its single logical-turn planning effect", err)
			}
			effect := effects[0]
			original := fx.JSON(t, effect)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			state := &planReconcileStore{Service: f.State, effect: effect.ID, stop: cancel, clock: clock, shortFirst: mode == "attempt_deadline"}
			ports := &planReconcileGrants{state: f.State, clock: clock, mode: mode}
			planner, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: &authFixture{}, Grants: ports, Clock: clock})
			if err != nil {
				t.Fatal(err)
			}
			host := fixtureServer(t)
			host.options.Config = deps.Config
			host.deps.Store, host.deps.Clock = state, clock
			host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: planner, Helper: &admin.Service{}, Worker: &dataworker.Service{}, Launcher: &healthLauncher{}}
			host.reconcileLoop(ctx)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("real launch planner stalled before its next durable outcome")
			}
			readScope := api.Scope{Config: deps.Config, Actor: api.Actor{Kind: "service", ID: fx.ID(t)}}
			record, err := f.State.Effect(context.Background(), readScope, effect.ID)
			if err != nil || !bytes.Equal(fx.JSON(t, record.Effect), original) || record.ClaimantID == effect.Context.Actor.ID {
				t.Fatal("planning rewrote the original author or lost its fresh claimant", err)
			}
			operation, err := f.State.Operation(context.Background(), readScope, reservation.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "integrity_control" {
				var fault *api.Error
				if !errors.As(host.fault, &fault) || fault.Code != api.CodeIntegrity || record.Outcome != nil || operation.Status != "pending" || len(ports.scopes) != 1 {
					t.Fatal("integrity control was hidden or falsely completed", host.fault)
				}
				return
			}
			if host.fault != nil || record.State != api.EffectFailed || record.Outcome == nil || record.Outcome.Status != "failed" || record.Outcome.LaunchPlan != nil || record.Outcome.Process != nil || record.Outcome.Error == nil || record.Outcome.Error.Code != api.CodeNotImplemented || record.Outcome.Error.Owner != "lb-v2-grants" || record.Outcome.Error.Message != "component grant source is not implemented" || operation.Status != "failed" || operation.Error == nil || !reflect.DeepEqual(operation.Error, record.Outcome.Error) || operation.LastSeq == 0 {
				t.Fatal("real planning refusal did not retain its exact failed effect and operation", host.fault)
			}
			wantCalls, wantGeneration := 1, api.Generation(3)
			if mode == "expired_claim" || mode == "attempt_deadline" {
				wantCalls, wantGeneration = 2, 4
			}
			if len(ports.scopes) != wantCalls || len(state.claims) != wantCalls || record.Generation != wantGeneration {
				t.Fatal("planning did not reclaim exactly the original expired effect")
			}
			if wantCalls == 2 && ports.scopes[0].Actor.ID == ports.scopes[1].Actor.ID {
				t.Fatal("expired attempt regained authority through a reused claimant")
			}
			if wantCalls == 2 {
				old := state.claims[0]
				_, err := f.State.CompleteEffect(context.Background(), ports.scopes[0], api.EffectOutcome{EffectID: effect.ID, ClaimID: old.ClaimID, ExpectedGeneration: old.Record.Generation, Status: "failed", Error: api.NotImplemented("lb-v2-grants", "stale component attempt")})
				codeIs(t, err, api.CodeForbidden)
			}
			if remaining, err := f.State.PendingEffects(context.Background(), api.CursorRequest{Limit: 200}); err != nil || len(remaining) != 0 {
				t.Fatal("failed planning effect remained runnable", err)
			}
			if verified, err := f.State.Verify(context.Background(), api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
				t.Fatal("real planning outcome failed store verification", err)
			}
		})
	}
}
