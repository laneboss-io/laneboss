//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The barrier schedules real inventory reads; it never replaces their results.
type inventoryBarrier struct {
	*store.Service
	entered chan struct{}
	proceed chan struct{}
}

func (b *inventoryBarrier) LaunchInventory(ctx context.Context) ([]api.LaunchPlanRecord, error) {
	select {
	case b.entered <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-b.proceed:
		return b.Service.LaunchInventory(ctx)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type recoveryGroup struct {
	api.HelperControl
	ledgers []*recoveryLedger
}

func (g *recoveryGroup) ReconcileCapture(ctx context.Context, binding api.CaptureBinding) (api.CaptureBinding, error) {
	for _, ledger := range g.ledgers {
		if ledger.fixture.Plan.Capture.ID == binding.ID {
			return ledger.ReconcileCapture(ctx, binding)
		}
	}
	return api.CaptureBinding{}, serviceError(api.CodeIntegrity, "capture selected an unknown launch")
}

func (g *recoveryGroup) ReconcileGate(ctx context.Context, request api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	for _, ledger := range g.ledgers {
		if ledger.fixture.Plan.Lease.ID == request.LeaseID {
			return ledger.ReconcileGate(ctx, request)
		}
	}
	return api.LaunchReconciliation{}, serviceError(api.CodeIntegrity, "gate selected an unknown launch")
}

func TestCollectedRecoveryAdmits(t *testing.T) {
	f := fx.ReadyForIdentity(t, true, uint32(os.Geteuid())+1000, uint32(os.Getegid())+1000)
	f.Observation(t, "running")
	parent := *f
	f.Child(t)
	collect := f.Cleanup(t, func(ctx context.Context, scope api.Scope, principal api.WorkerPrincipal) (api.WorkerResultReceipt, error) {
		return dataworker.RunArchive(ctx, dataworker.ArchiveJob{Principal: principal, Scope: scope, Bootstrap: f.State,
			Read: func(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
				return f.State.WorkerObject(ctx, scope, q)
			}, Sink: f.State, Clock: f.Deps.Clock})
	})
	next := fx.NewIn(t, f.State, f.Deps)
	f.State = next.State
	s := launchServer(t, f)
	barrier := &inventoryBarrier{Service: f.State, entered: make(chan struct{}), proceed: make(chan struct{})}
	s.deps.Store = barrier
	helper := &recoveryLedger{fixture: f, gate: f.Observation(t, "exited")}
	live := &recoveryLedger{fixture: &parent, gate: parent.Observation(t, "running")}
	s.runtime = api.RuntimeServices{Store: barrier, Helper: &recoveryGroup{ledgers: []*recoveryLedger{helper, live}}, LaunchPlanner: &lifecycle.Service{}}
	s.launchConfigured = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan struct{})
	go func() { defer close(done); s.launchRecoveryLoop(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	awaitTick := func() {
		t.Helper()
		select {
		case <-barrier.entered:
		case <-done:
			t.Fatal("recovery stopped before its next tick", s.fault)
		case <-ctx.Done():
			t.Fatal("recovery did not reach its next tick")
		}
	}
	awaitTick()
	barrier.proceed <- struct{}{}
	awaitTick() // First tick completed; the next real read is held for cleanup.
	if helper.captureCalls != 1 || helper.gateCalls != 1 || live.captureCalls != 1 || live.gateCalls != 1 {
		t.Fatal("uncleaned ended lane lost capture or gate reconciliation")
	}
	collect()
	// Native ownership has been collected. The same helper refusal must still
	// close admission for an uncleaned run (TestRecoveryStopJournal below).
	helper.err = serviceError(api.CodeContainmentUnknown, "capture snapshot checkpoint is unavailable")
	barrier.proceed <- struct{}{}
	awaitTick()
	s.mu.RLock()
	healthy, fault := s.launchJobsActive && s.launchJobsHealthy, s.fault
	s.mu.RUnlock()
	if !healthy || fault != nil || helper.captureCalls != 1 || helper.gateCalls != 1 || live.captureCalls != 2 || live.gateCalls != 2 {
		t.Fatal("collected launch stopped recovery or revisited its native ownership", fault)
	}
	request := next.Human.Request
	request.RequestID, request.IdempotencyKey = fx.ID(t), fx.ID(t)
	var err error
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	scope := next.Human
	scope.Request, scope.Frame = request, &fx.Frame{Raw: fx.JSON(t, request)}
	s.deps.Authenticator = &authFixture{scope: scope, store: next.State}
	// Only lifecycle preflight is a component adapter here. Admission, atomic
	// request ownership, ticket consumption and the next launch are real.
	if err := s.Register("lane.start", func(ctx context.Context, scope api.Scope, body json.RawMessage) (json.RawMessage, error) {
		var start api.StartRequest
		if err := api.DecodeObject(body, &start); err != nil {
			return nil, err
		}
		if start.Lane != next.Start.Lane || start.Driver != api.DriverCodex {
			return nil, serviceError(api.CodeConflict, "second start changed its reserved inputs")
		}
		key := api.RequestKey{Method: request.Method, IdempotencyKey: request.IdempotencyKey, RequestSHA256: request.RequestSHA256}
		next.Receipt, err = next.State.LookupReceipt(ctx, scope, key)
		if err != nil {
			return nil, err
		}
		next.Human = scope
		next.Reservation, err = next.State.ReserveLaunch(ctx, scope, next.ReservationRequest(t))
		if err != nil {
			return nil, err
		}
		receipt, err := next.State.LookupReceipt(ctx, scope, key)
		if err != nil {
			return nil, err
		}
		if receipt.Reply == nil {
			return nil, serviceError(api.CodeIntegrity, "second launch has no committed reply")
		}
		return receipt.Reply.Result, nil
	}); err != nil {
		t.Fatal(err)
	}
	encoded, _, err := s.dispatchMutation(ctx, scope, request)
	var operation api.Operation
	if err != nil || json.Unmarshal(encoded, &operation) != nil || operation.ID != next.Reservation.OperationID ||
		operation.LifeID == f.Lane.LifeID || operation.LifeID != next.Reservation.Target.LifeID || operation.Status != "pending" {
		t.Fatal("second lane.start was not admitted after collection", err)
	}
	t.Log("collection kept recovery healthy and admitted the next Codex launch")
}

func TestRecoveryStopJournal(t *testing.T) {
	for _, kind := range []string{"typed", "untyped"} {
		t.Run(kind, func(t *testing.T) {
			f := fx.Ready(t, true)
			s := launchServer(t, f)
			private := string(fx.ID(t))
			failure := &api.Error{Code: api.CodeContainmentUnknown, Owner: private, OperationID: fx.ID(t),
				Message: "capture snapshot checkpoint is unavailable", Instead: "/private/" + private}
			var cause error = fmt.Errorf("/private/%s: %w", private, failure)
			code, message := failure.Code, failure.Message
			if kind == "untyped" {
				cause = errors.New("/private/" + private)
				code, message = api.CodeIntegrity, "internal service operation failed"
			}
			helper := &recoveryLedger{fixture: f, err: cause}
			s.runtime = api.RuntimeServices{Store: f.State, Helper: helper, LaunchPlanner: &lifecycle.Service{}}
			s.launchConfigured = true
			journal, err := os.CreateTemp(t.TempDir(), "journal")
			if err != nil {
				t.Fatal(err)
			}
			stderr := os.Stderr
			os.Stderr = journal
			t.Cleanup(func() {
				os.Stderr = stderr
				if err := journal.Close(); err != nil {
					t.Error(err)
				}
			})
			s.launchRecoveryLoop(context.Background())
			os.Stderr = stderr
			if !errors.Is(s.fault, cause) || s.launchJobsActive || s.launchJobsHealthy || helper.captureCalls != 1 || helper.gateCalls != 0 {
				t.Fatal("live capture failure did not retain its cause and close admission", s.fault)
			}
			request := f.Human.Request
			request.RequestID, request.IdempotencyKey = fx.ID(t), fx.ID(t)
			request.RequestSHA256, err = api.RequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			scope := f.Human
			scope.Request, scope.Frame = request, &fx.Frame{Raw: fx.JSON(t, request)}
			_, _, err = s.dispatchMutation(context.Background(), scope, request)
			var refusal *api.Error
			if !errors.As(err, &refusal) || refusal.Code != api.CodePrerequisite || refusal.Message != "launch admission requires LaunchPlanner and active healthy recovery/capture jobs" {
				t.Fatal("real capture failure opened new launch admission", err)
			}
			data, err := os.ReadFile(journal.Name())
			if err != nil {
				t.Fatal(err)
			}
			var entry map[string]string
			if bytes.Count(data, []byte{'\n'}) != 1 || json.Unmarshal(data, &entry) != nil || len(entry) != 3 ||
				entry["event"] != "launch_recovery_stopped" || entry["code"] != string(code) || entry["message"] != message ||
				bytes.Contains(data, []byte(private)) || bytes.Contains(data, []byte("/private/")) {
				t.Fatalf("stopping recovery lost its fixed private-safe journal line: %q", data)
			}
			t.Logf("captured stop journal: %s", data)
		})
	}
}
