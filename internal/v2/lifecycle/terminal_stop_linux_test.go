//go:build linux

package lifecycle

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The real SQLite writer owns the terminal receipt, rather than trusting the
// module's proposed Operation fields. Identity/helper are declared fixtures.
func TestStopEndedJournal(t *testing.T) {
	stopEndedJournal(t, 0)
}

func stopEndedJournal(t *testing.T, exitCode int, afterStop ...func(*fx.Fixture, api.Operation)) {
	t.Helper()
	var f *fx.Fixture
	if len(afterStop) == 0 {
		f = fx.Ready(t, true)
	} else {
		f = fx.ControlledChild(t)
	}
	f.Opened(t)
	f.Ended(t, exitCode)
	s, err := New(Dependencies{Store: f.State, Identity: &fixtureIdentity{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.State.Lane(context.Background(), f.Execution, f.Reservation.Target)
	if err != nil {
		t.Fatal(err)
	}
	scope := f.LaneScope(t)
	reasonBytes := []byte("retain the measured ended run")
	reason, err := f.State.RetainObject(context.Background(), f.Execution, api.RetainObjectRequest{Intent: f.Intent(t, api.InternalObjectRetain),
		Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: "task", Bytes: reasonBytes, SHA256: fx.Digest(reasonBytes), Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: scope.Actor, LifeID: before.LifeID, Audience: "owner", Generation: 1}}})
	if err != nil {
		t.Fatal("cannot retain actual caller-visible stop reason", err)
	}
	request := api.StopRequest{Target: f.Reservation.Target, ExpectedGeneration: before.Generation, Reason: reason}
	scope.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: scope.Config, Method: "lane.stop",
		RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, request)}
	scope.Request.RequestSHA256, err = api.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame = &fx.Frame{Raw: fx.JSON(t, scope.Request)}
	ctx, retire := f.State.TrackMutation(context.Background())
	defer retire()
	_, won, err := f.State.ReserveMutation(ctx, api.RequestReservation{Scope: scope, RawRequest: scope.Frame.Bytes(), Deadline: fx.Expiry()})
	if err != nil || !won {
		t.Fatal("cannot reserve actual terminal stop", err)
	}
	operation, err := s.LaneStop(ctx, scope, request)
	if err != nil || operation.Stop == nil || operation.Stop.State != before.State || operation.Stop.End.Observation.State != "exited" ||
		operation.Stop.End.Observation.ExitCode == nil || *operation.Stop.End.Observation.ExitCode != exitCode {
		t.Fatal("real writer did not retain a typed terminal stop", err)
	}
	retained, err := f.State.Operation(ctx, scope, operation.ID)
	if err != nil || !reflect.DeepEqual(retained, operation) {
		t.Fatal("operation status lost the committed terminal stop", err)
	}
	replay, err := s.LaneStop(ctx, scope, request)
	if err != nil || !reflect.DeepEqual(replay, operation) {
		t.Fatal("actual terminal stop did not replay exactly", err)
	}
	after, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("real terminal stop changed its life projection", err)
	}
	for _, mode := range []string{"forged-result", "no-generation", "no-epoch"} {
		// Submit a false module result. The writer must derive its own end,
		// while refusing missing transaction fences before any success.
		attempt := scope
		attempt.Request.RequestID, attempt.Request.IdempotencyKey = fx.ID(t), fx.ID(t)
		attempt.Request.RequestSHA256, err = api.RequestDigest(attempt.Request)
		if err != nil {
			t.Fatal(err)
		}
		attempt.Frame = &fx.Frame{Raw: fx.JSON(t, attempt.Request)}
		attemptCtx, retireAttempt := f.State.TrackMutation(context.Background())
		defer retireAttempt()
		reserved, won, err := f.State.ReserveMutation(attemptCtx, api.RequestReservation{Scope: attempt, RawRequest: attempt.Frame.Bytes(), Deadline: fx.Expiry()})
		if err != nil || !won {
			t.Fatal("cannot reserve independent writer stop control", err)
		}
		forged := *operation.Stop
		forged.State = "accepted"
		input := api.Transaction{Scope: attempt, RawRequest: attempt.Frame.Bytes(),
			Compare: []api.Compare{{Kind: api.CompareLane, ID: before.LifeID, Generation: before.Generation}},
			Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: before.LifeID, Epoch: before.CancellationEpoch}}},
			Reply:   &api.RPCReply{Result: fx.JSON(t, api.Operation{ID: reserved.Operation.ID, Status: "succeeded", LifeID: before.LifeID, Run: before.Run, Stop: &forged})}}
		if mode == "no-generation" {
			input.Compare = nil
		} else if mode == "no-epoch" {
			input.Guards = nil
		}
		commit, err := f.State.Transact(attemptCtx, input)
		if mode == "forged-result" {
			if err != nil || !reflect.DeepEqual(commit.Operation.Stop, operation.Stop) {
				t.Fatal("writer trusted a module-supplied terminal result", err)
			}
		} else {
			typed, ok := err.(*api.Error)
			if !ok || typed.Code != api.CodeForbidden || commit.Operation.ID != "" {
				t.Error("writer accepted terminal stop without its fence", mode, err)
			}
		}
	}
	verification, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("terminal stop's actual journal did not verify", err)
	}
	if !t.Failed() {
		t.Logf("real SQLite before stop: state=%s exit=%d; typed stop, exact replay and journal verification passed", before.State, exitCode)
	}
	for _, verify := range afterStop {
		verify(f, operation)
	}
}
