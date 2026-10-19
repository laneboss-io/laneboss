//go:build linux

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type recoveryClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *recoveryClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *recoveryClock) advance(d time.Duration) { c.mu.Lock(); c.at = c.at.Add(d); c.mu.Unlock() }

func TestReservationRecovery(t *testing.T) {
	for _, mode := range []string{"reopen", "live_owner", "retired_owner", "before_deadline", "untracked_owner"} {
		t.Run(mode, func(t *testing.T) {
			s, deps := testStore(t)
			clock := &recoveryClock{at: time.Now().UTC()}
			s.deps.Clock, deps.Clock = clock, clock
			input := testTransaction(t)
			raw, err := json.MarshalIndent(input.Scope.Request, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call, retire := s.TrackMutation(ctx)
			t.Cleanup(retire)
			if mode == "untracked_owner" {
				call = ctx
			}
			reservation := api.RequestReservation{Scope: input.Scope, RawRequest: raw,
				Deadline: api.Timestamp(clock.Now().Add(30 * time.Second).Format(time.RFC3339Nano))}
			first, won, err := s.ReserveMutation(call, reservation)
			if err != nil || !won {
				t.Fatal("reservation recovery control failed", err)
			}
			if mode == "retired_owner" || mode == "before_deadline" {
				retire()
			}
			if mode == "live_owner" {
				loser, releaseLoser := s.TrackMutation(context.Background())
				if _, won, err := s.ReserveMutation(loser, reservation); err != nil || won {
					t.Fatal("reservation loser control failed", err)
				}
				releaseLoser()
				// Cancellation is not evidence that the handler returned.
				cancel()
			}
			if mode == "before_deadline" {
				clock.advance(29 * time.Second)
			} else {
				clock.advance(31 * time.Second)
			}
			if mode == "reopen" {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				s, err = New(deps)
				if err != nil {
					t.Fatal("orphan reopen failed", err)
				}
				t.Cleanup(func() {
					if err := s.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			if err := s.RecoverReservations(context.Background()); err != nil {
				t.Fatal("reservation recovery failed", err)
			}
			key := requestKey(input.Scope.Request)
			receipt, err := s.LookupReceipt(context.Background(), input.Scope, key)
			if err != nil {
				t.Fatal("recovered receipt lookup failed", err)
			}
			if mode == "live_owner" || mode == "before_deadline" || mode == "untracked_owner" {
				if receipt.Reply != nil || receipt.Operation.Status != "pending" || receipt.Operation.ID != first.Operation.ID {
					t.Fatal("recovery finalized a live or unexpired reservation")
				}
				return
			}
			if receipt.Reply == nil || receipt.Reply.Error == nil || receipt.Reply.Error.Code != api.CodeUnavailable || receipt.Operation.Status != "failed" {
				t.Fatal("orphan reservation remained pending")
			}
			if receipt.Operation.ID != first.Operation.ID || receipt.Key != key || receipt.Actor != input.Scope.Actor || !bytes.Equal(receipt.RawRequest, raw) || receipt.Operation.Error == nil || receipt.Operation.Error.OperationID != first.Operation.ID {
				t.Fatal("recovery changed the original request receipt")
			}
			requests, err := s.DispatchRequests(context.Background())
			if err != nil || len(requests) != 0 {
				t.Fatal("recovered reservation still blocks request drain", err)
			}
			replay, err := s.Transact(context.Background(), input)
			if err != nil || !replay.Replayed || replay.Operation.Status != "failed" || replay.Reply == nil || replay.Reply.Error == nil {
				t.Fatal("orphan retry reexecuted instead of replaying failure", err)
			}
			verification, err := s.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
			if err != nil || !verification.OK || verification.Events != 1 {
				t.Fatal("recovery did not retain one valid failure event", err)
			}
			if err := s.RecoverReservations(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyReservationRecovery(t *testing.T) {
	s, deps := testStore(t)
	input := testTransaction(t)
	raw, err := json.MarshalIndent(input.Scope.Request, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	operation := api.Operation{ID: testID(t), Status: "pending"}
	data, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	// Install the old reservation representation once, before reopen. No
	// immutable history/trigger is removed to manufacture this compatibility input.
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO operations VALUES(?,?,?)", operation.ID, principal(input.Scope), data); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec("INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)", principal(input.Scope), input.Scope.Request.Method,
		input.Scope.Request.IdempotencyKey, input.Scope.Request.RequestSHA256, raw, operation.ID,
		time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(deps)
	if err != nil {
		t.Fatal("legacy reservation reopen failed", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := s.RecoverReservations(context.Background()); err != nil {
		t.Fatal(err)
	}
	receipt, err := s.LookupReceipt(context.Background(), input.Scope, requestKey(input.Scope.Request))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Reply == nil || receipt.Operation.Status != "failed" || receipt.Operation.ID != operation.ID || !bytes.Equal(raw, receipt.RawRequest) {
		t.Fatal("legacy orphan reservation remained pending")
	}
}

func TestRecoveryKeepsEffectHandoff(t *testing.T) {
	s, _ := testStore(t)
	clock := &recoveryClock{at: time.Now().UTC()}
	s.deps.Clock = clock
	input := testTransaction(t)
	raw, err := json.Marshal(input.Scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, retire := s.TrackMutation(context.Background())
	defer retire()
	receipt, won, err := s.ReserveMutation(ctx, api.RequestReservation{Scope: input.Scope, RawRequest: raw,
		Deadline: api.Timestamp(clock.Now().Add(30 * time.Second).Format(time.RFC3339Nano))})
	if err != nil || !won {
		t.Fatal("effect handoff reservation failed", err)
	}
	intent := api.InternalIntent{ID: testID(t), Kind: api.InternalLifecycleEffect, Config: s.deps.Config,
		Actor: input.Scope.Actor, RequestedBy: input.Scope.Actor, CauseOperationID: receipt.Operation.ID, CauseRequestID: input.Scope.Request.RequestID,
		EffectID: testID(t), Target: api.LifeRef{LifeID: testID(t), Run: 1}}
	effect := api.Effect{ID: intent.EffectID, OperationID: receipt.Operation.ID, Context: &intent,
		Stop: &api.ProcessHandle{ID: testID(t), Target: intent.Target, ContainmentID: testID(t), Generation: "component-handoff"}}
	internal := input.Scope
	internal.Request = api.Request{}
	staged := api.Transaction{Scope: internal, Internal: &intent, Effects: []api.Effect{effect}}
	if err := api.ValidateTransactionShape(staged); err != nil {
		t.Fatal("effect handoff fixture has invalid shape", err)
	}
	if _, err := s.Transact(context.Background(), staged); err != nil {
		t.Fatal("durable effect handoff failed", err)
	}
	retire()
	clock.advance(31 * time.Second)
	if err := s.RecoverReservations(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := s.LookupReceipt(context.Background(), input.Scope, requestKey(input.Scope.Request))
	if err != nil {
		t.Fatal(err)
	}
	if after.Reply != nil || after.Operation.Status != "pending" {
		t.Fatal("reservation recovery discarded a durable effect handoff")
	}
}
