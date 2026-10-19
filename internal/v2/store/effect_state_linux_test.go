//go:build linux

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestStoredEffectStates(t *testing.T) {
	for _, status := range []string{"succeeded", "failed"} {
		t.Run(status, func(t *testing.T) {
			s, deps := testStore(t)
			ctx := context.Background()
			input := testPendingTransaction(t)
			if _, err := s.Transact(ctx, input); err != nil {
				t.Fatal("effect state setup failed", err)
			}
			effect := input.Effects[0]
			pending, err := s.Effect(ctx, input.Scope, effect.ID)
			if err != nil || pending.State != api.EffectPending || pending.Outcome != nil {
				t.Fatal("new effect lost pending state", err)
			}
			claim, err := s.ClaimEffect(ctx, input.Scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: pending.Generation,
				ClaimantID: input.Scope.Actor.ID, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
			if err != nil || claim.Record.State != api.EffectClaimed || claim.Record.Generation != 2 {
				t.Fatal("claim state left shared vocabulary", err)
			}
			outcome := api.EffectOutcome{EffectID: effect.ID, ClaimID: claim.ClaimID, ExpectedGeneration: claim.Record.Generation, Status: status}
			want := api.EffectCompleted
			if status == "failed" {
				want = api.EffectFailed
				outcome.Error = &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-service", Message: "component stop refused"}
			} else {
				zero, exit := uint64(0), 0
				outcome.Observation = &api.ProcessObservation{Handle: *effect.Stop, State: "exited", Survivors: &zero, ExitCode: &exit,
					PromptStatus: "completed", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
			}
			commit, err := s.CompleteEffect(ctx, input.Scope, outcome)
			if err != nil {
				t.Fatal("measured state completion failed", err)
			}
			actual, err := s.Effect(ctx, input.Scope, effect.ID)
			if err != nil || actual.State != want || actual.Outcome == nil || actual.Outcome.Status != status || commit.Operation.Status != status {
				t.Fatal("terminal effect confused state and outcome", err)
			}
			if replay, err := s.CompleteEffect(ctx, input.Scope, outcome); err != nil || !replay.Replayed || replay.LastSeq != commit.LastSeq {
				t.Fatal("typed terminal completion did not replay", err)
			}
			if verified, err := s.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
				t.Fatal("typed effect state failed store verification", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = New(deps)
			if err != nil {
				t.Fatal("typed terminal state did not reopen", err)
			}
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			actual, err = s.Effect(ctx, input.Scope, effect.ID)
			if err != nil || actual.State != want || actual.Outcome == nil || actual.Outcome.Status != status {
				t.Fatal("reopen lost typed terminal state", err)
			}
		})
	}
}

func TestEffectReclaimState(t *testing.T) {
	s, _ := testStore(t)
	clock := &recoveryClock{at: time.Now().UTC()}
	s.deps.Clock = clock
	ctx, input := context.Background(), testPendingTransaction(t)
	if _, err := s.Transact(ctx, input); err != nil {
		t.Fatal(err)
	}
	request := api.EffectClaimRequest{EffectID: input.Effects[0].ID, ExpectedGeneration: 1, ClaimantID: input.Scope.Actor.ID,
		Deadline: api.Timestamp(clock.Now().Add(time.Second).Format(time.RFC3339Nano))}
	first, err := s.ClaimEffect(ctx, input.Scope, request)
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(2 * time.Second)
	request.ExpectedGeneration, request.Deadline = first.Record.Generation, api.Timestamp(clock.Now().Add(time.Minute).Format(time.RFC3339Nano))
	second, err := s.ClaimEffect(ctx, input.Scope, request)
	if err != nil || second.Record.State != api.EffectClaimed || second.Record.Generation != 3 || second.ClaimID == first.ClaimID {
		t.Fatal("reclaim left shared claimed state", err)
	}
	old := api.EffectOutcome{EffectID: request.EffectID, ClaimID: first.ClaimID, ExpectedGeneration: first.Record.Generation, Status: "failed",
		Error: &api.Error{Code: api.CodeForbidden, Message: "component old claim refused"}}
	if _, err := s.CompleteEffect(ctx, input.Scope, old); err == nil {
		t.Fatal("reclaim accepted the expired claim")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
	if verified, err := s.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
		t.Fatal("shared reclaim state failed verification", err)
	}
}

func TestEffectStateRefusal(t *testing.T) {
	for _, state := range []api.EffectState{"running", "reconciling", "succeeded", "unknown"} {
		t.Run(string(state), func(t *testing.T) {
			s, _ := testStore(t)
			ctx, input := context.Background(), testPendingTransaction(t)
			if _, err := s.Transact(ctx, input); err != nil {
				t.Fatal(err)
			}
			record, err := s.Effect(ctx, input.Scope, input.Effects[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			// A corruption fixture changes only the mutable outbox state.
			// Immutable effect intent and history guards remain installed.
			record.State = state
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.ExecContext(ctx, "UPDATE effect_states SET data=? WHERE id=?", data, string(record.Effect.ID)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Effect(ctx, input.Scope, record.Effect.ID); err == nil {
				t.Fatal("store accepted a foreign effect state")
			} else {
				expectCode(t, err, api.CodeIntegrity)
			}
			if _, err := s.DispatchEffects(ctx); err == nil {
				t.Fatal("dispatch accepted a foreign effect state")
			}
			if _, err := s.PendingEffects(ctx, api.CursorRequest{Limit: 200}); err == nil {
				t.Fatal("pending inventory accepted a foreign effect state")
			}
			if _, err := s.Verify(ctx, api.VerifyRequest{Scope: "all"}); err == nil {
				t.Fatal("verification accepted a foreign effect state")
			}
		})
	}
}
