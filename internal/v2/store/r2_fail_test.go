//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type ownedFailPort interface {
	FailOwnedEffect(context.Context, api.Scope, api.EffectLease, *api.Error, *api.ProcessObservation) (api.Commit, error)
}

func callOwnedFailure(s *Service, ctx context.Context, scope api.Scope, lease api.EffectLease, failure *api.Error, observation *api.ProcessObservation) (api.Commit, error) {
	port, ok := any(s).(ownedFailPort)
	if !ok {
		return api.Commit{}, api.NotImplemented("lb-v2-service", "owned failure completion")
	}
	return port.FailOwnedEffect(ctx, scope, lease, failure, observation)
}

func TestOwnedFailedObservation(t *testing.T) {
	for _, mode := range []string{"exit", "signal"} {
		t.Run(mode, func(t *testing.T) {
			f := newArch(t)
			zero := uint64(0)
			exit, signal := 7, 15
			observation := api.ProcessObservation{Handle: f.record.Process, State: "exited", Survivors: &zero, PromptStatus: "cut", ObservedAt: archStamp()}
			if mode == "exit" {
				observation.ExitCode = &exit
			} else {
				observation.Signal = &signal
			}
			failure := &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-service", Message: "measured worker failure", Instead: "Preserve work and inspect the original worker observation."}
			commit, err := callOwnedFailure(f.s, context.Background(), f.executor, f.record.Claim, failure, &observation)
			if err != nil || commit.Operation.Status != "failed" || commit.Operation.Error == nil {
				t.Fatal("measured owned failure did not reach a terminal operation", err)
			}
			record, err := f.s.Effect(context.Background(), f.executor, f.record.Claim.Record.Effect.ID)
			if err != nil || record.State != api.EffectFailed || record.Outcome == nil || record.Outcome.Observation == nil || !sameValue(*record.Outcome.Observation, observation) {
				t.Fatal("terminal owned failure hid its measured observation", err)
			}
			public, err := f.s.lookupReceipt(context.Background(), f.s.db, f.record.Scope, requestKey(f.record.Request))
			if err != nil || public.Reply == nil || public.Reply.Error == nil || public.Reply.Error.Instead == "" {
				t.Fatal("failed archive did not seal its reason and next step", err)
			}
			if err := f.s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := New(f.deps)
			if err != nil {
				t.Fatal("failed owned outcome did not survive restart", err)
			}
			t.Cleanup(func() {
				if err := reopened.Close(); err != nil {
					t.Error(err)
				}
			})
		})
	}
}

func TestOwnedRefusesForeignFailure(t *testing.T) {
	f := newArch(t)
	bad := f.record.Claim
	bad.ClaimID = testID(t)
	failure := &api.Error{Code: api.CodeBudget, Message: "actual allocation refusal", Instead: "Adjust the approved budget."}
	if _, err := callOwnedFailure(f.s, context.Background(), f.executor, bad, failure, nil); err == nil {
		t.Fatal("foreign claim sealed an owned failure")
	} else {
		expectCode(t, err, api.CodeConflict)
	}
	if _, err := callOwnedFailure(f.s, context.Background(), f.executor, f.record.Claim, &api.Error{Code: api.CodeConflict, Message: "fence changed"}, nil); err == nil {
		t.Fatal("real fence refusal was relabeled as a measured failure")
	} else {
		expectCode(t, err, api.CodeInvalid)
	}
	current, err := f.s.Effect(context.Background(), f.executor, f.record.Claim.Record.Effect.ID)
	if err != nil || current.Outcome != nil {
		t.Fatal("refused failure mutated the original claim", err)
	}
}

func TestOwnedMeasuredReasons(t *testing.T) {
	for _, code := range []api.ErrorCode{api.CodeBudget, api.CodeDeadline, api.CodeNotImplemented, api.CodeInvalid} {
		t.Run(string(code), func(t *testing.T) {
			f := newCollect(t)
			reason := &api.Error{Code: code, Message: "measured cleanup refusal", Instead: "Retain the original workspace and repair the named prerequisite."}
			commit, err := callOwnedFailure(f.arch.s, context.Background(), f.arch.executor, f.job.Claim, reason, nil)
			if err != nil || commit.Operation.Status != "failed" || commit.Operation.Error == nil || commit.Operation.Error.Code != code {
				t.Fatal("owned measured refusal did not become terminal", err)
			}
			var lane api.Lane
			if err := storedProjection(context.Background(), f.arch.s.db, "lane", f.job.Intent.Cause.Target.LifeID, &lane); err != nil || lane.Cleaned {
				t.Fatal("failed cleanup was counted as clean", err)
			}
		})
	}
}
