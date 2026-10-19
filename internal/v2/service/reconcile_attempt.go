package service

import (
	"context"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type attemptResult uint8

const (
	attemptNext attemptResult = iota
	attemptPause
	attemptStop
)

// Each attempt has a fresh claimant and a context bounded by the same durable
// lease. A pending port cannot keep the serial reconciler past claim expiry.
func (s *Server) reconcileEffect(ctx context.Context, effect api.Effect, retries effectRetries) (result attemptResult) {
	attempt := effectAttempt{server: s, kind: effectKind(effect), outcome: "fault", reason: "claim_unknown"}
	if err := attempt.write("started", "claim"); err != nil {
		s.recordFault(err)
		return attemptStop
	}
	defer func() {
		if err := attempt.write(attempt.outcome, attempt.reason); err != nil {
			s.recordFault(err)
			result = attemptStop
		}
	}()
	claimant, err := wire.NewID()
	if err != nil {
		return attempt.fault("claim", err)
	}
	scope := api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: claimant}, Source: "worker"}
	record, err := s.deps.Store.Effect(ctx, scope, effect.ID)
	if err != nil {
		return attempt.fault("lookup", err)
	}
	retained, err := retainedUsage(ctx, s.deps.Store, scope, effect)
	if err != nil {
		return attempt.fault("usage_owner", err)
	}
	if retained {
		attempt.outcome, attempt.reason = "deferred", "retained_usage_owner"
		return attemptNext
	}
	retained, err = retainedMaterialization(ctx, s.deps.Store, scope, effect)
	if err != nil {
		return attempt.fault("owner", err)
	}
	if retained {
		// The planning flow owns this exact durable child. Do not take its
		// pending/expired claim or send it through archive/Clean failure ports.
		attempt.outcome, attempt.reason = "deferred", "retained_materialization_owner_"+"store_materialization"
		retries.refused(effect.ID, s.deps.Clock.Now())
		return attemptNext
	}
	retained, err = retainedAgentPrepare(ctx, s.deps.Store, scope, effect)
	if err != nil {
		return attempt.fault("owner", err)
	}
	if retained {
		attempt.outcome, attempt.reason = "deferred", "retained_agent_prepare_owner"
		retries.refused(effect.ID, s.deps.Clock.Now())
		return attemptNext
	}
	retained, err = retainedReviewWorker(ctx, s.deps.Store, scope, effect)
	if err != nil {
		return attempt.fault("owner", err)
	}
	if retained {
		if effect.Worker != nil && effect.Worker.Kind == "test" {
			if err := s.executeChildEffect(ctx, effect); err != nil {
				return attempt.fault("native_test", err)
			}
			attempt.outcome, attempt.reason = "completed", "retained_test_owner"
			return attemptNext
		}
		attempt.outcome, attempt.reason = "deferred", "retained_review_owner"
		retries.refused(effect.ID, s.deps.Clock.Now())
		return attemptNext
	}
	deadline := api.Timestamp(s.deps.Clock.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))
	owned := effect.Clean != nil || effect.Worker != nil && effect.Worker.Kind == "archive"
	var deadlineFailure error
	if control, ok := s.deps.Store.(interface {
		OwnedEffectDeadline(context.Context, api.Scope, api.ID) (api.Timestamp, error)
	}); ok && owned {
		chosen, chooseErr := control.OwnedEffectDeadline(ctx, scope, effect.ID)
		if chooseErr != nil {
			deadlineFailure = chooseErr
		} else {
			deadline = chosen
		}
	}
	request := api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: record.Generation, ClaimantID: claimant, Deadline: deadline}
	lease, err := s.deps.Store.ClaimEffect(ctx, scope, request)
	if effectFenceRefused(err) && owned {
		if recovery, ok := s.deps.Store.(interface {
			ClaimOwnedRecovery(context.Context, api.Scope, api.EffectClaimRequest) (api.EffectLease, error)
		}); ok {
			lease, err = recovery.ClaimOwnedRecovery(ctx, scope, request)
		}
	}
	if effectFenceRefused(err) {
		return attempt.deferEffect("claim", err, effect.ID, retries)
	}
	var typed *api.Error
	if errors.As(err, &typed) && typed.Code == api.CodeUnavailable {
		if control, ok := s.deps.Store.(dispatchStore); ok {
			freeze, readErr := control.ActiveDispatchFreeze(ctx)
			if readErr == nil && freeze != nil {
				attempt.outcome, attempt.reason = "deferred", "dispatch_frozen"
				return attemptPause
			}
		}
	}
	if err != nil {
		return attempt.fault("claim", err)
	}
	var outcome api.EffectOutcome
	if deadlineFailure != nil {
		err = deadlineFailure
	} else {
		expires, parseErr := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
		if parseErr != nil {
			return attempt.fault("claim", serviceError(api.CodeIntegrity, "effect claim has no execution deadline"))
		}
		runCtx, cancel := context.WithTimeout(ctx, expires.Sub(s.deps.Clock.Now()))
		runCtx = api.WithHelperReasonObserver(runCtx, attempt.observeHelperReason)
		started := time.Now()
		outcome, err = s.runEffect(runCtx, scope, lease)
		attempt.ranFor = time.Since(started)
		cancel()
	}
	if owned {
		if err != nil {
			if ctx.Err() != nil {
				attempt.outcome, attempt.reason = "cancelled", "run_cancelled"
				return attemptStop
			}
			if effectFenceRefused(err) {
				if control, ok := s.deps.Store.(interface {
					OwnedFenceFailure(context.Context, api.Scope, api.EffectLease) (*api.Error, error)
				}); ok {
					permanent, readErr := control.OwnedFenceFailure(ctx, scope, lease)
					if readErr != nil {
						if ctx.Err() != nil {
							attempt.outcome, attempt.reason = "cancelled", "owned_fence_cancelled"
							return attemptStop
						}
						return attempt.fault("owned_fence", readErr)
					}
					if permanent != nil {
						err = permanent
					}
				}
				if effectFenceRefused(err) {
					return attempt.deferEffect("run", err, effect.ID, retries)
				}
			}
			original := err
			outcome, err = s.failOwnedEffect(ctx, scope, lease, outcome, err)
			if err != nil {
				if ctx.Err() != nil {
					attempt.outcome, attempt.reason = "cancelled", "owned_failure_cancelled"
					return attemptStop
				}
				// Name the failure being recorded too (box 107: a refused record hid why the effect failed).
				if effectFenceRefused(err) || ownedFailurePending(err) {
					result := attempt.deferEffect("owned_failure", err, effect.ID, retries)
					attempt.detail += "; recording: " + failureClass(original, attempt.ranFor)
					return result
				}
				result := attempt.fault("owned_failure", err)
				attempt.detail += "; recording: " + failureClass(original, attempt.ranFor)
				return result
			}
		}
		actual, err := s.deps.Store.Effect(ctx, scope, effect.ID)
		if err != nil {
			return attempt.fault("readback", err)
		}
		if actual.State != api.EffectCompleted && actual.State != api.EffectFailed || actual.Outcome == nil || !sameOwnedOutcome(*actual.Outcome, outcome) {
			return attempt.fault("readback", serviceError(api.CodeIntegrity, "owned effect returned before its atomic verified completion"))
		}
		retries.completed(effect.ID)
		attempt.completed(outcome)
		return attemptNext
	}
	if err != nil {
		if ctx.Err() != nil {
			attempt.outcome, attempt.reason = "cancelled", "run_cancelled"
			return attemptStop
		}
		refusal := executionRefusal(err)
		if refusal == nil {
			refusal = unsupportedWorker(effect, err)
		}
		if refusal == nil && (effect.PlanLaunch != nil || effect.HelperRelease != nil) {
			refusal = terminalPlanRefusal(err)
		}
		if refusal != nil {
			outcome = api.EffectOutcome{EffectID: effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "failed", Error: refusal}
		} else if effectFenceRefused(err) || (effect.ApplyChange != nil || effect.PlanLaunch != nil || effect.HelperRelease != nil || effect.HelperAbort != nil || effect.Stop != nil || effect.Deliver != nil) && transientPlanAttempt(err) {
			return attempt.deferEffect("run", err, effect.ID, retries)
		} else {
			// An unknown external outcome or a storage/integrity failure never
			// becomes a fabricated terminal result. Retain it and stop.
			return attempt.fault("run", err)
		}
	}
	if _, err := s.deps.Store.CompleteEffect(ctx, scope, outcome); err != nil {
		if effectFenceRefused(err) || (effect.ApplyChange != nil || effect.Stop != nil || effect.HelperRelease != nil) && transientPlanAttempt(err) {
			return attempt.deferEffect("complete", err, effect.ID, retries)
		}
		return attempt.fault("complete", err)
	}
	retries.completed(effect.ID)
	attempt.completed(outcome)
	return attemptNext
}

// Only a single declared refusal from the real planner is terminal here.
// Joined cleanup/storage failures must keep their complete failure semantics.
func terminalPlanRefusal(err error) *api.Error {
	typed, ok := err.(*api.Error)
	if !ok || typed == nil || typed.Retryable {
		return nil
	}
	switch typed.Code {
	case api.CodeNotImplemented, api.CodePrerequisite, api.CodeUnsupported, api.CodeInvalid, api.CodeNotFound, api.CodeVersion, api.CodeBudget:
		return typed
	}
	return nil
}

func transientPlanAttempt(err error) bool {
	if err == context.Canceled || err == context.DeadlineExceeded {
		return true
	}
	switch failure := err.(type) {
	case *api.Error:
		if failure == nil {
			return false
		}
		switch failure.Code {
		case api.CodeUnavailable, api.CodeContainmentUnknown, api.CodeDeadline, api.CodeCancelled, api.CodeConflict:
			return true
		}
	case interface{ Unwrap() []error }:
		causes := failure.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !transientPlanAttempt(cause) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return transientPlanAttempt(failure.Unwrap())
	}
	return false
}
