package service

import (
	"context"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Failed plans have their own durable outbox. They never borrow the completed
// planner's claim and never become generic PlanLaunch/Worker effects.
func (s *Server) reconcilePlanCleanup(ctx context.Context, retries effectRetries) error {
	store, ok := s.deps.Store.(api.PlanCleanupStore)
	if !ok {
		return nil // Stores without the private outbox cannot contain its rows.
	}
	scope := api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: s.controller}, Source: "worker"}
	// Component servers have no installed controller. The per-attempt identity
	// is still fresh and authenticated by the single writer, as for effects.
	if scope.Actor.ID == "" {
		id, err := wire.NewID()
		if err != nil {
			return err
		}
		scope.Actor.ID = id
	}
	jobs, err := store.PendingPlanCleanup(ctx, scope)
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !retries.ready(job.ID, s.deps.Clock.Now()) {
			continue
		}
		status, err := store.PlanCleanupStatus(ctx, scope, job.ID)
		if err != nil {
			return err
		}
		if status.State == "completed" || status.Claim != nil && cleanupClaimLive(status.Claim.ExpiresAt, s.deps.Clock.Now()) {
			continue
		}
		claimant, err := wire.NewID()
		if err != nil {
			return err
		}
		attemptScope := scope
		attemptScope.Actor.ID = claimant
		deadline := s.deps.Clock.Now().Add(30 * time.Second)
		claim, err := store.ClaimPlanCleanup(ctx, attemptScope, job, api.EffectClaimRequest{EffectID: job.ID,
			ExpectedGeneration: status.Generation, ClaimantID: claimant, Deadline: api.Timestamp(deadline.UTC().Format(time.RFC3339Nano))})
		if err != nil {
			if pendingCleanupError(err) {
				retries.refused(job.ID, s.deps.Clock.Now())
				continue
			}
			return err
		}
		expires, parseErr := time.Parse(time.RFC3339Nano, string(claim.ExpiresAt))
		if parseErr != nil {
			return serviceError(api.CodeIntegrity, "cleanup claim has no durable execution deadline")
		}
		s.mu.RLock()
		executor, available := s.runtime.Credentials.(api.PlanCleanupExecutor)
		s.mu.RUnlock()
		var receipt api.PlanCleanupReceipt
		if !available || executor == nil || reflect.ValueOf(executor).Kind() == reflect.Pointer && reflect.ValueOf(executor).IsNil() {
			err = api.NotImplemented("lb-v2-secrets", "protected failed-plan cleanup execution and journal read-back")
		} else {
			runCtx, cancel := context.WithTimeout(ctx, expires.Sub(s.deps.Clock.Now()))
			err = store.CheckPlanCleanupClaim(runCtx, attemptScope, claim)
			if err == nil {
				receipt, err = executor.ExecutePlanCleanup(runCtx, attemptScope, claim)
			}
			if err == nil {
				_, err = store.CompletePlanCleanup(runCtx, attemptScope, claim, receipt, executor)
			}
			cancel()
		}
		if err == nil {
			actual, readErr := store.PlanCleanupStatus(ctx, attemptScope, job.ID)
			if readErr != nil {
				return readErr
			}
			if actual.State != "completed" || actual.Receipt == nil || !reflect.DeepEqual(*actual.Receipt, receipt) {
				return serviceError(api.CodeIntegrity, "failed-plan cleanup returned before its durable terminal acknowledgement")
			}
			retries.completed(job.ID)
			continue
		}
		if !pendingCleanupError(err) {
			return err // Storage/integrity or joined failures are never success.
		}
		// An expired attempt cannot author even a refusal. Retain its exact
		// claim for recovery; a later fresh claimant reconciles the same job.
		if expires.After(s.deps.Clock.Now()) {
			failure, ok := err.(*api.Error)
			if ok {
				// Shutdown cannot discard a refusal already observed under this
				// claim. Only its metadata write outlives parent cancellation;
				// external execution remains cancelled, and the original claim
				// expiry still bounds and authorizes the durable write.
				recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), expires.Sub(s.deps.Clock.Now()))
				recordErr := store.RecordPlanCleanupRefusal(recordCtx, attemptScope, claim, failure)
				cancel()
				if recordErr != nil && !effectFenceRefused(recordErr) {
					return recordErr
				}
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		retries.refused(job.ID, s.deps.Clock.Now())
	}
	return nil
}

func cleanupClaimLive(expires api.Timestamp, now time.Time) bool {
	deadline, err := time.Parse(time.RFC3339Nano, string(expires))
	return err == nil && deadline.After(now)
}

func pendingCleanupError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err == context.Canceled || err == context.DeadlineExceeded
	}
	failure, ok := err.(*api.Error)
	if !ok || failure == nil {
		return false
	}
	switch failure.Code {
	case api.CodeUnavailable, api.CodeContainmentUnknown, api.CodeDeadline, api.CodeCancelled,
		api.CodeConflict, api.CodeForbidden, api.CodeNotImplemented, api.CodePrerequisite, api.CodeNotFound:
		return true
	}
	return false
}
