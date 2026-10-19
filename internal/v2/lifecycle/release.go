package lifecycle

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// One launch owns one immutable release comparison, regardless of whether a
// check or a stop first observes its end. The helper measures every resource;
// this effect records no release success of its own.
func runRelease(facts runFacts, observed api.ProcessObservation) (api.Effect, error) {
	if !validID(facts.leaseID) {
		return api.Effect{}, problem(api.CodePrerequisite, "ended run has no retained helper lease",
			"Retain the run and restore its original launch binding before release.")
	}
	if err := validateObservation(facts.handle, observed); err != nil {
		return api.Effect{}, err
	}
	if err := requireQuiescence(observed); err != nil {
		return api.Effect{}, err
	}
	return api.Effect{ID: launchObjectID(facts.launchID, "run-release"),
		HelperRelease: &api.HelperReleaseRequest{LeaseID: facts.leaseID, Observation: observed}}, nil
}

func sameProcessObservation(a, b api.ProcessObservation) bool {
	a.ObservedAt, b.ObservedAt = "", ""
	return reflect.DeepEqual(a, b)
}

// RecordStoppedRun is a private installed reconciler port. It retains the end
// and the release outbox entry atomically before Stop can complete. Its live
// claim authenticates this attempt; the effect keeps the original author's
// cause across reclamation. It grants no public RPC or helper authority.
func (s *Service) RecordStoppedRun(ctx context.Context, scope api.Scope, lease api.EffectLease, observed api.ProcessObservation) error {
	if err := s.ready(); err != nil {
		return err
	}
	if err := contextReady(ctx); err != nil {
		return err
	}
	if scope.Actor.Kind != "service" || !validID(scope.Actor.ID) || scope.Request.Method != "" || scope.Connection != nil ||
		lease.Record.Effect.Stop == nil || lease.Record.Effect.Context == nil {
		return problem(api.CodeForbidden, "run end requires the installed stop claim", "Reconcile the original committed stop effect.")
	}
	current, err := s.deps.Store.Effect(ctx, scope, lease.Record.Effect.ID)
	if err != nil {
		return failure(err)
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
	if effectRecord(current) != nil || !api.EffectLeaseClaimed(lease) || !reflect.DeepEqual(current, lease.Record) ||
		current.State != api.EffectClaimed || current.Outcome != nil || current.ClaimID != lease.ClaimID ||
		current.ClaimantID != scope.Actor.ID || current.ClaimExpiresAt != lease.ExpiresAt ||
		parseErr != nil || !s.deps.Clock.Now().Before(expires) {
		return problem(api.CodeConflict, "run end stop claim is stale or foreign", "Reclaim the same durable stop effect.")
	}
	cause := *current.Effect.Context
	if cause.Kind != api.InternalLifecycleEffect || cause.Config != scope.Config || cause.EffectID != current.Effect.ID ||
		cause.CauseOperationID != current.Effect.OperationID || cause.Target != current.Effect.Stop.Target {
		return integrity("stop lost its original causal run")
	}
	if err := validateObservation(*current.Effect.Stop, observed); err != nil {
		return err
	}
	if err := requireQuiescence(observed); err != nil {
		return err
	}
	unlock, err := s.lockLife(ctx, cause.Target.LifeID)
	if err != nil {
		return err
	}
	defer unlock()
	lane, err := s.lane(ctx, scope, cause.Target, false)
	if err != nil {
		return err
	}
	if lane.Cleaned || lane.Run != cause.Target.Run || lane.CancellationEpoch != cause.CancellationEpoch {
		return problem(api.CodeConflict, "stopped life or cancellation fence changed", "Retain the original run and reconcile its stop.")
	}
	facts, err := s.facts(ctx, scope, lane, cause.Target)
	if err != nil {
		return err
	}
	if facts.handle != *current.Effect.Stop {
		return integrity("stop selected a foreign retained process")
	}
	if facts.end != nil {
		if facts.end.Reason == "service_lost" || !sameProcessObservation(facts.end.Observation, observed) {
			return integrity("stop disagrees with the committed run end")
		}
		observed = facts.end.Observation
	}
	release, err := runRelease(facts, observed)
	if err != nil {
		return err
	}
	prior, err := s.deps.Store.Effect(ctx, scope, release.ID)
	hasRelease := err == nil
	if err == nil {
		if effectRecord(prior) != nil || prior.Effect.HelperRelease == nil || prior.Effect.Context == nil ||
			prior.Effect.Context.Target != cause.Target || prior.Effect.HelperRelease.LeaseID != facts.leaseID ||
			!sameProcessObservation(prior.Effect.HelperRelease.Observation, observed) || facts.end == nil {
			return integrity("run release pin belongs to another end or lease")
		}
		if lane.State != "stopping" {
			return nil
		}
	}
	if err != nil && !notFound(err) {
		return failure(err)
	}
	release.OperationID = cause.CauseOperationID
	releaseCause := cause
	releaseCause.ID, releaseCause.EffectID, releaseCause.Kind = launchObjectID(facts.launchID, "run-release-cause"), release.ID, api.InternalHelperRelease
	release.Context, release.HelperRelease.Cause = &releaseCause, releaseCause
	// The current claimant authors this transaction, while the immutable DTO
	// above retains the original stop author and requester.
	cause.Actor = scope.Actor
	cause.ID = launchObjectID(current.Effect.ID, "end-"+string(lease.ClaimID))
	next := lane
	events := []api.Event{}
	stateChanged := facts.end == nil || lane.State == "stopping"
	if stateChanged {
		if lane.Generation >= api.Generation(maxInteger) {
			return integrity("life generation exhausted")
		}
		next.Generation++
		next.State, next.Containment = "verifying", "quiescent"
		type runEvent struct {
			kind api.EventKind
			data any
		}
		values := []runEvent{}
		if facts.end == nil {
			values = append(values, runEvent{"run.observed", observed},
				runEvent{"lane.ended", api.RunEndEvent{LaunchID: facts.launchID, Reason: "stop", Observation: observed, BudgetRemaining: lane.BudgetRemaining}})
		}
		values = append(values, runEvent{"lane.state", api.StateEvent{From: lane.State, To: next.State, Generation: next.Generation}})
		for _, value := range values {
			event, err := s.event(scope, lane, value.kind, value.data, scope.Actor)
			if err != nil {
				return err
			}
			event.OperationID, event.RequestID, event.RequestedBy = cause.CauseOperationID, cause.CauseRequestID, cause.RequestedBy
			event.ObservedAt = observed.ObservedAt
			events = append(events, event)
		}
	}
	writes := api.StateWrites{}
	if stateChanged {
		writes.Lanes = []api.Lane{next}
	}
	var effects []api.Effect
	if !hasRelease {
		effects = []api.Effect{release}
	}
	_, err = s.deps.Store.Transact(api.WithEffectLease(ctx, lease), api.Transaction{Scope: scope, Internal: &cause, Writes: writes, Events: events, Effects: effects,
		Compare: []api.Compare{{Kind: api.CompareLane, ID: lane.LifeID, Generation: lane.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: cause.CancellationEpoch}}}})
	if err != nil {
		return failure(err)
	}
	s.NotifyCommit()
	return nil
}
