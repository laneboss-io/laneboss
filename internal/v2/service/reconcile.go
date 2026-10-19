package service

import (
	"context"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Server) reconcileLoop(ctx context.Context) {
	s.mu.Lock()
	s.reconciling = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.reconciling = false; s.mu.Unlock() }()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	retries := make(effectRetries)
	for {
		if ctx.Err() != nil {
			return
		}
		paused, err := s.prepareReconcile(ctx)
		if err != nil {
			if ctx.Err() == nil {
				s.recordFault(err)
			}
			return
		}
		if !paused {
			// The watchdog's refusal for one life is recorded; it does not end the only reconcile loop, which
			// also runs every later outbox effect (premortem entry 2).
			if err := s.reconcileWatchdog(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				s.recordFault(err)
			}
			if err := s.reconcilePlanCleanup(ctx, retries); err != nil {
				if ctx.Err() == nil {
					s.recordFault(err)
				}
				return
			}
			if ctx.Err() != nil {
				return
			}
			if recovery, ok := s.deps.Store.(interface{ RecoverGuidance(context.Context) error }); ok {
				if err := recovery.RecoverGuidance(ctx); err != nil {
					if err != ctx.Err() {
						s.recordFault(err)
					}
					return
				}
			}
			effects, err := s.deps.Store.PendingEffects(ctx, api.CursorRequest{Limit: 200})
			if err != nil {
				// Only this loop's exact cancellation ends an interrupted read.
				// A joined or independent storage failure remains a host fault.
				if err != ctx.Err() {
					s.recordFault(err)
				}
				return
			}
		effectsLoop:
			for _, effect := range effects {
				if ctx.Err() != nil {
					return
				}
				if !retries.ready(effect.ID, s.deps.Clock.Now()) {
					continue
				}
				switch s.reconcileEffect(ctx, effect, retries) {
				case attemptStop:
					return
				case attemptPause:
					break effectsLoop
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) prepareReconcile(ctx context.Context) (bool, error) {
	if recovery, ok := s.deps.Store.(interface{ RecoverArchives(context.Context) error }); ok {
		if err := recovery.RecoverArchives(ctx); err != nil {
			return false, err
		}
	}
	if recovery, ok := s.deps.Store.(interface{ RecoverReservations(context.Context) error }); ok {
		if err := recovery.RecoverReservations(ctx); err != nil {
			return false, err
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dispatchPaused, nil
}

// Only an all-fence error can become a retained refusal. If a joined error
// also contains storage/integrity failure, keep the whole failure fatal.
func executionRefusal(err error) *api.Error {
	if !effectFenceRefused(err) {
		return nil
	}
	return forbiddenCause(err)
}

func forbiddenCause(err error) *api.Error {
	switch failure := err.(type) {
	case *api.Error:
		if failure != nil && failure.Code == api.CodeForbidden {
			return failure
		}
	case interface{ Unwrap() []error }:
		for _, cause := range failure.Unwrap() {
			if refused := forbiddenCause(cause); refused != nil {
				return refused
			}
		}
	case interface{ Unwrap() error }:
		return forbiddenCause(failure.Unwrap())
	}
	return nil
}

// A stale/revoked effect is local to that attempt. A joined store or integrity
// failure must remain fatal even when another cause is an expected fence.
func effectFenceRefused(err error) bool {
	switch failure := err.(type) {
	case *api.Error:
		return failure != nil && (failure.Code == api.CodeForbidden || failure.Code == api.CodeConflict)
	case interface{ Unwrap() []error }:
		causes := failure.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !effectFenceRefused(cause) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return effectFenceRefused(failure.Unwrap())
	}
	return false
}

func (s *Server) recordFault(err error) {
	s.mu.Lock()
	s.fault = errors.Join(s.fault, err)
	s.mu.Unlock()
}

func (s *Server) runEffect(ctx context.Context, scope api.Scope, lease api.EffectLease) (outcome api.EffectOutcome, resultErr error) {
	effect := lease.Record.Effect
	check := "effect_claim"
	defer func() {
		if effect.PlanLaunch != nil && ctx != nil {
			api.ObserveHelperReason(ctx, resultErr, check)
		}
	}()
	outcome = api.EffectOutcome{EffectID: effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "succeeded"}
	current, err := s.deps.Store.Effect(ctx, scope, effect.ID)
	if err != nil {
		return outcome, err
	}
	expires, err := time.Parse(time.RFC3339Nano, string(current.ClaimExpiresAt))
	if err != nil || !api.EffectLeaseClaimed(lease) || current.State != api.EffectClaimed || !expires.After(s.deps.Clock.Now()) || current.Outcome != nil || current.ClaimID != lease.ClaimID || current.Generation != lease.Record.Generation || current.ClaimantID != scope.Actor.ID || !reflect.DeepEqual(current.Effect, effect) {
		return outcome, serviceError(api.CodeConflict, "effect execution lost its actual current durable claim")
	}
	s.mu.RLock()
	runtime := s.runtime
	s.mu.RUnlock()
	check = "effect_support"
	if err := supportsEffect(runtime, effect); err != nil {
		return outcome, err
	}
	ctx = api.WithEffectLease(ctx, lease)
	// First claim advances pending generation 1 to 2. Every later claim
	// reconciles the same effect while retaining the shared claimed state.
	recovering := lease.Record.Generation > 2
	switch {
	case effect.ApplyChange != nil:
		return s.runChangePublication(ctx, scope, lease, runtime)
	case effect.Worker != nil && effect.Worker.Kind == "archive":
		return s.runArchive(ctx, scope, lease)
	case effect.Clean != nil:
		return s.runCleanup(ctx, scope, lease)
	case effect.Deliver != nil:
		return s.runMailDelivery(ctx, scope, lease)
	case effect.PlanLaunch != nil:
		// The executor is an internal claim, not a public authenticated scope.
		// Bind its policy generation from the current store for this attempt;
		// lifecycle still compares it with the reservation and rechecks at each
		// boundary. Never copy a stale generation from the original requester.
		check = "plan_policy"
		policy, err := s.deps.Store.Policy(ctx, scope)
		if err != nil {
			return outcome, err
		}
		scope.PolicyGeneration = policy.Generation
		// The runner's per-run authority (assembly/run_check.go verifyRun) reads the live planning claim from the
		// context; carry this attempt's effect lease into planning.
		plan, err := runPlanning(api.WithEffectLease(ctx, lease), runtime.LaunchPlanner, scope, lease)
		if err != nil {
			return outcome, err
		}
		check = "agent_stage"
		opened, process, err := s.reconcileAgentLaunch(ctx, scope, lease, plan, runtime)
		if err != nil {
			return outcome, err
		}
		outcome.Process = &process
		outcome.LaunchPlan = &opened
	case effect.Launch != nil:
		binding, err := s.Binding(ctx, effect.Launch.LaunchID)
		if err != nil {
			return outcome, err
		}
		actual, err := runtime.Helper.ReconcileGate(ctx, api.HelperReconcileRequest{LeaseID: binding.Record.UIDLeaseID, LaunchID: binding.Record.ID,
			PreparedID: binding.Prepared.ID, OperationID: effect.OperationID})
		if err != nil {
			return outcome, err
		}
		if actual.Prepared == nil || *actual.Prepared != binding.Prepared {
			return outcome, serviceError(api.CodeContainmentUnknown, "launch gate identity is unknown")
		}
		if actual.Process != nil {
			control, err := s.launchStore()
			if err != nil {
				return outcome, err
			}
			if err := control.RecordLaunchObservation(ctx, binding.Record.ID, actual); err != nil {
				return outcome, err
			}
			outcome.Process = actual.Process
		} else {
			if actual.GateState != "prepared" || actual.Observation.State != "prepared" {
				return outcome, serviceError(api.CodeContainmentUnknown, "gate is not known nonexecuting")
			}
			permit, err := runtime.Identity.BindLaunch(ctx, binding)
			if err != nil {
				return outcome, err
			}
			process, err := runtime.Launcher.Launch(ctx, binding.Prepared, permit)
			if err != nil {
				return outcome, err
			}
			outcome.Process = &process
		}
	case effect.Stop != nil:
		if selector, ok := s.deps.Store.(interface {
			GrantRevocationEffect(context.Context, api.Scope, api.ID) (bool, error)
		}); ok {
			revocation, err := selector.GrantRevocationEffect(ctx, scope, effect.ID)
			if err != nil {
				return outcome, err
			}
			if revocation {
				coordinator, ok := runtime.Lifecycle.(interface {
					RevokeLaunch(context.Context, api.Scope, api.EffectLease) error
				})
				if !ok {
					return outcome, serviceError(api.CodePrerequisite, "grant revocation requires its causal lifecycle coordinator")
				}
				if err := coordinator.RevokeLaunch(ctx, scope, lease); err != nil {
					return outcome, err
				}
			}
		}
		coordinator, _ := runtime.Lifecycle.(interface {
			RecordStoppedRun(context.Context, api.Scope, api.EffectLease, api.ProcessObservation) error
		})
		observation, err := ReconcileStoppedGate(ctx, runtime.Launcher, coordinator, scope, lease)
		if err != nil {
			return outcome, err
		}
		outcome.Observation = &observation
	case effect.HelperAllocate != nil:
		if recovering {
			return outcome, serviceError(api.CodeContainmentUnknown, "allocation reply was lost; helper reconciliation is required before repeating")
		}
		value, err := runtime.Helper.Allocate(ctx, *effect.HelperAllocate)
		if err != nil {
			return outcome, err
		}
		outcome.HelperLease = &value
	case effect.HelperPrepare != nil:
		if recovering {
			request := api.HelperReconcileRequest{LeaseID: effect.HelperPrepare.LeaseID, OperationID: effect.OperationID}
			if control, ok := s.deps.Store.(launchControlStore); ok {
				plans, err := control.LaunchInventory(ctx)
				if err != nil {
					return outcome, err
				}
				for _, plan := range plans {
					if plan.Handoff != nil && plan.Handoff.Spec.ID == effect.HelperPrepare.PreparedSpecID && plan.Handoff.SpecSHA256 == effect.HelperPrepare.SpecSHA256 {
						request.LaunchID = plan.Reservation.LaunchID
						if plan.Phase == "bound" || plan.Phase == "opened" {
							binding, err := s.deps.Store.LaunchBinding(ctx, request.LaunchID)
							if err != nil {
								return outcome, err
							}
							request.PreparedID = binding.Prepared.ID
						}
					}
				}
			}
			value, err := runtime.Helper.ReconcileGate(ctx, request)
			if err != nil {
				return outcome, err
			}
			if value.Prepared == nil {
				return outcome, serviceError(api.CodeContainmentUnknown, "prepared gate outcome is unknown")
			}
			outcome.Prepared = value.Prepared
		} else {
			value, err := runtime.Helper.Prepare(ctx, *effect.HelperPrepare)
			if err != nil {
				return outcome, err
			}
			outcome.Prepared = &value
		}
	case effect.HelperRelease != nil:
		// Every fresh claim drains the same retained request before native
		// teardown. Reclamation keeps the snapshot and measured receipt exact.
		if err := s.DrainReleaseCaptures(ctx, *effect.HelperRelease); err != nil {
			return outcome, err
		}
		// The retained request pins the original author and capture source.
		// Native credential cleanup authenticates this exact live claimant;
		// keep every other cause field and the immutable outbox unchanged.
		release := *effect.HelperRelease
		release.Cause.Actor = api.Actor{Kind: "service", ID: lease.Record.ClaimantID}
		value, err := runtime.Helper.Release(ctx, release)
		if err != nil {
			return outcome, err
		}
		if collector, ok := runtime.Lifecycle.(interface {
			CollectGrantWorkers(context.Context, api.Scope, api.EffectLease, api.ReleaseReceipt) error
		}); ok {
			if err := collector.CollectGrantWorkers(ctx, scope, lease, value); err != nil {
				return outcome, err
			}
		}
		outcome.Release = &value
	case effect.HelperAbort != nil:
		if err := s.DrainAbortCaptures(ctx, *effect.HelperAbort); err != nil {
			return outcome, err
		}
		value, err := runtime.Helper.AbortGate(ctx, *effect.HelperAbort)
		if err != nil {
			return outcome, err
		}
		outcome.Abort = &value
	case effect.Channel != nil:
		var value api.Delivery
		var err error
		if recovering {
			value, err = runtime.Delivery.ReconcileChannel(ctx, scope, *effect.Channel)
		} else {
			value, err = runtime.Delivery.DeliverChannel(ctx, scope, *effect.Channel)
		}
		if err != nil {
			return outcome, err
		}
		outcome.Delivery = &value
	default:
		return outcome, api.NotImplemented("lb-v2-service", "effect execution requires its owning coordinator")
	}
	return outcome, nil
}

// ReconcileStoppedGate observes the original gate and commits its measured end
// through the current stop claim. The launcher and coordinator independently
// resolve that claim; this in-process boundary grants no public authority.
func ReconcileStoppedGate(ctx context.Context, launcher api.Launcher, coordinator interface {
	RecordStoppedRun(context.Context, api.Scope, api.EffectLease, api.ProcessObservation) error
}, scope api.Scope, lease api.EffectLease) (api.ProcessObservation, error) {
	if lease.Record.Effect.Stop == nil {
		return api.ProcessObservation{}, serviceError(api.CodeForbidden, "stopped gate requires its original stop effect")
	}
	ctx = api.WithEffectLease(ctx, lease)
	observation, err := launcher.Observe(ctx, *lease.Record.Effect.Stop)
	if err != nil {
		return observation, err
	}
	// The stop intent is already committed. An exited gate still needs the
	// same causal helper fence before its end can be published as stopped.
	if observation.State == "running" || observation.State == "exited" {
		observation, err = launcher.Stop(ctx, *lease.Record.Effect.Stop, "committed stop intent")
	}
	if err != nil {
		return observation, err
	}
	// Contracts §3 orders native observation before recording the end; §14
	// permits correlated StopGate preflight within this committed effect.
	// A successful native stop still cannot publish completion without its
	// lifecycle owner for the real end and subsequent release.
	if coordinator == nil {
		return observation, serviceError(api.CodePrerequisite, "stop requires its durable lifecycle end and release coordinator")
	}
	return observation, coordinator.RecordStoppedRun(ctx, scope, lease, observation)
}
