// Package watchdog validates outside quota evidence for service continuation.
// No lane-facing method is registered by this package.
package watchdog

import (
	"context"
	"reflect"
	"regexp"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Config      string
	Store       api.StateStore
	Credentials api.CredentialBroker
	Lifecycle   api.Continuation
	Launcher    api.Launcher
	Claudock    api.Runner
	Grants      api.GrantResolver
	Clock       api.Clock
	// ResolveUsage supplies retained native worker facts and protected profile/
	// runtime enrollment for a committed usage envelope. The envelope itself
	// cannot authenticate its own producer. Missing installation fails closed.
	ResolveUsage func(context.Context, api.Scope, api.BlobRef) (UsageProvenance, error)
}

type Service struct {
	deps Dependencies
}

var _ api.Watchdog = (*Service)(nil)

var validID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var validDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func New(deps Dependencies) (*Service, error) {
	if !validID.MatchString(deps.Config) {
		return nil, problem(api.CodeInvalid, "watchdog requires one explicit configuration")
	}
	for _, dependency := range []any{
		deps.Store, deps.Credentials, deps.Lifecycle, deps.Launcher,
		deps.Claudock, deps.Grants, deps.Clock,
	} {
		if nilDependency(dependency) {
			return nil, problem(api.CodePrerequisite, "watchdog dependency is missing")
		}
	}
	return &Service{deps: deps}, nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	// Interfaces containing nil concrete pointers must not pass initialization.
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func problem(code api.ErrorCode, message string) *api.Error {
	return &api.Error{
		Code: code, Message: message, Owner: "lb-v2-watchdog",
		Instead: "Retain the evidence and use the supervising service's recovery route.",
	}
}

func (s *Service) readScope() api.Scope {
	return api.Scope{
		Config: s.deps.Config, Source: "watchdog",
		Actor: api.Actor{Kind: "watchdog", ID: "watchdog"},
	}
}

// Run zero is the draft.4 internal current-life lookup. An exact old run can
// legitimately resolve a historical snapshot, which cannot fence new work.
func (s *Service) currentLane(ctx context.Context, target api.LifeRef) (api.Lane, error) {
	return s.deps.Store.Lane(ctx, s.readScope(), api.LifeRef{LifeID: target.LifeID})
}

// Shape is checked before entering the writer, including draft.4's closed
// internal field/event/effect/guard catalog. Current authority and atomic
// comparisons still belong to the service-owned store.
func (s *Service) transact(ctx context.Context, transaction api.Transaction) (api.Commit, error) {
	if err := api.ValidateTransactionShape(transaction); err != nil {
		return api.Commit{}, err
	}
	return s.deps.Store.Transact(ctx, transaction)
}

// ObserveLimit records one durable intent per causing run. Only lifecycle's
// consumed-once claim may acquire a replacement slot and open the next gate.
func (s *Service) ObserveLimit(ctx context.Context, signal api.LimitSignal) (api.Operation, error) {
	if err := s.ready(ctx); err != nil {
		return api.Operation{}, err
	}
	if err := checkSignal(signal); err != nil {
		return api.Operation{}, err
	}
	prior, found, err := s.intent(ctx, signal.Target)
	if err != nil {
		return api.Operation{}, err
	}
	if found {
		if prior.Status != "cancelled" && !sameLimitCause(prior.Swap.Limit, signal) {
			return api.Operation{}, problem(api.CodeConflict, "a different limit already owns this run's continuation")
		}
		return s.resumeIntent(ctx, prior)
	}
	plan, err := s.assess(ctx, signal)
	if err != nil {
		return api.Operation{}, err
	}
	return s.recordIntent(ctx, plan, signal, 0, 0)
}

// Cancel commits a live intent's epoch and marker under the shared life CAS.
// No absent or terminal intent causes a write or a new cancellation epoch.
// Lifecycle still owns process stopping and collection; cancellation alone is
// never evidence that a process exited or its credential slot can be released.
func (s *Service) Cancel(ctx context.Context, target api.LifeRef) error {
	if err := s.ready(ctx); err != nil {
		return err
	}
	if err := checkTarget(target); err != nil {
		return err
	}
	return s.cancelIntent(ctx, target)
}

// Reconcile reads service-origin watchdog and lifecycle controls. It neither
// treats a pending receipt as completion nor substitutes a fresh ObserveLimit for an
// already cancelled intent. Backoff uses durable event time, not process time.
func (s *Service) Reconcile(ctx context.Context, target api.LifeRef) (api.Operation, error) {
	if err := s.ready(ctx); err != nil {
		return api.Operation{}, err
	}
	if err := checkTarget(target); err != nil {
		return api.Operation{}, err
	}
	prior, found, err := s.intent(ctx, target)
	if err != nil {
		return api.Operation{}, err
	}
	if found {
		return s.resumeIntent(ctx, prior)
	}
	return s.reassess(ctx, target, 0, "")
}

// reassess is used for a durable wait or a legacy service limit record. It
// never resets the delay on a repeated ObserveLimit call or service restart.
func (s *Service) reassess(ctx context.Context, target api.LifeRef, generation api.Generation, operation api.ID) (api.Operation, error) {
	lane, err := s.currentLane(ctx, target)
	if err != nil {
		return api.Operation{}, err
	}
	waiting := false
	if generation > 0 {
		prior, found, err := s.intent(ctx, target)
		if err != nil {
			return api.Operation{}, err
		}
		if !found || prior.Generation != generation || prior.OperationID != operation ||
			(prior.Status != "waiting" && prior.Status != "pending") {
			return api.Operation{}, problem(api.CodeConflict, "continuation changed before fresh assessment")
		}
		waiting = prior.Status == "waiting"
	}
	events, err := s.events(ctx, target.LifeID)
	if err != nil {
		return api.Operation{}, err
	}
	if err := controlError(events, target, lane.LogicalTurnID); err != nil {
		return api.Operation{}, err
	}
	var signal *api.LimitSignal
	var waitUntil time.Time
	var previous int64
	var waitingOperation api.ID
	for _, event := range events {
		if event.Run != target.Run || !outsideEvent(event, "watchdog") {
			continue
		}
		switch event.Kind {
		case "watchdog.swapped":
			return api.Operation{}, problem(api.CodeIntegrity, "swap event is missing its durable continuation intent")
		case "watchdog.limit", "watchdog.waiting":
			var payload api.WatchdogEvent
			if err := decodePayload(event.Payload, &payload); err != nil {
				return api.Operation{}, err
			}
			if payload.Signal == nil || payload.Signal.Target != target {
				return api.Operation{}, problem(api.CodeIntegrity, "watchdog record has no matching limit")
			}
			if signal != nil && !sameLimitCause(*signal, *payload.Signal) {
				return api.Operation{}, problem(api.CodeIntegrity, "watchdog record changed its causing limit")
			}
			signal = payload.Signal
			if event.Kind == "watchdog.waiting" {
				if payload.RetryAfterMS < minBackoff.Milliseconds() ||
					payload.RetryAfterMS > maxBackoff.Milliseconds() || payload.RetryAfterMS < previous {
					return api.Operation{}, problem(api.CodeIntegrity, "watchdog backoff is outside its bound")
				}
				at, err := timestamp(event.RecordedAt)
				if err != nil || at.After(s.deps.Clock.Now()) || (previous > 0 && at.Before(waitUntil)) {
					return api.Operation{}, problem(api.CodeIntegrity, "watchdog wait time is invalid")
				}
				waitUntil = at.Add(time.Duration(payload.RetryAfterMS) * time.Millisecond)
				previous = payload.RetryAfterMS
				waitingOperation = event.OperationID
			}
		}
	}
	if signal == nil {
		return api.Operation{}, problem(api.CodeNotFound, "no durable watchdog limit exists for this run")
	}
	if waiting && previous == 0 {
		return api.Operation{}, problem(api.CodeIntegrity, "waiting intent has no durable waiting event")
	}
	if waiting && waitingOperation != operation {
		return api.Operation{}, problem(api.CodeIntegrity, "waiting intent has no matching current wait operation")
	}
	if s.deps.Clock.Now().Before(waitUntil) {
		err := problem(api.CodeUnavailable, "watchdog profile-room backoff has not elapsed")
		err.Retryable = true
		return api.Operation{}, err
	}
	plan, err := s.assessFresh(ctx, *signal, true)
	if err != nil {
		return api.Operation{}, err
	}
	return s.recordIntent(ctx, plan, *signal, generation, previous)
}

func (s *Service) ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		if err == context.DeadlineExceeded {
			return problem(api.CodeDeadline, "watchdog deadline elapsed")
		}
		return problem(api.CodeCancelled, "watchdog request was cancelled")
	}
	if s == nil || s.deps.Store == nil || s.deps.Clock == nil {
		return problem(api.CodePrerequisite, "watchdog was not initialized")
	}
	return nil
}

func checkTarget(target api.LifeRef) error {
	if !validID.MatchString(string(target.LifeID)) || target.Run == 0 || uint64(target.Run) > maxExactInteger {
		return problem(api.CodeInvalid, "watchdog requires an immutable life and positive run")
	}
	return nil
}

func timestamp(value api.Timestamp) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, string(value))
	if err != nil || len(value) == 0 || value[len(value)-1] != 'Z' {
		return time.Time{}, problem(api.CodeIntegrity, "outside evidence time is not UTC RFC3339")
	}
	return parsed, nil
}

const (
	maxExactInteger = uint64(1<<53 - 1)
	minBackoff      = 5 * time.Second
	maxBackoff      = 5 * time.Minute
)

// nextBackoff saturates before multiplication so arbitrarily long exhaustion
// cannot wrap into a busy loop. Only a durable waiting event advances attempts.
func nextBackoff(previous int64) (int64, error) {
	if previous == 0 {
		return minBackoff.Milliseconds(), nil
	}
	if previous < minBackoff.Milliseconds() || previous > maxBackoff.Milliseconds() {
		return 0, problem(api.CodeIntegrity, "previous watchdog backoff is invalid")
	}
	if previous >= maxBackoff.Milliseconds()/2 {
		return maxBackoff.Milliseconds(), nil
	}
	return previous * 2, nil
}
