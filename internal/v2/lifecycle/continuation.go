package lifecycle

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Continue has no RPC registration. Only the trusted watchdog can present a
// matching committed swap intent; a carried sender never becomes its actor.
func (s *Service) Continue(ctx context.Context, scope api.Scope,
	request api.ContinuationRequest) (api.Operation, error) {
	if err := s.ready(); err != nil {
		return api.Operation{}, err
	}
	if err := contextReady(ctx); err != nil {
		return api.Operation{}, err
	}
	swap := request.Swap
	if scope.Actor.Kind != "watchdog" || scope.Source != "watchdog" ||
		scope.Request.Method != "" || scope.Request.Proof != nil || scope.Config == "" || !validID(scope.Actor.ID) || !validID(swap.OperationID) {
		return api.Operation{}, problem(api.CodeForbidden, "continuation is watchdog-internal",
			"Use ordinary authenticated resume; profile swaps have no lane RPC.")
	}
	if swap.CausingRun == 0 || uint64(swap.CausingRun) >= maxInteger ||
		swap.ContinuationRun != swap.CausingRun+1 ||
		swap.Limit.Target.Run != swap.CausingRun || !validTarget(swap.Limit.Target) ||
		!validID(swap.LogicalTurnID) || !validID(swap.FromProfileID) || !validID(swap.ToProfileID) ||
		swap.FromProfileID == swap.ToProfileID {
		return api.Operation{}, invalid("invalid profile continuation correlation")
	}
	if !validID(request.IntentID) || !validID(swap.EligibilityID) ||
		swap.ExpectedGeneration == 0 || uint64(swap.ExpectedGeneration) > maxInteger ||
		uint64(swap.CancellationEpoch) > maxInteger ||
		!validID(swap.ProfileGrantID) {
		return api.Operation{}, invalid("continuation request does not match its durable correlation")
	}
	unlock, err := s.lockLife(ctx, swap.Limit.Target.LifeID)
	if err != nil {
		return api.Operation{}, err
	}
	defer unlock()
	operation, err := s.deps.Store.Operation(ctx, scope, swap.OperationID)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	if operation.ID != swap.OperationID || operation.LifeID != swap.Limit.Target.LifeID ||
		operation.Run != swap.CausingRun && operation.Run != swap.ContinuationRun {
		return api.Operation{}, problem(api.CodeConflict, "profile swap intent is not pending",
			"Inspect the original watchdog operation; do not create a replacement launch.")
	}
	intent, err := s.deps.Store.ContinuationIntent(ctx, scope, request.IntentID)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	if err := api.ValidateContinuationOperation(intent, request, operation); err != nil {
		return api.Operation{}, failure(err)
	}
	if intent.ID != request.IntentID || intent.OperationID != swap.OperationID ||
		intent.Target != swap.Limit.Target || intent.LogicalTurnID != swap.LogicalTurnID ||
		intent.ExpectedGeneration != swap.ExpectedGeneration ||
		intent.CancellationEpoch != swap.CancellationEpoch ||
		intent.Eligibility.ID != swap.EligibilityID || !reflect.DeepEqual(intent.Swap, swap) ||
		(intent.Status != "pending" && intent.Status != "claimed" && intent.Status != "completed") {
		return api.Operation{}, problem(api.CodeForbidden, "no matching committed watchdog effect",
			"Reconcile the durable swap intent through the watchdog.")
	}
	if intent.Status == "completed" {
		if operation.Run != swap.ContinuationRun {
			return api.Operation{}, integrity("completed continuation has no continued run")
		}
		if _, err := s.continuationReplayLife(ctx, scope, request); err != nil {
			return api.Operation{}, err
		}
		return operation, nil
	}
	selector := api.LaunchReservationRequest{OperationID: swap.OperationID, ContinuationID: request.IntentID,
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: swap.Limit.Target.LifeID, Epoch: swap.CancellationEpoch}}}}
	if err := api.ValidateLaunchReservationRequest(scope, selector); err != nil {
		return api.Operation{}, failure(err)
	}
	if operation.Run == swap.ContinuationRun && (operation.Status == "pending" || operation.Status == "running") {
		lane, err := s.continuationReplayLife(ctx, scope, request)
		if err != nil {
			return api.Operation{}, err
		}
		reservation, err := s.deps.Store.ReserveLaunch(ctx, scope, selector)
		if err != nil {
			return api.Operation{}, failure(err)
		}
		if api.ValidateLaunchReservation(reservation) != nil || reservation.Mode != "continue" || reservation.Config != scope.Config ||
			reservation.OperationID != operation.ID || reservation.Target != (api.LifeRef{LifeID: operation.LifeID, Run: operation.Run}) ||
			reservation.Authority != (api.LaunchAuthority{Kind: "starter", ID: reservation.PreviousLaunchID}) ||
			reservation.Level != lane.Level || reservation.Role != lane.Role || reservation.Driver != lane.Session.Driver ||
			reservation.BaseGeneration != swap.ExpectedGeneration || reservation.CancellationEpoch != swap.CancellationEpoch || reservation.RequestedBy != scope.Actor {
			return api.Operation{}, integrity("continuation retry changed its retained reservation")
		}
		current, err := s.deps.Store.Operation(ctx, scope, operation.ID)
		if err != nil {
			return api.Operation{}, failure(err)
		}
		currentIntent, err := s.deps.Store.ContinuationIntent(ctx, scope, request.IntentID)
		if err != nil {
			return api.Operation{}, failure(err)
		}
		if err := api.ValidateContinuationOperation(currentIntent, request, current); err != nil {
			return api.Operation{}, failure(err)
		}
		if current.LifeID != operation.LifeID || current.Run != operation.Run {
			return api.Operation{}, integrity("continuation replay changed its retained operation target")
		}
		return current, nil
	}
	lane, err := s.lane(ctx, scope, swap.Limit.Target, true)
	if err != nil {
		return api.Operation{}, err
	}
	lane, err = s.refreshLaunchPolicy(ctx, scope, lane)
	if err != nil {
		return api.Operation{}, err
	}
	if lane.LogicalTurnID != swap.LogicalTurnID || lane.Generation != swap.ExpectedGeneration ||
		lane.CancellationEpoch != swap.CancellationEpoch {
		return api.Operation{}, problem(api.CodeConflict, "logical turn changed",
			"Cancel the stale watchdog continuation.")
	}
	if err := s.resumeReady(ctx, scope, lane, swap.Limit.Target,
		lane.BudgetRemaining); err != nil {
		return api.Operation{}, err
	}
	facts, err := s.facts(ctx, scope, lane, swap.Limit.Target)
	if err != nil {
		return api.Operation{}, err
	}
	if err := requireReviewCapture(facts); err != nil {
		return api.Operation{}, err
	}
	grants, err := s.revalidate(ctx, scope, lane)
	if err != nil {
		return api.Operation{}, err
	}
	var from, to *api.ProfileGrant
	for i := range grants.Profiles {
		grant := &grants.Profiles[i]
		if grant.ID == lane.ProfileGrantID && grant.ProfileID == swap.FromProfileID {
			from = grant
		}
		if grant.ID == swap.ProfileGrantID && grant.ProfileID == swap.ToProfileID && grant.Driver == lane.Session.Driver {
			to = grant
		}
	}
	if from == nil || to == nil || from.Provider != to.Provider ||
		from.Driver != to.Driver || swap.Limit.ProfileID != from.ProfileID {
		return api.Operation{}, problem(api.CodeForbidden, "profile swap exceeds retained delegation",
			"Use a currently delegated compatible profile without changing the task budget.")
	}
	toExpires, expiryErr := time.Parse(time.RFC3339Nano, string(to.ExpiresAt))
	if expiryErr != nil || !s.deps.Clock.Now().Before(toExpires) ||
		to.Paid && !from.Paid || to.Paid && lane.BudgetRemaining.SpendMicros <= 0 {
		return api.Operation{}, problem(api.CodeForbidden, "replacement profile is expired or requires a paid fallback",
			"Use an unexpired delegated profile within the existing provider and spend budget.")
	}
	if absent(s.deps.Credentials) {
		return api.Operation{}, api.NotImplemented("lb-v2-secrets", "CredentialBroker.Room")
	}
	expected := api.ProfileEligibilityRequest{Target: swap.Limit.Target, GrantSetID: grants.ID,
		FromGrantID: from.ID, ToGrantID: to.ID, Driver: lane.Session.Driver,
		Model: lane.Model, Session: lane.Session, HistoryID: lane.Session.HistoryID}
	retainedEnd, retainedErr := time.Parse(time.RFC3339Nano, string(intent.Eligibility.ExpiresAt))
	if !intent.Eligibility.Compatible || intent.Eligibility.Request != expected ||
		!validBlob(intent.Eligibility.Evidence) || retainedErr != nil || !s.deps.Clock.Now().Before(retainedEnd) {
		return api.Operation{}, problem(api.CodeForbidden, "stored profile eligibility differs from the retained task",
			"Use the exact driver, provider, model, session and private history.")
	}
	eligibility, err := s.deps.Credentials.Eligibility(ctx, expected)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	eligibilityEnd, eligibilityErr := time.Parse(time.RFC3339Nano, string(eligibility.ExpiresAt))
	if eligibilityErr != nil || !validID(eligibility.ID) || !eligibility.Compatible || eligibility.Request != expected ||
		!validBlob(eligibility.Evidence) || !s.deps.Clock.Now().Before(eligibilityEnd) {
		return api.Operation{}, problem(api.CodeForbidden, "current profile eligibility is unavailable",
			"Re-evaluate the delegated compatible profile before continuing.")
	}
	policy, err := s.policyForLane(ctx, scope, lane)
	if err != nil {
		return api.Operation{}, err
	}
	for _, excluded := range policy.ProfileExclusions {
		if excluded == to.ID || excluded == to.ProfileID {
			return api.Operation{}, problem(api.CodeForbidden, "replacement profile is excluded by current policy",
				"Select another currently delegated compatible profile.")
		}
	}
	if intent.Slot != nil {
		slotEnd, slotErr := time.Parse(time.RFC3339Nano, string(intent.Slot.ExpiresAt))
		if !validID(intent.Slot.ID) || intent.Slot.ProfileGrantID != to.ID || intent.Slot.ProfileID != to.ProfileID ||
			!validID(intent.Slot.LeaseID) || slotErr != nil || !s.deps.Clock.Now().Before(slotEnd) {
			return api.Operation{}, integrity("retained continuation slot does not match the selected profile")
		}
	}
	room, err := s.deps.Credentials.Room(ctx, *to)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	expires, err := time.Parse(time.RFC3339Nano, string(room.ExpiresAt))
	if err != nil || !room.Available || room.ProfileID != to.ProfileID ||
		!validBlob(room.Evidence) || !s.deps.Clock.Now().Before(expires) {
		return api.Operation{}, problem(api.CodeUnavailable, "replacement profile room is unavailable",
			"Retain profile_wait and let the watchdog apply bounded backoff.")
	}
	// ReserveLaunch owns the atomic continuation/reservation handoff. The plan
	// effect acquires and retains the selected slot under its actual stage claim;
	// this request never resets the logical turn, counters or remaining budget.
	reservation, err := s.deps.Store.ReserveLaunch(ctx, scope, selector)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	if api.ValidateLaunchReservation(reservation) != nil || reservation.Mode != "continue" ||
		reservation.Config != scope.Config || reservation.Target.LifeID != lane.LifeID ||
		reservation.Target.Run != swap.ContinuationRun || reservation.OperationID != swap.OperationID ||
		reservation.BaseGeneration != lane.Generation || reservation.CancellationEpoch != lane.CancellationEpoch ||
		reservation.Level != lane.Level || reservation.Role != lane.Role || reservation.Driver != lane.Session.Driver ||
		reservation.Authority != (api.LaunchAuthority{Kind: "starter", ID: lane.LaunchID}) ||
		reservation.PolicyGeneration != scope.PolicyGeneration || reservation.RequestedBy != scope.Actor {
		return api.Operation{}, integrity("continuation reservation changed its durable fence")
	}
	retained, err := s.deps.Store.Operation(ctx, scope, reservation.OperationID)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	currentIntent, err := s.deps.Store.ContinuationIntent(ctx, scope, request.IntentID)
	if err != nil {
		return api.Operation{}, failure(err)
	}
	if err := api.ValidateContinuationOperation(currentIntent, request, retained); err != nil {
		return api.Operation{}, failure(err)
	}
	if retained.ID != reservation.OperationID ||
		retained.LifeID != reservation.Target.LifeID || retained.Run != reservation.Target.Run {
		return api.Operation{}, integrity("continuation has no retained pending operation")
	}
	return retained, nil
}

func (s *Service) continuationReplayLife(ctx context.Context, scope api.Scope, request api.ContinuationRequest) (api.Lane, error) {
	swap := request.Swap
	lane, err := s.lane(ctx, scope, swap.Limit.Target, false)
	if err != nil {
		return api.Lane{}, err
	}
	if lane.Cleaned || lane.CancellationEpoch != swap.CancellationEpoch || lane.LogicalTurnID != swap.LogicalTurnID ||
		lane.Run != swap.CausingRun && lane.Run != swap.ContinuationRun {
		return api.Lane{}, problem(api.CodeConflict, "continuation replay was cancelled or superseded", "Reconcile its original operation without a replacement launch.")
	}
	if _, err := s.revalidate(ctx, scope, lane); err != nil {
		return api.Lane{}, err
	}
	if _, err := s.policyForLane(ctx, scope, lane); err != nil {
		return api.Lane{}, err
	}
	facts, err := s.facts(ctx, scope, lane, swap.Limit.Target)
	if err != nil {
		return api.Lane{}, err
	}
	if err := requireReviewCapture(facts); err != nil {
		return api.Lane{}, err
	}
	return lane, nil
}
