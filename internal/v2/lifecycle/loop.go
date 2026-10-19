package lifecycle

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// loopSetting reads the actual durable schedule across runs. It survives a
// component restart and does not spawn a timer or fabricate a requester.
func (s *Service) loopSetting(ctx context.Context, scope api.Scope, lane api.Lane) (api.LoopRequest, bool, error) {
	setting, event, err := s.loopRecord(ctx, scope, lane)
	return setting, event.Seq != 0, err
}

func (s *Service) loopRecord(ctx context.Context, scope api.Scope, lane api.Lane) (api.LoopRequest, api.Event, error) {
	var setting api.LoopRequest
	var latest api.Event
	for run := api.RunNumber(1); run <= lane.Run; run++ {
		err := s.walkEvents(ctx, scope, lane, api.LifeRef{LifeID: lane.LifeID, Run: run}, func(event api.Event) error {
			if event.Kind != "lane.loop" || event.Seq <= latest.Seq {
				return nil
			}
			var value api.LoopRequest
			if decode(event.Payload, &value) != nil || validateInput("lane.loop", value) != nil ||
				value.Target.LifeID != lane.LifeID || value.Target.Run != event.Run {
				return integrity("stored loop configuration is invalid")
			}
			setting, latest = value, event
			return nil
		})
		if err != nil {
			return api.LoopRequest{}, api.Event{}, err
		}
	}
	return setting, latest, nil
}

// ReserveLoop is a private installed-scheduler entry. LoopDue stays a read;
// only the store's dedicated Loop alternative reserves the original outbox.
func (s *Service) ReserveLoop(ctx context.Context, scope api.Scope, target api.LifeRef) (api.LaunchReservation, error) {
	if err := s.ready(); err != nil {
		return api.LaunchReservation{}, err
	}
	if err := contextReady(ctx); err != nil {
		return api.LaunchReservation{}, err
	}
	if !validTarget(target) {
		return api.LaunchReservation{}, invalid("invalid loop target")
	}
	unlock, err := s.lockLife(ctx, target.LifeID)
	if err != nil {
		return api.LaunchReservation{}, err
	}
	defer unlock()
	if err := api.CheckSchedulerScope(ctx, scope, s.deps.Clock.Now()); err != nil {
		return api.LaunchReservation{}, failure(err)
	}
	lane, err := s.lane(ctx, scope, target, true)
	if err != nil {
		return api.LaunchReservation{}, err
	}
	if !validBudget(lane.BudgetRemaining) {
		return api.LaunchReservation{}, integrity("loop target has an invalid remaining budget")
	}
	setting, selected, err := s.loopRecord(ctx, scope, lane)
	if err != nil {
		return api.LaunchReservation{}, err
	}
	current, due, err := s.LoopDue(ctx, scope, target)
	if err != nil {
		return api.LaunchReservation{}, err
	}
	if !due || selected.Seq == 0 || !reflect.DeepEqual(current, setting) {
		return api.LaunchReservation{}, problem(api.CodeConflict, "loop is not due under its selected setting", "Reconcile the current setting and original ended run.")
	}
	facts, err := s.facts(ctx, scope, lane, target)
	if err != nil {
		return api.LaunchReservation{}, err
	}
	if facts.endID == "" || !loopEndMatches(facts.end, lane) {
		return api.LaunchReservation{}, integrity("loop selection lost its committed end")
	}
	selector := api.LoopTurnSelector{Target: target, SettingEventID: selected.ID, SettingSeq: selected.Seq,
		SettingOperationID: selected.OperationID, EndEventID: facts.endID, EndSeq: facts.endSeq,
		ExpectedGeneration: lane.Generation, CancellationEpoch: lane.CancellationEpoch, PreviousLaunchID: lane.LaunchID}
	request := api.LaunchReservationRequest{Loop: &selector}
	if err := api.ValidateLaunchReservationRequest(scope, request); err != nil {
		return api.LaunchReservation{}, failure(err)
	}
	reservation, err := s.deps.Store.ReserveLaunch(ctx, scope, request)
	if err != nil {
		return api.LaunchReservation{}, failure(err)
	}
	if api.ValidateLaunchReservation(reservation) != nil || reservation.Loop == nil || reservation.Loop.Selector != selector ||
		reservation.Config != scope.Config || reservation.RequestedBy != scope.Actor || reservation.PolicyGeneration != scope.PolicyGeneration ||
		reservation.Loop.ConfiguredBy != selected.RequestedBy || !reflect.DeepEqual(reservation.Loop.Setting, setting) ||
		!reflect.DeepEqual(reservation.Loop.End, *facts.end) || reservation.Level != lane.Level || reservation.Role != lane.Role ||
		reservation.Driver != lane.Session.Driver || reservation.ParentLifeID != lane.ParentLifeID || reservation.RootLifeID != lane.RootLifeID ||
		reservation.StarterEventSeq != lane.StarterEventSeq || !reflect.DeepEqual(reservation.StarterChain, lane.StarterChain) ||
		reservation.Loop.BudgetRemaining != lane.BudgetRemaining || reservation.Loop.PreviousSession != lane.Session ||
		reservation.Loop.PreviousLogicalTurnID != lane.LogicalTurnID {
		return api.LaunchReservation{}, integrity("loop writer returned a foreign causal reservation")
	}
	return reservation, nil
}

// LoopDue is a private scheduler read of the persisted setting and actual end.
// A due result is eligibility only. The installed scheduler still reserves and
// dispatches an authenticated turn under current grants/policy/life/epoch; this
// read cannot manufacture a lane actor or replace the launch reservation.
func (s *Service) LoopDue(ctx context.Context, scope api.Scope, target api.LifeRef) (api.LoopRequest, bool, error) {
	if err := s.ready(); err != nil {
		return api.LoopRequest{}, false, err
	}
	if err := contextReady(ctx); err != nil {
		return api.LoopRequest{}, false, err
	}
	if scope.Actor.Kind != "service" && scope.Actor.Kind != "scheduler" || !validID(scope.Actor.ID) || scope.Request.Method != "" {
		return api.LoopRequest{}, false, problem(api.CodeForbidden, "schedule reads require the installed scheduler", "Use lane.loop for an authenticated configuration change.")
	}
	lane, err := s.lane(ctx, scope, target, true)
	if err != nil {
		return api.LoopRequest{}, false, err
	}
	setting, found, err := s.loopSetting(ctx, scope, lane)
	if err != nil || !found || !setting.Enabled || lane.Cleaned || lane.State != "idle" && lane.State != "verifying" {
		return setting, false, err
	}
	observation, facts, err := s.observe(ctx, scope, lane, target)
	if err != nil {
		return api.LoopRequest{}, false, err
	}
	if err := requireQuiescence(observation); err != nil {
		return api.LoopRequest{}, false, err
	}
	if !loopEndMatches(facts.end, lane) {
		return api.LoopRequest{}, false, problem(api.CodeContainmentUnknown, "loop has no committed quiescent end", "Reconcile the ended run before scheduling its next turn.")
	}
	ended, err := time.Parse(time.RFC3339Nano, string(facts.end.Observation.ObservedAt))
	if err != nil || setting.BackoffMS > int64((1<<63-1)/time.Millisecond) {
		return api.LoopRequest{}, false, integrity("loop backoff or end timestamp is invalid")
	}
	return setting, !s.deps.Clock.Now().Before(ended.Add(time.Duration(setting.BackoffMS) * time.Millisecond)), nil
}

func loopEndMatches(end *api.RunEndEvent, lane api.Lane) bool {
	return end != nil && end.Reason != "service_lost" && !end.ProfileContinuation &&
		end.LaunchID == lane.LaunchID && end.BudgetRemaining == lane.BudgetRemaining &&
		requireQuiescence(end.Observation) == nil
}
