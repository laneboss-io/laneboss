package lifecycle

import (
	"context"
	"encoding/json"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// A protected identity/store model, not native scheduler authentication.
type loopSource struct {
	identity api.InstalledScheduler
	err      error
	reads    int
}

func (source *loopSource) VerifyScheduler(ctx context.Context) (api.InstalledScheduler, error) {
	source.reads++
	if err := ctx.Err(); err != nil {
		return api.InstalledScheduler{}, err
	}
	return source.identity, source.err
}

type loopStore struct {
	*launchFixtureStore
	source     *loopSource
	clock      api.Clock
	ends       map[api.ID]api.ID
	calls      int
	checkScope bool
}

// The model derives its cause from actual retained events under the writer
// lock, validates the shared contracts and publishes all model rows together.
func (store *loopStore) ReserveLaunch(ctx context.Context, scope api.Scope, request api.LaunchReservationRequest) (api.LaunchReservation, error) {
	if request.Loop == nil {
		return store.launchFixtureStore.ReserveLaunch(ctx, scope, request)
	}
	store.calls++
	if err := api.ValidateLaunchReservationRequest(scope, request); err != nil {
		return api.LaunchReservation{}, err
	}
	if store.checkScope {
		if err := api.CheckSchedulerScope(ctx, scope, store.clock.Now()); err != nil {
			return api.LaunchReservation{}, err
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	selector := *request.Loop
	lane, ok := store.lanes[selector.Target.LifeID]
	epoch, fenced := store.fences[selector.Target.LifeID]
	if !fenced || epoch != selector.CancellationEpoch || !ok || lane.Run != selector.Target.Run || lane.Generation != selector.ExpectedGeneration || lane.CancellationEpoch != selector.CancellationEpoch ||
		lane.LaunchID != selector.PreviousLaunchID || lane.Cleaned || lane.State != "idle" && lane.State != "verifying" ||
		scope.PolicyGeneration != store.policy.Generation || store.source.identity.PolicyGeneration != store.policy.Generation {
		return api.LaunchReservation{}, launchConflict()
	}
	var settingEvent, endEvent api.Event
	for _, event := range store.events {
		if event.Config != scope.Config || event.LifeID != lane.LifeID || event.Origin != "service" {
			continue
		}
		if event.Kind == "lane.loop" && event.Seq > settingEvent.Seq {
			settingEvent = event
		}
		if event.Kind == "lane.ended" && event.Run == lane.Run && event.Seq > endEvent.Seq {
			endEvent = event
		}
	}
	var setting api.LoopRequest
	var end api.RunEndEvent
	if settingEvent.ID != selector.SettingEventID || settingEvent.Seq != selector.SettingSeq || settingEvent.OperationID != selector.SettingOperationID ||
		endEvent.ID != selector.EndEventID || endEvent.Seq != selector.EndSeq || api.DecodeObject(settingEvent.Payload, &setting) != nil ||
		api.DecodeObject(endEvent.Payload, &end) != nil || !setting.Enabled || setting.IdleMessage == nil || end.LaunchID != lane.LaunchID ||
		end.Reason == "service_lost" || end.ProfileContinuation || requireQuiescence(end.Observation) != nil || end.BudgetRemaining != lane.BudgetRemaining {
		return api.LaunchReservation{}, launchConflict()
	}
	for _, event := range store.events {
		if event.LifeID == lane.LifeID && event.Run == lane.Run && event.Kind == "run.observed" && event.Seq > endEvent.Seq {
			var observation api.ProcessObservation
			if api.DecodeObject(event.Payload, &observation) != nil || requireQuiescence(observation) != nil {
				return api.LaunchReservation{}, launchConflict()
			}
		}
	}
	ended, err := time.Parse(time.RFC3339Nano, string(end.Observation.ObservedAt))
	if err != nil || setting.BackoffMS < 1 || setting.BackoffMS > int64(maxInteger) {
		return api.LaunchReservation{}, launchConflict()
	}
	due := ended.Add(time.Duration(setting.BackoffMS) * time.Millisecond)
	if store.clock.Now().Before(due) {
		return api.LaunchReservation{}, launchConflict()
	}
	previous, ok := store.bindings[lane.LaunchID]
	grants, issued := store.grants[lane.GrantSetID]
	if !ok || previous.Recovery == nil || !issued || grants.Revoked || grants.PolicyGeneration != store.policy.Generation {
		return api.LaunchReservation{}, launchConflict()
	}
	if id, used := store.ends[endEvent.ID]; used {
		return store.plans[id].Reservation, nil
	}
	r := api.LaunchReservation{ID: launchIDForTest(), Config: scope.Config, Mode: "turn", Level: lane.Level, Role: lane.Role, Driver: lane.Session.Driver,
		Authority: api.LaunchAuthority{Kind: "scheduler", ID: store.source.identity.CapabilityID}, Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run + 1},
		LaunchID: launchIDForTest(), SpecID: launchIDForTest(), GrantSetID: launchIDForTest(), Generation: lane.Generation + 1, BaseGeneration: lane.Generation,
		CancellationEpoch: lane.CancellationEpoch, PolicyGeneration: store.policy.Generation, ParentLifeID: lane.ParentLifeID, RootLifeID: lane.RootLifeID,
		StarterChain: lane.StarterChain, StarterEventSeq: lane.StarterEventSeq, OperationID: launchIDForTest(), RequestID: launchIDForTest(),
		RequestedBy: scope.Actor, PreviousLaunchID: lane.LaunchID}
	grants.ID, grants.Generation, grants.SHA256 = r.GrantSetID, 1, ""
	grantBytes, err := json.Marshal(grants)
	if err != nil {
		return api.LaunchReservation{}, err
	}
	grants.SHA256 = digestOf(grantBytes)
	loop := api.LoopTurnCause{Schema: "laneboss.loop-turn.v2", Scheduler: store.source.identity, Selector: selector,
		ConfiguredBy: settingEvent.RequestedBy, Setting: setting, End: end, GrantGeneration: grants.Generation,
		PreviousSession: lane.Session, PreviousHome: previous.Recovery.Home, BudgetRemaining: lane.BudgetRemaining,
		DueAt: api.Timestamp(due.UTC().Format(time.RFC3339Nano)), ReservedAt: api.Timestamp(store.clock.Now().UTC().Format(time.RFC3339Nano)),
		ReservationID: r.ID, OperationID: r.OperationID, RequestID: r.RequestID, LaunchID: r.LaunchID, GrantSetID: r.GrantSetID,
		LogicalTurnID: launchIDForTest(), PreviousLogicalTurnID: lane.LogicalTurnID, PlanEffectID: launchIDForTest()}
	raw, err := json.Marshal(loop)
	if err != nil {
		return api.LaunchReservation{}, err
	}
	raw, err = api.CanonicalJSON(raw)
	if err != nil {
		return api.LaunchReservation{}, err
	}
	r.Loop, r.RequestSHA256 = &loop, digestOf(raw)
	r.OriginalRequest = api.BlobRef{ID: launchIDForTest(), Class: "manifest", Bytes: int64(len(raw)), SHA256: digestOf(raw)}
	if err := api.ValidateLaunchReservation(r); err != nil {
		return api.LaunchReservation{}, err
	}
	event := api.Event{Schema: api.SchemaVersion, ID: launchIDForTest(), Config: r.Config, Seq: store.seq + 1, Kind: "loop.reserved", Origin: "service",
		Actor: scope.Actor, RequestedBy: scope.Actor, RequestID: r.RequestID, OperationID: r.OperationID, LifeID: r.Target.LifeID, Run: r.Target.Run,
		LogicalTurnID: loop.LogicalTurnID, ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID, StarterChain: r.StarterChain,
		StarterEventSeq: r.StarterEventSeq, RecordedAt: loop.ReservedAt, RequestedAt: loop.ReservedAt, ObservedAt: loop.ReservedAt, Payload: raw}
	if err := api.ValidateLoopReservedEvent(event, r); err != nil {
		return api.LaunchReservation{}, err
	}
	if store.checkScope {
		if err := api.CheckSchedulerScope(ctx, scope, store.clock.Now()); err != nil {
			return api.LaunchReservation{}, err
		}
	}
	store.plans[r.ID] = api.LaunchPlanRecord{Reservation: r, Phase: "reserved", Generation: 1}
	store.blobs[r.OriginalRequest.ID] = append([]byte{}, raw...)
	store.metadata[r.OriginalRequest.ID] = api.ObjectMetadata{Ref: r.OriginalRequest, Origin: "service", SourceOperationID: r.OperationID,
		ACL: api.ObjectACL{Config: r.Config, LifeID: lane.LifeID, Audience: "owner", Generation: r.Generation, Owner: api.Actor{Kind: "service", ID: "launch-service"}}}
	store.grants[grants.ID] = grants
	store.operations[r.OperationID] = api.Operation{ID: r.OperationID, Status: "pending", LifeID: r.Target.LifeID, Run: r.Target.Run}
	cause := api.InternalIntent{ID: launchIDForTest(), Kind: api.InternalLaunchPlan, Config: r.Config, Actor: api.Actor{Kind: "service", ID: "launch-service"},
		RequestedBy: scope.Actor, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: loop.PlanEffectID, Target: r.Target,
		LogicalTurnID: loop.LogicalTurnID, CancellationEpoch: r.CancellationEpoch}
	store.effects[loop.PlanEffectID] = api.EffectRecord{Effect: api.Effect{ID: loop.PlanEffectID, OperationID: r.OperationID, Context: &cause,
		PlanLaunch: &api.LaunchPlanEffect{ReservationID: r.ID}}, State: api.EffectPending, Generation: 1}
	store.seq, store.events = event.Seq, append(store.events, event)
	store.ends[endEvent.ID] = r.ID
	return r, nil
}
