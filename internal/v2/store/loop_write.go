package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func loopKey(config string, pick api.LoopTurnSelector) api.ID {
	return api.ID(hash([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", config, pick.Target.LifeID, pick.Target.Run, pick.EndEventID))))
}

// Compare retained ACL metadata without constructing the configurator's scope.
func loopTaskVisible(actor api.Actor, acl api.ObjectACL) bool {
	if actor.Kind != "human" && actor.Kind != "lane" {
		return false
	}
	if acl.Owner == actor || acl.Audience == "config" {
		return true
	}
	switch acl.Audience {
	case "human":
		return actor.Kind == "human"
	case "life":
		return acl.LifeID != "" && acl.LifeID == actor.LifeID
	case "participants":
		return slices.Contains(acl.Participants, actor.ID) || actor.LifeID != "" && slices.Contains(acl.Participants, actor.LifeID)
	}
	return false
}

func lastLoop(ctx context.Context, db queryer, life api.ID, kind string, run api.RunNumber) (api.Event, error) {
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT data FROM events WHERE json_extract(data,'$.life_id')=? AND json_extract(data,'$.kind')=? AND (?=0 OR json_extract(data,'$.run')=?) ORDER BY seq DESC LIMIT 1`, string(life), kind, uint64(run), uint64(run)).Scan(&raw)
	if err == sql.ErrNoRows {
		return api.Event{}, fault(api.CodePrerequisite, "loop requires its actual setting and end")
	}
	if err != nil {
		return api.Event{}, err
	}
	var event api.Event
	if err := decodeStored(raw, &event); err != nil {
		return event, err
	}
	if event.Origin != "service" {
		return event, fault(api.CodeForbidden, "loop input is not authoritative")
	}
	return event, nil
}

// reserveLoop owns the same writer lock as ReserveLaunch. The producer must
// not reenter this writer; native checks and the locked policy view are distinct.
func (s *Service) reserveLoop(ctx context.Context, scope api.Scope, pick api.LoopTurnSelector) (result api.LaunchReservation, resultErr error) {
	stamp, err := api.SchedulerStamp(ctx, scope, s.deps.Clock.Now())
	if err != nil {
		return result, err
	}
	if err := s.dispatchAllowed(ctx, s.db); err != nil {
		return result, err
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, s.db, "policy", api.ID(scope.Config), &policy); err != nil {
		return result, err
	}
	if policy.Generation != scope.PolicyGeneration || stamp.PolicyGeneration != policy.Generation {
		return result, fault(api.CodeConflict, "loop policy changed")
	}
	settingEvent, err := lastLoop(ctx, s.db, pick.Target.LifeID, "lane.loop", 0)
	if err != nil {
		return result, err
	}
	endEvent, err := lastLoop(ctx, s.db, pick.Target.LifeID, "lane.ended", pick.Target.Run)
	if err != nil {
		return result, err
	}
	var setting api.LoopRequest
	var end api.RunEndEvent
	if wire.Decode(settingEvent.Payload, &setting) != nil || wire.Decode(endEvent.Payload, &end) != nil {
		return result, fault(api.CodeIntegrity, "loop event payload is invalid")
	}
	if settingEvent.ID != pick.SettingEventID || settingEvent.Seq != pick.SettingSeq || settingEvent.OperationID != pick.SettingOperationID || endEvent.ID != pick.EndEventID || endEvent.Seq != pick.EndSeq || !setting.Enabled || setting.IdleMessage == nil || setting.Target.LifeID != pick.Target.LifeID || setting.Target.Run > pick.Target.Run || end.LaunchID != pick.PreviousLaunchID || end.ProfileContinuation || end.Reason == "limit" || end.Reason == "service_lost" {
		return result, fault(api.CodeConflict, "loop selection changed or is disabled")
	}
	if end.Observation.State != "exited" || end.Observation.Survivors == nil || *end.Observation.Survivors != 0 || end.Observation.Handle.Target != pick.Target || (end.Observation.ExitCode == nil) == (end.Observation.Signal == nil) {
		return result, fault(api.CodeContainmentUnknown, "loop has no known terminal quiescence")
	}
	ended, err := time.Parse(time.RFC3339Nano, string(end.Observation.ObservedAt))
	if err != nil || setting.BackoffMS < 1 || setting.BackoffMS > int64((1<<63-1)/time.Millisecond) {
		return result, fault(api.CodeIntegrity, "loop backoff or time is invalid")
	}
	due := ended.Add(time.Duration(setting.BackoffMS) * time.Millisecond)
	if s.deps.Clock.Now().Before(due) {
		return result, fault(api.CodeConflict, "loop is not due")
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", pick.Target.LifeID, &lane); err != nil {
		return result, err
	}
	if lane.Cleaned || lane.CancellationEpoch != pick.CancellationEpoch || lane.PolicyGeneration != policy.Generation || !positiveBudget(lane.BudgetRemaining) {
		return result, fault(api.CodeConflict, "loop life, policy, budget or epoch changed")
	}
	if err := s.loopChain(ctx, s.db, lane, policy.Generation); err != nil {
		return result, err
	}
	var prior api.ID
	err = storedProjection(ctx, s.db, "loop_end", loopKey(scope.Config, pick), &prior)
	if err == nil {
		var kept api.LaunchPlanRecord
		if err := storedProjection(ctx, s.db, "launch_plan", prior, &kept); err != nil {
			return result, err
		}
		old := kept.Reservation
		if old.Loop == nil || old.Loop.Selector != pick || old.RequestedBy != scope.Actor || old.Loop.Scheduler.InstallationGeneration != stamp.InstallationGeneration {
			return result, fault(api.CodeConflict, "loop replay differs from its original selection")
		}
		if err := s.checkLaunchBytes(ctx, s.db, kept); err != nil {
			return result, err
		}
		if err := s.currentLaunch(ctx, s.db, kept); err != nil {
			return result, err
		}
		if err := api.CheckSchedulerScope(ctx, scope, s.deps.Clock.Now()); err != nil {
			return result, err
		}
		return old, nil
	}
	if !absent(err) {
		return result, err
	}
	if lane.Run != pick.Target.Run || lane.Generation != pick.ExpectedGeneration || lane.LaunchID != pick.PreviousLaunchID || lane.State != "idle" && lane.State != "verifying" || lane.BudgetRemaining != end.BudgetRemaining {
		return result, fault(api.CodeConflict, "loop causing life changed")
	}
	var pending int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM projections WHERE kind='launch_plan' AND json_extract(data,'$.reservation.target.life_id')=? AND json_extract(data,'$.reservation.target.run')=? AND json_extract(data,'$.phase')!='failed'`, string(lane.LifeID), uint64(lane.Run+1)).Scan(&pending); err != nil {
		return result, err
	}
	if pending != 0 {
		return result, fault(api.CodeConflict, "another launch owns the next run")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM events WHERE json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND seq>? AND json_extract(data,'$.kind') IN ('run.observed','lane.lost')`, string(lane.LifeID), uint64(lane.Run), uint64(endEvent.Seq))
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var raw []byte
		var row api.Event
		var observed api.ProcessObservation
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return result, err
		}
		if decodeStored(raw, &row) != nil || row.Kind == "lane.lost" || wire.Decode(row.Payload, &observed) != nil || observed.State != "exited" || observed.Survivors == nil || *observed.Survivors != 0 {
			rows.Close()
			return result, fault(api.CodeContainmentUnknown, "later loop observation is not quiescent")
		}
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return result, readErr
	}
	if closeErr != nil {
		return result, closeErr
	}
	previous, err := s.launchBinding(ctx, s.db, lane.LaunchID)
	if err != nil {
		return result, err
	}
	if previous.Recovery == nil || previous.Record.Target != pick.Target || previous.Record.ContainmentID != end.Observation.Handle.ContainmentID || previous.Record.ProcessGeneration != end.Observation.Handle.Generation || !samePrivateSession(lane.Session, previous.Recovery.Handoff.Spec.Runner.Session) || lane.Session.VendorID == "" {
		return result, fault(api.CodeIntegrity, "loop lost its retained private session")
	}
	workspace := previous.Recovery.Handoff.Spec.Workspace
	if lane.Workspace.ID != workspace.ID || lane.Workspace.ProjectID != workspace.ProjectID || lane.Workspace.Branch != workspace.Branch ||
		lane.Workspace.Base != workspace.Base || lane.Workspace.LogicalCWD != workspace.LogicalCWD {
		return result, fault(api.CodeIntegrity, "loop workspace changed from its retained binding")
	}
	var measured struct {
		Observation api.ProcessObservation
		Generation  api.Generation
	}
	if err := storedProjection(ctx, s.db, "launch_observation", lane.LaunchID, &measured); err != nil {
		return result, err
	}
	a, b := measured.Observation, end.Observation
	a.ObservedAt, b.ObservedAt = "", ""
	if !sameValue(a, b) {
		return result, fault(api.CodeContainmentUnknown, "loop end differs from outside observation")
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, s.db, "grants", lane.GrantSetID, &grants); err != nil {
		return result, err
	}
	if grants.PolicyGeneration != policy.Generation || grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return result, fault(api.CodeForbidden, "loop grants changed")
	}
	if !sameValue(grants, previous.Recovery.Handoff.Spec.Grants) && !s.narrowedLaunchGrants(previous.Recovery.Handoff.Spec.Grants, grants) {
		return result, fault(api.CodeForbidden, "loop grants widened beyond the previous binding")
	}
	eligible := false
	for _, profile := range grants.Profiles {
		if profile.ID == lane.ProfileGrantID && profile.Driver == lane.Session.Driver && future(profile.ExpiresAt, s.deps.Clock.Now()) &&
			!slices.Contains(policy.ProfileExclusions, profile.ProfileID) && (!profile.Paid || lane.BudgetRemaining.SpendMicros > 0) {
			eligible = true
		}
	}
	if !eligible || lane.Model == "" || lane.Effort == "" {
		return result, fault(api.CodeForbidden, "loop retained model or profile is no longer eligible")
	}
	meta, _, err := objectRow(ctx, s.db, setting.IdleMessage.ID)
	if err != nil {
		return result, err
	}
	if meta.Ref != *setting.IdleMessage || meta.Ref.Class != "task" || meta.ACL.Config != scope.Config || meta.ACL.LifeID != "" && meta.ACL.LifeID != lane.LifeID && meta.ACL.LifeID != settingEvent.RequestedBy.LifeID {
		return result, fault(api.CodeForbidden, "loop idle input lost its exact authorized bytes")
	}
	configurator := settingEvent.RequestedBy
	if !loopTaskVisible(configurator, meta.ACL) {
		return result, fault(api.CodeForbidden, "loop configurator cannot read its retained idle input")
	}
	r := api.LaunchReservation{Config: scope.Config, Mode: "turn", Level: lane.Level, Role: lane.Role, Driver: lane.Session.Driver, Authority: api.LaunchAuthority{Kind: "scheduler", ID: stamp.CapabilityID}, Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run + 1}, Generation: lane.Generation + 1, BaseGeneration: lane.Generation, CancellationEpoch: lane.CancellationEpoch, PolicyGeneration: policy.Generation, ParentLifeID: lane.ParentLifeID, RootLifeID: lane.RootLifeID, StarterChain: append([]api.ID{}, lane.StarterChain...), StarterEventSeq: lane.StarterEventSeq, RequestedBy: scope.Actor, PreviousLaunchID: lane.LaunchID}
	for _, id := range []*api.ID{&r.ID, &r.LaunchID, &r.SpecID, &r.GrantSetID, &r.OperationID, &r.RequestID} {
		*id, err = wire.NewID()
		if err != nil {
			return result, err
		}
	}
	oldGrants := grants
	grants.ID, grants.Generation, grants.SHA256 = r.GrantSetID, 1, ""
	grantRaw, err := canonicalValue(grants)
	if err != nil {
		return result, err
	}
	grants.SHA256 = api.Digest(hash(grantRaw))
	turnID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	effectID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	loop := api.LoopTurnCause{Schema: "laneboss.loop-turn.v2", Scheduler: stamp, Selector: pick, ConfiguredBy: settingEvent.RequestedBy, Setting: setting, End: end, GrantGeneration: grants.Generation, PreviousSession: lane.Session, PreviousHome: previous.Recovery.Home, BudgetRemaining: lane.BudgetRemaining, DueAt: api.Timestamp(due.UTC().Format(time.RFC3339Nano)), ReservedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)), ReservationID: r.ID, OperationID: r.OperationID, RequestID: r.RequestID, LaunchID: r.LaunchID, GrantSetID: r.GrantSetID, LogicalTurnID: turnID, PreviousLogicalTurnID: lane.LogicalTurnID, PlanEffectID: effectID}
	raw, err := canonicalValue(loop)
	if err != nil {
		return result, err
	}
	r.Loop, r.RequestSHA256 = &loop, api.Digest(hash(raw))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	objectID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	actor := api.Actor{Kind: "service", ID: s.storeID}
	r.OriginalRequest, err = s.retain(ctx, tx, api.Scope{Config: scope.Config, Actor: actor}, api.ObjectWrite{ObjectKey: objectID, Class: "manifest", Bytes: raw, SHA256: r.RequestSHA256, Origin: "service", ACL: api.ObjectACL{Config: scope.Config, Owner: actor, LifeID: lane.LifeID, Audience: "owner", Generation: 1}}, r.OperationID, loop.ReservedAt)
	if err != nil {
		return result, err
	}
	if err := api.ValidateLaunchReservation(r); err != nil {
		return result, err
	}
	plan := api.LaunchPlanRecord{Reservation: r, Generation: 1, Phase: "reserved"}
	for _, item := range []struct {
		kind  string
		id    api.ID
		value any
	}{{"launch_plan", r.ID, plan}, {"launch_operation", r.OperationID, launchOwner{Request: api.LaunchReservationRequest{Loop: &pick}, ReservationID: r.ID, Actor: scope.Actor}}, {"launch_authority", r.ID, launchAuthority{Ceiling: oldGrants}}, {"grants", grants.ID, grants}, {"loop_end", loopKey(scope.Config, pick), r.ID}} {
		if err := put(ctx, tx, item.kind, item.id, 1, item.value); err != nil {
			return result, err
		}
	}
	intentID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	cause := api.InternalIntent{ID: intentID, Kind: api.InternalLaunchPlan, Config: r.Config, Actor: actor, RequestedBy: scope.Actor, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: effectID, Target: r.Target, LogicalTurnID: turnID, CancellationEpoch: r.CancellationEpoch}
	if err := insertLaunchEffect(ctx, tx, api.Effect{ID: effectID, OperationID: r.OperationID, Context: &cause, PlanLaunch: &api.LaunchPlanEffect{ReservationID: r.ID}}); err != nil {
		return result, err
	}
	eventID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	event := api.Event{Schema: api.SchemaVersion, ID: eventID, Config: r.Config, Kind: "loop.reserved", Actor: scope.Actor, RequestedBy: scope.Actor, RequestID: r.RequestID, OperationID: r.OperationID, LifeID: r.Target.LifeID, Run: r.Target.Run, LogicalTurnID: turnID, ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID, StarterChain: r.StarterChain, StarterEventSeq: r.StarterEventSeq, Origin: "service", Payload: raw}
	seq, err := appendPrivateEvent(ctx, tx, event, loop.ReservedAt)
	if err != nil {
		return result, err
	}
	operation := api.Operation{ID: r.OperationID, Status: "pending", LifeID: r.Target.LifeID, Run: r.Target.Run, FirstSeq: seq, LastSeq: seq}
	opRaw, err := json.Marshal(operation)
	if err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO operations VALUES(?,?,?)", string(r.OperationID), principal(scope), opRaw); err != nil {
		return result, err
	}
	receipt := loopReceipt{Scheduler: stamp, Receipt: api.MutationReceipt{Config: r.Config, Actor: scope.Actor,
		Key:              api.RequestKey{Method: "loop.reserved", IdempotencyKey: r.ID, RequestSHA256: r.RequestSHA256},
		PolicyGeneration: r.PolicyGeneration, Operation: operation, Reply: &api.RPCReply{Result: opRaw},
		RawRequest: raw, FirstSeq: seq, LastSeq: seq, RecordedAt: loop.ReservedAt}}
	if err := put(ctx, tx, "loop_receipt", r.ID, 1, receipt); err != nil {
		return result, err
	}
	if err := api.CheckSchedulerScope(ctx, scope, s.deps.Clock.Now()); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return r, nil
}
