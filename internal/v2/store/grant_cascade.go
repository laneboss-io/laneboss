package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type grantCascadeKey struct{}
type grantCascadeRequest struct {
	Store   *Service
	Request api.GrantRevokeRequest
}

// Every public read/mutation checks the current writer head, including a
// previously pinned read view. Revocation blocks authority at its atomic grant
// commit; the Stop outbox's later transport invalidation is physical cleanup.
func (s *Service) grantRevocationFence(ctx context.Context, db queryer, id api.ID) error {
	var revoked bool
	if err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM projections WHERE kind='grants' AND id=? AND json_extract(data,'$.revoked')=1)", string(id)).Scan(&revoked); err != nil {
		return err
	}
	if revoked {
		return fault(api.CodeUnauthenticated, "launch grant authority was revoked")
	}
	return nil
}

// This private writer capability derives the complete cascade under the same
// SQLite transaction as its intent. Public callers supply no affected lives,
// process handles, service event labels or replacement grant contents.
func (s *Service) RevokeGrants(ctx context.Context, scope api.Scope, request api.GrantRevokeRequest, guards []api.TransactionGuard) (api.Commit, error) {
	if err := manifest.RevokeInput(request); err != nil {
		return api.Commit{}, err
	}
	if scope.Request.Method != "grants.revoke" || scope.Frame == nil || scope.Actor.Kind != "human" && scope.Actor.Kind != "lane" {
		return api.Commit{}, fault(api.CodeForbidden, "grant revocation requires its authenticated original request")
	}
	var body api.GrantRevokeRequest
	if err := wire.Decode(scope.Request.Params, &body); err != nil || !sameValue(body, request) {
		return api.Commit{}, fault(api.CodeForbidden, "grant revocation differs from its original request body")
	}
	ctx = context.WithValue(ctx, grantCascadeKey{}, grantCascadeRequest{s, request})
	return s.Transact(ctx, api.Transaction{Scope: scope, RawRequest: scope.Frame.Bytes(), Guards: guards})
}

func (s *Service) isGrantCascade(ctx context.Context, input api.Transaction) bool {
	v, ok := ctx.Value(grantCascadeKey{}).(grantCascadeRequest)
	return ok && v.Store == s && input.Internal == nil && input.Scope.Request.Method == "grants.revoke"
}

func projectionValues[T any](ctx context.Context, db readDatabase, kind string) ([]T, error) {
	rows, err := db.QueryContext(ctx, "SELECT data FROM projections WHERE kind=? ORDER BY id", kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []T
	for rows.Next() {
		var raw []byte
		var value T
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := decodeStored(raw, &value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (s *Service) buildGrantCascade(ctx context.Context, tx *sql.Tx, input api.Transaction) (api.Transaction, error) {
	v := ctx.Value(grantCascadeKey{}).(grantCascadeRequest)
	request, scope := v.Request, input.Scope
	var target api.GrantSet
	if err := storedProjection(ctx, tx, "grants", request.GrantSetID, &target); err != nil {
		return input, err
	}
	if target.Generation != request.ExpectedGeneration || target.Revoked {
		return input, fault(api.CodeConflict, "revocation grant generation changed or is already revoked")
	}
	if err := s.launchInput(ctx, tx, scope, request.Reason); err != nil {
		return input, err
	}
	lanes, err := projectionValues[api.Lane](ctx, tx, "lane")
	if err != nil {
		return input, err
	}
	if scope.Actor.Kind == "lane" {
		var controller api.Lane
		if err := storedProjection(ctx, tx, "lane", scope.Actor.LifeID, &controller); err != nil {
			return input, err
		}
		var authority api.GrantSet
		if err := storedProjection(ctx, tx, "grants", controller.GrantSetID, &authority); err != nil {
			return input, err
		}
		if controller.Cleaned || controller.LaunchID != scope.LaunchID || controller.Level != scope.Actor.Level || controller.Role != scope.Actor.Role ||
			controller.PolicyGeneration != scope.PolicyGeneration || authority.Revoked {
			return input, fault(api.CodeForbidden, "grant revocation controller is no longer the current authority")
		}
		var targetLane *api.Lane
		for index := range lanes {
			if lanes[index].LifeID == target.LifeID && lanes[index].GrantSetID == target.ID {
				targetLane = &lanes[index]
				break
			}
		}
		if targetLane == nil {
			if target.ParentLifeID != scope.Actor.LifeID {
				return input, fault(api.CodeNotFound, "grant set is outside the caller's authentic starter subtree")
			}
			if controller.State != "running" || !future(authority.ExpiresAt, s.deps.Clock.Now()) {
				return input, fault(api.CodeForbidden, "grant revocation controller is no longer the current running authority")
			}
		} else if targetLane.State != "running" {
			if scope.Actor.LifeID != target.LifeID {
				if !slices.Contains(targetLane.StarterChain, scope.Actor.LifeID) {
					return input, fault(api.CodeNotFound, "grant set is outside the caller's authentic starter subtree")
				}
				allowAndLog("grant_collection_owner")
			}
		} else {
			if controller.State != "running" || !future(authority.ExpiresAt, s.deps.Clock.Now()) {
				return input, fault(api.CodeForbidden, "grant revocation controller is no longer the current running authority")
			}
			if scope.Actor.LifeID == target.LifeID || !slices.Contains(targetLane.StarterChain, scope.Actor.LifeID) {
				return input, fault(api.CodeNotFound, "grant set is outside the caller's authentic starter subtree")
			}
		}
	} else {
		proof := false
		for _, guard := range input.Guards {
			proof = proof || guard.Proof != nil
		}
		if !proof {
			return input, fault(api.CodeForbidden, "human grant revocation requires its exact atomic proof")
		}
	}
	sets, err := projectionValues[api.GrantSet](ctx, tx, "grants")
	if err != nil {
		return input, err
	}
	// Root template derivation has no parent life edge. Its retained ceiling is
	// the authoritative dependency; member IDs were deliberately re-keyed.
	plans, err := projectionValues[api.LaunchPlanRecord](ctx, tx, "launch_plan")
	if err != nil {
		return input, err
	}
	affected, lives := map[api.ID]bool{target.ID: true}, map[api.ID]bool{target.LifeID: true}
	for changed := true; changed; {
		changed = false
		for _, plan := range plans {
			var authority launchAuthority
			if err := storedProjection(ctx, tx, "launch_authority", plan.Reservation.ID, &authority); err != nil {
				return input, err
			}
			if affected[authority.Ceiling.ID] && !affected[plan.Reservation.GrantSetID] {
				affected[plan.Reservation.GrantSetID], lives[plan.Reservation.Target.LifeID], changed = true, true, true
			}
		}
		for _, set := range sets {
			if lives[set.ParentLifeID] && !affected[set.ID] {
				affected[set.ID], lives[set.LifeID], changed = true, true, true
			}
		}
	}
	if err := s.grantCascadeCollectionPrerequisites(ctx, tx, affected, lanes, sets); err != nil {
		return input, err
	}
	operation, err := wire.NewID()
	if err != nil {
		return input, err
	}
	appendEvent := func(lane api.Lane, kind api.EventKind, value any) error {
		id, err := wire.NewID()
		if err != nil {
			return err
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		input.Events = append(input.Events, api.Event{Schema: api.SchemaVersion, ID: id, Config: scope.Config, Kind: kind,
			Actor: scope.Actor, RequestedBy: scope.Actor, OperationID: operation, RequestID: scope.Request.RequestID,
			LifeID: lane.LifeID, Run: lane.Run, RootLifeID: lane.RootLifeID, ParentLifeID: lane.ParentLifeID,
			StarterChain: lane.StarterChain, StarterEventSeq: lane.StarterEventSeq, Origin: "service", Payload: raw})
		return nil
	}
	for _, set := range sets {
		if !affected[set.ID] || set.Revoked {
			continue
		}
		if uint64(set.Generation) >= manifest.MaxInteger {
			return input, fault(api.CodeIntegrity, "grant generation exhausted")
		}
		input.Compare = append(input.Compare, api.Compare{Kind: api.CompareGrants, ID: set.ID, Generation: set.Generation})
		set.Generation++
		set.Revoked = true
		set.SHA256 = ""
		set.SHA256, err = manifest.HashValue(set)
		if err != nil {
			return input, err
		}
		input.Writes.Grants = append(input.Writes.Grants, set)
		lane := api.Lane{LifeID: set.LifeID, RootLifeID: set.LifeID, StarterChain: []api.ID{}}
		for _, candidate := range lanes {
			if candidate.LifeID == set.LifeID {
				lane = candidate
			}
		}
		if err := appendEvent(lane, "grants.revoked", api.GrantEvent{GrantSet: set, Reason: &request.Reason}); err != nil {
			return input, err
		}
	}
	continuations, err := projectionValues[api.ContinuationIntent](ctx, tx, "continuation")
	if err != nil {
		return input, err
	}
	for _, lane := range lanes {
		if !lives[lane.LifeID] || lane.Cleaned {
			continue
		}
		if uint64(lane.Generation) >= manifest.MaxInteger || uint64(lane.CancellationEpoch) >= manifest.MaxInteger {
			return input, fault(api.CodeIntegrity, "revocation life generation exhausted")
		}
		var observed struct {
			Observation api.ProcessObservation
			Generation  api.Generation
		}
		if err := storedProjection(ctx, tx, "launch_observation", lane.LaunchID, &observed); err != nil {
			return input, fault(api.CodePrerequisite, "revocation needs the retained native process before collection")
		}
		binding, err := s.launchBinding(ctx, tx, lane.LaunchID)
		if err != nil {
			return input, err
		}
		handle := observed.Observation.Handle
		if binding.Recovery == nil || handle.Target != (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) || handle.ContainmentID != binding.Record.ContainmentID || handle.Generation != binding.Record.ProcessGeneration {
			return input, fault(api.CodeIntegrity, "revocation process differs from its retained launch")
		}
		next := lane
		next.Generation++
		next.CancellationEpoch++
		next.State = "stopping"
		input.Compare = append(input.Compare, api.Compare{Kind: api.CompareLane, ID: lane.LifeID, Generation: lane.Generation})
		input.Writes.Lanes = append(input.Writes.Lanes, next)
		if err := appendEvent(lane, "lane.stopping", api.StateEvent{From: lane.State, To: next.State, Generation: next.Generation, Reason: &request.Reason}); err != nil {
			return input, err
		}
		for _, pending := range continuations {
			if pending.Target.LifeID != lane.LifeID || pending.Status == "cancelled" || pending.Status == "completed" {
				continue
			}
			pending.Generation++
			pending.Status = "cancelled"
			input.Writes.Continuations = append(input.Writes.Continuations, pending)
			if err := appendEvent(lane, "watchdog.cancelled", api.WatchdogEvent{Reason: "grants revoked", BudgetRemaining: lane.BudgetRemaining}); err != nil {
				return input, err
			}
		}
		id, err := wire.NewID()
		if err != nil {
			return input, err
		}
		causeID, err := wire.NewID()
		if err != nil {
			return input, err
		}
		cause := api.InternalIntent{ID: causeID, Kind: api.InternalLifecycleEffect, Config: scope.Config,
			Actor: api.Actor{Kind: "service", ID: "lifecycle"}, RequestedBy: scope.Actor, CauseOperationID: operation,
			CauseRequestID: scope.Request.RequestID, EffectID: id, Target: handle.Target, LogicalTurnID: lane.LogicalTurnID, CancellationEpoch: next.CancellationEpoch}
		input.Effects = append(input.Effects, api.Effect{ID: id, OperationID: operation, Context: &cause, Stop: &handle})
	}
	// Unbound reservations are fenced by the revoked ceiling. Their existing
	// cleanup owner must measure any helper allocations; do not report success
	// while that separate job may still own resources.
	for _, plan := range plans {
		if !affected[plan.Reservation.GrantSetID] || plan.Phase == "opened" || plan.Phase == "bound" {
			continue
		}
		if plan.Phase != "failed" {
			return input, fault(api.CodePrerequisite, "revocation awaits the retained unbound launch cleanup owner")
		}
		cleanups, err := projectionValues[storedPlanCleanup](ctx, tx, "plan_cleanup")
		if err != nil {
			return input, err
		}
		for _, cleanup := range cleanups {
			if cleanup.Request.ReservationID == plan.Reservation.ID && cleanup.State != "completed" {
				return input, fault(api.CodePrerequisite, "revocation awaits the retained unbound launch cleanup owner")
			}
		}
	}
	status := "succeeded"
	if len(input.Effects) != 0 {
		status = "pending"
	}
	raw, err := json.Marshal(api.Operation{ID: operation, Status: status})
	if err != nil {
		return input, err
	}
	input.Reply = &api.RPCReply{Result: raw}
	return input, nil
}
