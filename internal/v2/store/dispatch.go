package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// These are service-owned deployment controls, not RPCs or new StateWrites.
// The existing projection/history transaction keeps the barrier and its receipt
// durable without changing the schema of an already-open draft.4 store.
type dispatchState struct {
	Config string
	Epoch  api.Generation
	Active *api.FreezeReceipt `json:",omitempty"`
}

type dispatchFreeze struct {
	Request api.FreezeRequest
	Receipt api.FreezeReceipt
	Thawed  bool
}

func dispatchController(scope api.Scope, config string) error {
	if scope.Config != config || scope.Actor.Kind != "service" || scope.Connection != nil || scope.Request.Method != "" || !wire.ValidID(string(scope.Actor.ID)) {
		return fault(api.CodeForbidden, "dispatch control requires the bound internal deployment service")
	}
	return nil
}

func readDispatch(ctx context.Context, db queryer, config string) (dispatchState, error) {
	state := dispatchState{Config: config}
	err := storedProjection(ctx, db, "dispatch_state", api.ID(config), &state)
	var typed *api.Error
	if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
		return dispatchState{Config: config}, nil
	}
	if err != nil {
		return state, err
	}
	if state.Config != config || state.Epoch == 0 || state.Epoch >= 1<<53 {
		return state, fault(api.CodeIntegrity, "retained dispatch state is invalid")
	}
	if state.Active != nil && (state.Active.Config != config || state.Active.DispatchEpoch != state.Epoch || !wire.ValidID(string(state.Active.ID)) || state.Active.InstallationGeneration == 0) {
		return state, fault(api.CodeIntegrity, "active dispatch freeze binding is invalid")
	}
	return state, nil
}

func (s *Service) dispatchAllowed(ctx context.Context, db queryer) error {
	state, err := readDispatch(ctx, db, s.deps.Config)
	if err != nil {
		return err
	}
	if state.Active != nil {
		return &api.Error{Code: api.CodeUnavailable, Message: "deployment freeze has stopped dispatch", OperationID: state.Active.OperationID,
			Instead: "Retain the current operation and reconcile the durable deployment freeze before dispatch resumes."}
	}
	return nil
}

func (s *Service) ActiveDispatchFreeze(ctx context.Context) (*api.FreezeReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	state, err := readDispatch(ctx, s.db, s.deps.Config)
	return state.Active, err
}

func (s *Service) internalDispatchAllowed(ctx context.Context, input api.Transaction) error {
	state, err := readDispatch(ctx, s.db, s.deps.Config)
	if err != nil || state.Active == nil {
		return err
	}
	if input.Internal.Kind == api.InternalCaptureAppend || input.Internal.Kind == api.InternalEffectComplete || input.Internal.Kind == api.InternalHelperStop || input.Internal.Kind == api.InternalProfileCancel {
		return nil // Existing capture/claimed outcomes must still be collected.
	}
	if (input.Internal.Kind == api.InternalUpgradeApply || input.Internal.Kind == api.InternalMigrationApply) && input.Internal.CauseOperationID == state.Active.OperationID {
		return nil // Only the owning deployment may persist its durable phases.
	}
	return s.dispatchAllowed(ctx, s.db)
}

func (s *Service) FreezeDispatch(ctx context.Context, scope api.Scope, request api.FreezeRequest) (receipt api.FreezeReceipt, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return receipt, err
	}
	if err := dispatchController(scope, s.deps.Config); err != nil {
		return receipt, err
	}
	if !wire.ValidID(string(request.OperationID)) || request.ExpectedInstallationGeneration == 0 {
		return receipt, wire.Invalid("freeze requires a durable deployment operation and installation generation")
	}
	var prior dispatchFreeze
	err := storedProjection(ctx, s.db, "dispatch_freeze", request.OperationID, &prior)
	var typed *api.Error
	if err == nil {
		if prior.Request != request {
			return receipt, fault(api.CodeIdempotencyConflict, "deployment freeze operation has different content")
		}
		if prior.Thawed {
			return receipt, fault(api.CodeConflict, "deployment freeze was already thawed")
		}
		state, err := readDispatch(ctx, s.db, s.deps.Config)
		if err != nil {
			return receipt, err
		}
		if state.Active == nil || *state.Active != prior.Receipt {
			return receipt, fault(api.CodeIntegrity, "freeze receipt disagrees with active dispatch state")
		}
		return prior.Receipt, nil
	}
	if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
		return receipt, err
	}
	state, err := readDispatch(ctx, s.db, s.deps.Config)
	if err != nil {
		return receipt, err
	}
	if state.Active != nil || state.Epoch >= 1<<53-1 {
		return receipt, fault(api.CodeConflict, "another deployment owns the dispatch freeze")
	}
	// The in-process coordinator must have persisted its actual plan before it
	// asks for a barrier. A caller-provided operation ID alone is not authority.
	var encoded []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='upgrade' AND json_extract(data,'$.OperationID')=?", string(request.OperationID)).Scan(&encoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return receipt, fault(api.CodeForbidden, "freeze has no retained deployment plan")
		}
		return receipt, err
	}
	var plan api.DeploymentPlan
	if err := decodeStored(encoded, &plan); err != nil {
		return receipt, err
	}
	if plan.Config != scope.Config || plan.InstallationGeneration != request.ExpectedInstallationGeneration || (plan.Phase != "freezing" && plan.Phase != "draining") {
		return receipt, fault(api.CodeConflict, "freeze differs from the retained deployment phase or generation")
	}
	var operation api.Operation
	var operationData []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=?", string(request.OperationID)).Scan(&operationData); err != nil {
		return receipt, fault(api.CodeForbidden, "freeze operation is not committed")
	}
	if err := wire.Decode(operationData, &operation); err != nil || operation.ID != request.OperationID || (operation.Status != "pending" && operation.Status != "running") {
		return receipt, fault(api.CodeConflict, "freeze operation is not active")
	}
	metadata, _, err := objectRow(ctx, s.db, request.Reason.ID)
	if err != nil {
		return receipt, err
	}
	if metadata.Ref != request.Reason {
		return receipt, fault(api.CodeConflict, "freeze reason differs from committed bytes")
	}
	id, err := wire.NewID()
	if err != nil {
		return receipt, err
	}
	state.Epoch++
	receipt = api.FreezeReceipt{ID: id, Config: s.deps.Config, OperationID: request.OperationID,
		InstallationGeneration: request.ExpectedInstallationGeneration, DispatchEpoch: state.Epoch,
		FrozenAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))}
	state.Active = &receipt
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "dispatch_freeze", request.OperationID, 1, dispatchFreeze{Request: request, Receipt: receipt}); err != nil {
		return receipt, err
	}
	if err := put(ctx, tx, "dispatch_state", api.ID(s.deps.Config), state.Epoch, state); err != nil {
		return receipt, err
	}
	if err := tx.Commit(); err != nil {
		return receipt, err
	}
	s.notifyChanged()
	return receipt, nil
}

func (s *Service) ThawDispatch(ctx context.Context, scope api.Scope, receipt api.FreezeReceipt) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if err := dispatchController(scope, s.deps.Config); err != nil {
		return err
	}
	var saved dispatchFreeze
	if err := storedProjection(ctx, s.db, "dispatch_freeze", receipt.OperationID, &saved); err != nil {
		return err
	}
	if receipt != saved.Receipt || receipt.Config != s.deps.Config {
		return fault(api.CodeForbidden, "thaw requires the exact retained freeze receipt")
	}
	state, err := readDispatch(ctx, s.db, s.deps.Config)
	if err != nil {
		return err
	}
	if saved.Thawed {
		if state.Active != nil || state.Epoch != receipt.DispatchEpoch+1 {
			return fault(api.CodeConflict, "a later deployment changed dispatch")
		}
		return nil
	}
	if state.Active == nil || *state.Active != receipt || state.Epoch >= 1<<53-1 {
		return fault(api.CodeConflict, "thaw does not own the current dispatch epoch")
	}
	state.Epoch++
	state.Active, saved.Thawed = nil, true
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "dispatch_freeze", receipt.OperationID, 2, saved); err != nil {
		return err
	}
	if err := put(ctx, tx, "dispatch_state", api.ID(s.deps.Config), state.Epoch, state); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.notifyChanged()
	return nil
}

// Unlike PendingEffects, this host-only inventory includes unexpired claims.
// Startup/drain must not mistake a claimed external action for an empty queue.
func (s *Service) DispatchEffects(ctx context.Context) ([]api.EffectRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM effect_states WHERE json_extract(data,'$.Outcome') IS NULL ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []api.EffectRecord{}
	for rows.Next() {
		var data []byte
		var record api.EffectRecord
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := decodeStored(data, &record); err != nil {
			return nil, err
		}
		if err := validateEffect(record.Effect); err != nil {
			return nil, err
		}
		if err := validateEffectState(record); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (s *Service) DispatchRequests(ctx context.Context) ([]api.ID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT operation_id FROM reservations UNION SELECT json_extract(data,'$.Request.Cause.cause_operation_id') FROM projections WHERE kind='plan_cleanup' AND json_extract(data,'$.State') IN ('pending','claimed') ORDER BY 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []api.ID{}
	for rows.Next() {
		var id api.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if !wire.ValidID(string(id)) {
			return nil, fault(api.CodeIntegrity, "reserved dispatch has invalid operation identity")
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func (s *Service) DispatchTargets(ctx context.Context) ([]api.LifeRef, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT kind,data FROM projections WHERE kind IN ('lane','launch','plan_cleanup') ORDER BY kind,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := make(map[api.LifeRef]bool)
	result := []api.LifeRef{}
	for rows.Next() {
		var kind string
		var data []byte
		if err := rows.Scan(&kind, &data); err != nil {
			return nil, err
		}
		var target api.LifeRef
		if kind == "lane" {
			var lane api.Lane
			if err := decodeStored(data, &lane); err != nil {
				return nil, err
			}
			target = api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}
		} else if kind == "plan_cleanup" {
			var saved storedPlanCleanup
			if err := decodeStored(data, &saved); err != nil {
				return nil, err
			}
			if err := s.cleanupState(saved, saved.Request.ID); err != nil {
				return nil, err
			}
			if saved.State == "completed" {
				continue
			}
			target = saved.Request.Cause.Target
		} else {
			var launch api.LaunchRecord
			if err := wire.Decode(data, &launch); err != nil {
				return nil, err
			}
			target = launch.Target
		}
		if !wire.ValidID(string(target.LifeID)) || target.Run == 0 {
			return nil, fault(api.CodeIntegrity, "dispatch target has invalid life or run")
		}
		if !seen[target] {
			seen[target] = true
			result = append(result, target)
		}
	}
	return result, rows.Err()
}

func (s *Service) verifyDispatch(ctx context.Context) error {
	state, err := readDispatch(ctx, s.db, s.deps.Config)
	if err != nil {
		return err
	}
	if state.Active == nil {
		return nil
	}
	var saved dispatchFreeze
	if err := storedProjection(ctx, s.db, "dispatch_freeze", state.Active.OperationID, &saved); err != nil {
		return err
	}
	if saved.Thawed || saved.Receipt != *state.Active || saved.Request.OperationID != state.Active.OperationID || saved.Request.ExpectedInstallationGeneration != state.Active.InstallationGeneration {
		return fault(api.CodeIntegrity, "dispatch barrier and retained freeze disagree")
	}
	return nil
}
