package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

var _ api.CredentialSpendGuard = (*Service)(nil)
var _ api.SpendReconciler = (*Service)(nil)
var _ api.SpendStatusReader = (*Service)(nil)

type spendProfile struct{ CredentialID api.ID }
type retainedSpendReading struct {
	Reading api.SpendReading
	Balance api.SpendBalance
}

func spendEstimate(b api.SpendBalance) int64 {
	return min(b.SeedMicros-b.SpentMicros, b.AnchorMicros-(b.SpentMicros-b.AnchorSpentMicros))
}

func readSpendPool(ctx context.Context, db queryer, id api.ID) (api.SpendBalance, error) {
	var b api.SpendBalance
	if err := storedProjection(ctx, db, "spend_pool", id, &b); err != nil {
		return b, err
	}
	if b.CredentialID != id || b.Generation == 0 || b.Generation > 1<<53-1 || b.SeedMicros < 0 || b.SeedMicros > 1<<53-1 || b.SpentMicros < 0 || b.SpentMicros > 1<<53-1 ||
		b.AnchorSpentMicros < 0 || b.AnchorSpentMicros > b.SpentMicros || b.AnchorMicros < -(1<<53-1) || b.AnchorMicros > b.SeedMicros || b.ReadingMicros < 0 || b.ReadingMicros > 1<<53-1 || b.FloorMicros < 5000000 || b.FloorMicros > 1<<53-1 || b.RemainingMicros != spendEstimate(b) {
		return b, fault(api.CodeIntegrity, "credential spend projection is invalid")
	}
	return b, nil
}

func spendForSlot(ctx context.Context, db queryer, slot api.CredentialSlot) (api.SpendBalance, error) {
	var profile spendProfile
	if !wire.ValidID(string(slot.ProfileID)) {
		return api.SpendBalance{}, fault(api.CodePrerequisite, "API credential has no enrolled balance reading")
	}
	if err := storedProjection(ctx, db, "spend_profile", slot.ProfileID, &profile); err != nil {
		if absent(err) {
			return api.SpendBalance{}, fault(api.CodePrerequisite, "API credential has no enrolled balance reading")
		}
		return api.SpendBalance{}, err
	}
	return readSpendPool(ctx, db, profile.CredentialID)
}

func checkSpendBalance(b api.SpendBalance) error {
	if b.NeedsReading || b.AccountingError != nil {
		return fault(api.CodePrerequisite, "API credential requires an operator tool reading after release or incomplete usage")
	}
	if b.RemainingMicros <= b.FloorMicros {
		return fault(api.CodeBudget, "API credential remaining estimate is at or under its configured floor")
	}
	return nil
}

func (s *Service) checkCredentialSpend(ctx context.Context, db queryer, slot api.CredentialSlot) (api.SpendBalance, error) {
	if slot.Mode != "claude-api-key" {
		return api.SpendBalance{}, nil
	}
	b, err := spendForSlot(ctx, db, slot)
	if err != nil {
		return b, err
	}
	return b, checkSpendBalance(b)
}

func (s *Service) CheckCredentialSpend(ctx context.Context, slot api.CredentialSlot) (api.SpendBalance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.SpendBalance{}, err
	}
	return s.checkCredentialSpend(ctx, s.db, slot)
}

func (s *Service) ReconcileSpend(ctx context.Context, reading api.SpendReading) (result api.SpendBalance, resultErr error) {
	config, err := admin.CheckSpendReading(ctx, reading)
	if err != nil {
		return result, err
	}
	if config != s.deps.Config {
		return result, fault(api.CodeForbidden, "spend reading belongs to another configuration")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	result, err = s.reconcileSpend(ctx, tx, reading)
	if err != nil {
		return result, err
	}
	if _, err := admin.CheckSpendReading(ctx, reading); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return result, nil
}

func (s *Service) reconcileSpend(ctx context.Context, tx *sql.Tx, reading api.SpendReading) (api.SpendBalance, error) {
	amount, err := admin.PoolReading(reading)
	if err != nil {
		return api.SpendBalance{}, err
	}
	var prior retainedSpendReading
	if err := storedProjection(ctx, tx, "spend_reading", reading.ID, &prior); err == nil {
		if !sameValue(prior.Reading, reading) {
			return api.SpendBalance{}, fault(api.CodeIdempotencyConflict, "balance reading replay changed its exact tool stdout")
		}
		return prior.Balance, nil
	} else if !absent(err) {
		return api.SpendBalance{}, err
	}
	observed, err := time.Parse(time.RFC3339Nano, string(reading.ObservedAt))
	if err != nil || observed.After(s.deps.Clock.Now().Add(time.Second)) || s.deps.Clock.Now().Sub(observed) > time.Minute {
		return api.SpendBalance{}, fault(api.CodePrerequisite, "operator balance reading is stale or future dated")
	}
	b, err := readSpendPool(ctx, tx, reading.CredentialID)
	if absent(err) {
		b = api.SpendBalance{CredentialID: reading.CredentialID, SeedMicros: amount, AnchorMicros: amount}
	}
	if err != nil && !absent(err) {
		return b, err
	}
	if b.Generation >= 1<<53-1 {
		return b, fault(api.CodeIntegrity, "balance reconciliation generation exhausted")
	}
	if b.ObservedAt != "" {
		last, _ := time.Parse(time.RFC3339Nano, string(b.ObservedAt))
		if !observed.After(last) {
			return b, fault(api.CodeConflict, "operator balance reading did not advance")
		}
	}
	if b.AwaitingSince != "" {
		release, _ := time.Parse(time.RFC3339Nano, string(b.AwaitingSince))
		if !observed.After(release) {
			return b, fault(api.CodePrerequisite, "release reconciliation needs a later operator tool reading")
		}
	}
	for _, profile := range reading.ProfileIDs {
		var mapping spendProfile
		if err := storedProjection(ctx, tx, "spend_profile", profile, &mapping); err == nil {
			if mapping.CredentialID != reading.CredentialID {
				return b, fault(api.CodeForbidden, "profile already belongs to a different credential balance")
			}
		} else if absent(err) {
			if err := put(ctx, tx, "spend_profile", profile, 1, spendProfile{reading.CredentialID}); err != nil {
				return b, err
			}
		} else {
			return b, err
		}
	}
	// Retain the initial seed forever. The latest outside reading may replace
	// a prior reading, but never seed-minus-spend. Later costs reduce this anchor.
	b.AnchorMicros = min(b.SeedMicros-b.SpentMicros, amount)
	b.AnchorSpentMicros = b.SpentMicros
	b.ReadingMicros, b.FloorMicros, b.ObservedAt = amount, reading.FloorMicros, reading.ObservedAt
	b.NeedsReading, b.AwaitingSince, b.AccountingError = false, "", nil
	b.Generation++
	b.RemainingMicros = spendEstimate(b)
	if err := put(ctx, tx, "spend_pool", b.CredentialID, b.Generation, b); err != nil {
		return b, err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	journal := spendJournal(b, "spend.reconciled")
	seq, err := s.appendSpendEvent(ctx, tx, api.Lane{}, "spend.reconciled", journal, reading.ID, reading.ID, now)
	if err != nil {
		return b, err
	}
	operation := api.Operation{ID: reading.ID, Status: "succeeded", FirstSeq: seq, LastSeq: seq}
	if err := s.retainSpendOperation(ctx, tx, operation, reading); err != nil {
		return b, err
	}
	if err := put(ctx, tx, "spend_reading", reading.ID, 1, retainedSpendReading{reading, b}); err != nil {
		return b, err
	}
	if b.RemainingMicros <= b.FloorMicros {
		if err := s.stopSpendPool(ctx, tx, b, now); err != nil {
			return b, err
		}
	}
	return b, nil
}

func spendJournal(b api.SpendBalance, kind string) api.SpendJournal {
	return api.SpendJournal{EstimateMicros: b.RemainingMicros, ReadingMicros: b.ReadingMicros, FloorMicros: b.FloorMicros,
		Line: fmt.Sprintf("%s estimate_micros=%d reading_micros=%d floor_micros=%d", kind, b.RemainingMicros, b.ReadingMicros, b.FloorMicros)}
}

func (s *Service) appendSpendEvent(ctx context.Context, tx *sql.Tx, lane api.Lane, kind api.EventKind, payload any, operation, request api.ID, now api.Timestamp) (api.Sequence, error) {
	id, err := wire.NewID()
	if err != nil {
		return 0, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	actor := api.Actor{Kind: "service", ID: "spend"}
	return appendPrivateEvent(ctx, tx, api.Event{Schema: api.SchemaVersion, ID: id, Config: s.deps.Config, Kind: kind, Actor: actor, RequestedBy: actor,
		OperationID: operation, RequestID: request, LifeID: lane.LifeID, Run: lane.Run, RootLifeID: lane.RootLifeID, ParentLifeID: lane.ParentLifeID,
		StarterChain: append([]api.ID{}, lane.StarterChain...), StarterEventSeq: lane.StarterEventSeq, Origin: "service", Payload: raw}, now)
}

func (s *Service) retainSpendOperation(ctx context.Context, tx *sql.Tx, operation api.Operation, input any) error {
	raw, err := json.Marshal(operation)
	if err != nil {
		return err
	}
	actor := api.Actor{Kind: "service", ID: "spend"}
	if _, err := tx.ExecContext(ctx, "INSERT INTO operations VALUES(?,?,?)", string(operation.ID), principal(api.Scope{Actor: actor}), raw); err != nil {
		return err
	}
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	return put(ctx, tx, "internal_commit", operation.ID, 1, internalCommit{Digest: hash(data), Commit: api.Commit{Operation: operation, FirstSeq: operation.FirstSeq, LastSeq: operation.LastSeq}, Actor: actor})
}

func (s *Service) LaneSpend(ctx context.Context, scope api.Scope, target api.LifeRef) (*api.SpendBalance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return nil, err
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", target.LifeID, &lane); err != nil {
		return nil, err
	}
	visible, err := s.visibleLife(ctx, scope, target.LifeID)
	if err != nil {
		return nil, err
	}
	if !visible {
		return nil, fault(api.CodeNotFound, "lane is outside the caller's scope")
	}
	var data []byte
	err = s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='launch_plan' AND json_extract(data,'$.reservation.launch_id')=?", string(lane.LaunchID)).Scan(&data)
	if err != nil {
		return nil, err
	}
	var plan api.LaunchPlanRecord
	if err := decodeStored(data, &plan); err != nil {
		return nil, err
	}
	if plan.Plan == nil || plan.Plan.Runner.Slot.Mode != "claude-api-key" {
		return nil, nil
	}
	b, err := spendForSlot(ctx, s.db, plan.Plan.Runner.Slot)
	if err != nil {
		return nil, err
	}
	return &b, nil
}
