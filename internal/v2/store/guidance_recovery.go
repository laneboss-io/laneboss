package store

import (
	"context"
	"encoding/json"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// The installed outbox invokes this bounded inventory pass. It only finishes
// expired claims unavailable; it never schedules another evaluator or provider.
func (s *Service) RecoverGuidance(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='guidance' AND json_extract(data,'$.Status')='pending' ORDER BY json_extract(data,'$.Deadline'),id LIMIT 200")
	if err != nil {
		return err
	}
	claims := []api.GuidanceReservation{}
	for rows.Next() {
		var data []byte
		var claim api.GuidanceReservation
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(data, &claim); err != nil {
			rows.Close()
			return err
		}
		claims = append(claims, claim)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, claim := range claims {
		deadline, err := time.Parse(time.RFC3339Nano, string(claim.Deadline))
		if err != nil {
			return err
		}
		if s.deps.Clock.Now().Before(deadline) {
			continue
		}
		id, err := wire.NewID()
		if err != nil {
			return err
		}
		result := api.Guidance{ID: id, Target: claim.Target, LogicalTurnID: claim.LogicalTurnID, Task: claim.Task, PolicyGeneration: claim.PolicyGeneration, CandidateSnapshotID: claim.CandidateSnapshotID, ReservationID: claim.ID, AsOf: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)), Items: append([]api.GuidanceItem{}, claim.BindingItems...), JudgmentIDs: []api.ID{}, Status: "unavailable", Notice: "The original guidance owner expired before a measured completion; binding context is retained."}
		selection := api.GuidanceSelection{ReservationID: claim.ID, ClaimID: claim.ClaimID, AttemptID: claim.OwnerAttemptID, ExpectedGeneration: 1, Result: result}
		payload, err := json.Marshal(result)
		if err != nil {
			return err
		}
		eventID, err := wire.NewID()
		if err != nil {
			return err
		}
		intentID, err := wire.NewID()
		if err != nil {
			return err
		}
		actor := api.Actor{Kind: "service", ID: s.storeID}
		cause := api.InternalIntent{ID: intentID, Kind: api.InternalGuidanceRecover, Config: s.deps.Config, Actor: actor, RequestedBy: claim.RequestedBy, CauseOperationID: claim.OwnerOperationID, CauseRequestID: claim.OwnerRequestID, Target: claim.Target, LogicalTurnID: claim.LogicalTurnID, CancellationEpoch: claim.CancellationEpoch}
		event := api.Event{Schema: api.SchemaVersion, ID: eventID, Config: s.deps.Config, Kind: "guidance.selected", Actor: actor, RequestedBy: claim.RequestedBy, LifeID: claim.Target.LifeID, Run: claim.Target.Run, Origin: "service", Payload: payload, StarterChain: []api.ID{}}
		_, err = s.transactInternal(ctx, api.Transaction{Scope: api.Scope{Config: s.deps.Config, Actor: actor}, Internal: &cause, Writes: api.StateWrites{Guidance: []api.GuidanceSelection{selection}}, Events: []api.Event{event}, Compare: []api.Compare{{Kind: api.CompareGuidance, ID: claim.ID, Generation: 1}}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: claim.Target.LifeID, Epoch: claim.CancellationEpoch}}}})
		if err != nil {
			return err
		}
	}
	return nil
}
