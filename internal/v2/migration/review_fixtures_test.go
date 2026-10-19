package migration

import (
	"context"
	"sort"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The in-memory fixture inventories every state, including claimed and completed.
func (m *memStore) MigrationEffects(_ context.Context, scope api.Scope, operation api.ID) ([]api.EffectRecord, error) {
	records := []api.EffectRecord{}
	for _, record := range m.effects {
		if record.Effect.OperationID == operation {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Effect.ID < records[j].Effect.ID })
	return records, nil
}

// This measures the fixture's own outbox/lifecycle model, never RollbackRequest.
func (m *memStore) MigrationQuiescence(_ context.Context, scope api.Scope) (api.QuiescenceReceipt, error) {
	now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	result := api.QuiescenceReceipt{ID: "fixture-current-quiescence", ObservedAt: now,
		Freeze: api.FreezeReceipt{ID: "fixture-current-freeze", Config: scope.Config, OperationID: "fixture-freeze-operation",
			InstallationGeneration: 1, DispatchEpoch: 1, FrozenAt: now},
		Observations: []api.ProcessObservation{}, PendingEffectIDs: []api.ID{}}
	for id, record := range m.effects {
		if record.Outcome == nil && (record.State == api.EffectPending || record.State == api.EffectClaimed) {
			result.PendingEffectIDs = append(result.PendingEffectIDs, id)
		}
	}
	active := map[api.ID]bool{}
	for _, event := range m.events {
		if event.Kind == "lane.started" || event.Kind == "lane.resumed" {
			active[event.LifeID] = true
		}
		if event.Kind == "lane.ended" {
			delete(active, event.LifeID)
		}
	}
	for id := range active {
		count := uint64(1)
		result.Observations = append(result.Observations, api.ProcessObservation{
			Handle: api.ProcessHandle{ID: id}, State: "running", Survivors: &count, ObservedAt: now})
	}
	return result, nil
}
