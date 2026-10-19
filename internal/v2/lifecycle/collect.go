package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// OwnedCollector is the native data-owner boundary. It resolves WorkspaceID
// through its protected registry, verifies current ownership and a clean tree,
// and removes that workspace/branch without force under its ownership lock.
// It must journal by the original effect/operation, reconcile partial outcomes
// on retry, and preserve every RetainedObjectID. A caller supplies no host path.
type OwnedCollector interface {
	CollectOwned(context.Context, api.Scope, api.EffectLease, OwnedCleanRequest) (api.CleanEvent, error)
}

type OwnedCleanRequest struct {
	Request           api.CleanRequest
	Archive           api.ArchiveReceipt
	WorkspaceID       api.ID
	RetainedObjectIDs []api.ID
}

func (s *Service) lifecycleClaim(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.InternalIntent, error) {
	if err := s.ready(); err != nil {
		return api.InternalIntent{}, err
	}
	if err := contextReady(ctx); err != nil {
		return api.InternalIntent{}, err
	}
	if scope.Actor.Kind != "service" || !validID(scope.Actor.ID) || scope.Config == "" || scope.Request.Method != "" || scope.Request.Proof != nil ||
		!validID(lease.Record.Effect.ID) || !validID(lease.ClaimID) {
		return api.InternalIntent{}, problem(api.CodeForbidden, "lifecycle effect requires its installed service claim", "Claim and reconcile the original committed effect.")
	}
	current, err := s.deps.Store.Effect(ctx, scope, lease.Record.Effect.ID)
	if err != nil {
		return api.InternalIntent{}, failure(err)
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
	if effectRecord(current) != nil || !api.EffectLeaseClaimed(lease) || !reflect.DeepEqual(current, lease.Record) || current.State != api.EffectClaimed || current.Outcome != nil ||
		current.ClaimID != lease.ClaimID || current.ClaimantID != scope.Actor.ID || current.ClaimExpiresAt != lease.ExpiresAt ||
		parseErr != nil || !s.deps.Clock.Now().Before(expires) || current.Effect.Context == nil {
		return api.InternalIntent{}, problem(api.CodeConflict, "lifecycle effect claim is stale", "Reconcile the same effect under its current claim.")
	}
	cause := *current.Effect.Context
	if cause.Kind != api.InternalLifecycleEffect || cause.Config != scope.Config || cause.Actor != scope.Actor || cause.EffectID != current.Effect.ID ||
		cause.CauseOperationID != current.Effect.OperationID || !validTarget(cause.Target) || !validID(cause.CauseOperationID) || !validID(cause.ID) {
		return api.InternalIntent{}, integrity("lifecycle effect lost its original cause")
	}
	return cause, nil
}

// CollectClean runs only as the service's original Clean outbox stage. A
// pending LaneClean operation alone never sets Cleaned or emits lane.cleaned.
func (s *Service) CollectClean(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.CleanEvent, error) {
	cause, err := s.lifecycleClaim(ctx, scope, lease)
	if err != nil {
		return api.CleanEvent{}, err
	}
	effect := lease.Record.Effect
	if effect.Clean == nil || effect.Clean.Target != cause.Target ||
		!reflect.DeepEqual(effect, api.Effect{ID: effect.ID, OperationID: effect.OperationID, Context: effect.Context, Clean: effect.Clean}) {
		return api.CleanEvent{}, integrity("collector claim does not select the original Clean effect")
	}
	request := *effect.Clean
	unlock, err := s.lockLife(ctx, cause.Target.LifeID)
	if err != nil {
		return api.CleanEvent{}, err
	}
	defer unlock()
	lane, err := s.lane(ctx, scope, cause.Target, true)
	if err != nil {
		return api.CleanEvent{}, err
	}
	if lane.CancellationEpoch != cause.CancellationEpoch || lane.State != "merged" && lane.State != "abandoned" {
		return api.CleanEvent{}, problem(api.CodeConflict, "collector life fence changed", "Retain the archive and reconcile the original cleanup operation.")
	}
	if lane.Cleaned {
		return s.cleanedResult(ctx, scope, lane, cause, request)
	}
	if lane.Generation != request.ExpectedGeneration || lane.Generation >= api.Generation(maxInteger) || !validID(lane.Workspace.ID) {
		return api.CleanEvent{}, problem(api.CodeConflict, "collector generation changed", "Retain the workspace and reconcile the original Clean effect.")
	}
	observation, facts, err := s.observe(ctx, scope, lane, request.Target)
	if err != nil {
		return api.CleanEvent{}, err
	}
	if err := requireQuiescence(observation); err != nil {
		return api.CleanEvent{}, err
	}
	if facts.end == nil || facts.endSeq == 0 || facts.end.Reason == "service_lost" || requireQuiescence(facts.end.Observation) != nil {
		return api.CleanEvent{}, problem(api.CodeContainmentUnknown, "collector has no committed quiescent run end", "Preserve the workspace until containment and capture are reconciled.")
	}
	archive, err := s.archiveReceipt(ctx, scope, lane, request, facts.endSeq)
	if err != nil {
		return api.CleanEvent{}, err
	}
	retained, err := s.cleanRetainedObjects(ctx, scope, lane, archive)
	if err != nil {
		return api.CleanEvent{}, err
	}
	collector := s.deps.Collector
	if absent(collector) {
		collector, _ = s.deps.Worker.(OwnedCollector)
	}
	if absent(collector) {
		return api.CleanEvent{}, api.NotImplemented("lb-v2-grants", "owned workspace and branch collector")
	}
	if _, err := s.lifecycleClaim(ctx, scope, lease); err != nil {
		return api.CleanEvent{}, err
	}
	result, err := collector.CollectOwned(ctx, scope, lease, OwnedCleanRequest{Request: request, Archive: archive,
		WorkspaceID: lane.Workspace.ID, RetainedObjectIDs: append([]api.ID{}, retained...)})
	if err != nil {
		return api.CleanEvent{}, failure(err)
	}
	if err := validateCleanResult(lane, archive, facts.handle, retained, result); err != nil {
		return api.CleanEvent{}, err
	}
	if _, err := s.lifecycleClaim(ctx, scope, lease); err != nil {
		return api.CleanEvent{}, err
	}
	event, err := s.event(scope, lane, "lane.cleaned", result, scope.Actor)
	if err != nil {
		return api.CleanEvent{}, err
	}
	event.OperationID, event.RequestID, event.RequestedBy = cause.CauseOperationID, cause.CauseRequestID, cause.RequestedBy
	event.ObservedAt = result.Quiescence.ObservedAt
	next := lane
	next.Cleaned, next.Generation = true, lane.Generation+1
	_, err = s.deps.Store.Transact(ctx, api.Transaction{Scope: scope, Internal: &cause,
		Compare: []api.Compare{{Kind: api.CompareLane, ID: lane.LifeID, Generation: lane.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: lane.CancellationEpoch}}},
		Writes:  api.StateWrites{Lanes: []api.Lane{next}}, Events: []api.Event{event}})
	if err != nil {
		return api.CleanEvent{}, failure(err)
	}
	actual, err := s.lane(ctx, scope, request.Target, true)
	if err != nil {
		return api.CleanEvent{}, err
	}
	if !actual.Cleaned || actual.Generation != next.Generation || actual.State != lane.State || actual.CancellationEpoch != lane.CancellationEpoch {
		return api.CleanEvent{}, integrity("collector completion was not retained exactly")
	}
	s.NotifyCommit()
	return s.cleanedResult(ctx, scope, actual, cause, request)
}

func validateCleanResult(lane api.Lane, archive api.ArchiveReceipt, handle api.ProcessHandle, retained []api.ID, result api.CleanEvent) error {
	if result.ArchiveReceipt != archive || result.Quiescence.Handle != handle || validateObservation(handle, result.Quiescence) != nil || requireQuiescence(result.Quiescence) != nil ||
		len(result.RemovedObjectIDs) != 1 || result.RemovedObjectIDs[0] != lane.Workspace.ID || result.RetainedObjectIDs == nil {
		return integrity("collector result does not prove the owned workspace removal")
	}
	seen := map[api.ID]bool{}
	for _, id := range result.RetainedObjectIDs {
		if !validID(id) || seen[id] || id == lane.Workspace.ID {
			return integrity("collector result has invalid retained objects")
		}
		seen[id] = true
	}
	for _, id := range retained {
		if !seen[id] {
			return integrity("collector omitted a required retained record")
		}
	}
	return nil
}

func (s *Service) cleanedResult(ctx context.Context, scope api.Scope, lane api.Lane, cause api.InternalIntent, request api.CleanRequest) (api.CleanEvent, error) {
	var result api.CleanEvent
	found := false
	err := s.walkEvents(ctx, scope, lane, request.Target, func(event api.Event) error {
		if event.Kind == "lane.cleaned" && event.OperationID == cause.CauseOperationID && event.RequestID == cause.CauseRequestID {
			if api.DecodeObject(event.Payload, &result) != nil || result.ArchiveReceipt.ID != request.ArchiveReceiptID || result.ArchiveReceipt.LifeID != lane.LifeID {
				return integrity("cleaned projection has no original collector receipt")
			}
			found = true
		}
		return nil
	})
	if err != nil {
		return api.CleanEvent{}, err
	}
	if !found {
		return api.CleanEvent{}, integrity("cleaned projection has no original collector event")
	}
	facts, err := s.facts(ctx, scope, lane, request.Target)
	if err != nil {
		return api.CleanEvent{}, err
	}
	if facts.end == nil || facts.endSeq == 0 || facts.end.Reason == "service_lost" || requireQuiescence(facts.end.Observation) != nil {
		return api.CleanEvent{}, problem(api.CodeContainmentUnknown, "clean replay has no committed quiescent end", "Preserve retained records and reconcile the original cleanup.")
	}
	archive, err := s.archiveReceipt(ctx, scope, lane, request, facts.endSeq)
	if err != nil {
		return api.CleanEvent{}, err
	}
	retained, err := s.cleanRetainedObjects(ctx, scope, lane, archive)
	if err != nil {
		return api.CleanEvent{}, err
	}
	if validateCleanResult(lane, archive, facts.handle, retained, result) != nil {
		return api.CleanEvent{}, integrity("retained collector event has invalid removal evidence")
	}
	return result, nil
}

func (s *Service) cleanRetainedObjects(ctx context.Context, scope api.Scope, lane api.Lane, archive api.ArchiveReceipt) ([]api.ID, error) {
	ids := map[api.ID]bool{lane.Task.ID: true, archive.Manifest.ID: true}
	var visit func(any)
	visit = func(value any) {
		switch object := value.(type) {
		case map[string]any:
			if id, ok := object["id"].(string); ok {
				if digest, ok := object["sha256"].(string); ok && validID(api.ID(id)) && validDigest(api.Digest(digest)) && object["bytes"] != nil && object["class"] != nil {
					ids[api.ID(id)] = true
				}
			}
			for _, child := range object {
				visit(child)
			}
		case []any:
			for _, child := range object {
				visit(child)
			}
		}
	}
	for run := api.RunNumber(1); run <= lane.Run; run++ {
		if err := s.walkEvents(ctx, scope, lane, api.LifeRef{LifeID: lane.LifeID, Run: run}, func(event api.Event) error {
			var payload any
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				return integrity("cannot inventory retained lifecycle records")
			}
			visit(payload)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if !validID(lane.Task.ID) || ids[lane.Workspace.ID] {
		return nil, integrity("workspace removal overlaps retained lifecycle objects")
	}
	result := make([]api.ID, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}
