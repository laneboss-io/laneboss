package store

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// This adapter is installed from the service scope, never from an RPC-supplied
// source. Each method reopens SQL rows or the administrator's protected journal.
type collectionReads struct {
	store   *Service
	scope   api.Scope
	pass    *collectionPass
	runtime *runtimeMeasurements
}

func (s *Service) CleanupReadbacks(scope api.Scope) api.CleanupReadbacks {
	return collectionReads{store: s, scope: scope, pass: &collectionPass{}}
}

func (r collectionReads) BeginCleanupVerification(ctx context.Context, job api.CleanupJob) (context.Context, func(), error) {
	if r.runtime != nil {
		r.runtime.mu.Lock()
		valid := !r.runtime.closed && r.runtime.store == r.store && r.runtime.intent == job.Intent.ID && r.runtime.claim == job.Claim.ClaimID
		r.runtime.mu.Unlock()
		if !valid {
			return nil, nil, fault(api.CodeConflict, "cleanup runtime operation belongs to another job or has ended")
		}
		// Only CompleteCleanup supplies this private shared cache, and its
		// top-level defer closes it after verification and the final writer CAS.
		return context.WithValue(ctx, runtimeMeasurementsKey{}, r.runtime), func() {}, nil
	}
	operation, _, finish := r.store.runtimeOperation(ctx, job)
	return operation, finish, nil
}

func (r collectionReads) CheckCleanup(ctx context.Context, job api.CleanupJob, inventory api.CleanupInventory) error {
	s := r.store
	s.mu.RLock()
	defer s.mu.RUnlock()
	saved, err := r.current(ctx, job)
	if err != nil {
		return err
	}
	if saved.Inventory == nil || !sameValue(*saved.Inventory, inventory) {
		return fault(api.CodeForbidden, "cleanup verification selected a partial or foreign inventory")
	}
	return s.checkCollectionGraph(ctx, job, saved)
}
func (r collectionReads) ReadCleanupInventory(ctx context.Context, job api.CleanupJob, id api.ID) (api.CleanupInventory, error) {
	s := r.store
	s.mu.RLock()
	defer s.mu.RUnlock()
	saved, err := r.current(ctx, job)
	if err != nil {
		return api.CleanupInventory{}, err
	}
	if saved.Inventory == nil || saved.Inventory.ID != id {
		return api.CleanupInventory{}, fault(api.CodeForbidden, "cleanup inventory selector changed")
	}
	inventory := *saved.Inventory
	inventory.Objects = append([]api.CleanupObject(nil), inventory.Objects...)
	return s.readInventory(ctx, s.db, job, inventory)
}
func (r collectionReads) ReadCleanupReceipt(ctx context.Context, job api.CleanupJob, id api.ID) (api.CleanupReceipt, error) {
	s := r.store
	s.mu.RLock()
	defer s.mu.RUnlock()
	saved, err := r.current(ctx, job)
	if err != nil {
		return api.CleanupReceipt{}, err
	}
	if saved.Receipt == nil || saved.Receipt.ID != id {
		return api.CleanupReceipt{}, fault(api.CodeForbidden, "cleanup receipt selector changed")
	}
	receipt := *saved.Receipt
	receipt.Objects = append([]api.ObjectDisposition(nil), receipt.Objects...)
	return s.readCollectionReceipt(ctx, s.db, job, receipt)
}
func (r collectionReads) ReadCleanupObjectResult(ctx context.Context, job api.CleanupJob, id api.ID) (api.ObjectDisposition, error) {
	s := r.store
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, err := r.current(ctx, job); err != nil {
		return api.ObjectDisposition{}, err
	}
	var result api.ObjectDisposition
	err := storedProjection(ctx, s.db, "collection_object", cleanupObjectID(job.Intent.ID, string(id)), &result)
	return result, err
}
func (r collectionReads) ReadCleanupObject(ctx context.Context, job api.CleanupJob, object api.CleanupObject) (api.ObjectReadback, error) {
	s := r.store
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := r.current(ctx, job)
	if err != nil {
		return api.ObjectReadback{}, err
	}
	actual, found := r.pass.objects[object.Ref.ID]
	if !found || actual != object {
		return api.ObjectReadback{}, fault(api.CodeForbidden, "cleanup read selected an object outside the protected inventory")
	}
	return s.cleanupRead(ctx, s.db, object)
}
func (r collectionReads) ReadWorkspaceRemoval(ctx context.Context, job api.CleanupJob) (api.WorkspaceRemoval, error) {
	s := r.store
	if s.deps.CleanupNative == nil {
		return api.WorkspaceRemoval{}, api.NotImplemented("lb-v2-admin", "protected unforced workspace and branch removal journal")
	}
	s.mu.RLock()
	_, err := r.current(ctx, job)
	s.mu.RUnlock()
	if err != nil {
		return api.WorkspaceRemoval{}, err
	}
	return s.deps.CleanupNative.ReadWorkspaceRemoval(ctx, job)
}
func (r collectionReads) ReadCleanupWorkspace(ctx context.Context, job api.CleanupJob) (api.WorkspaceReadback, error) {
	s := r.store
	if s.deps.CleanupNative == nil {
		return api.WorkspaceReadback{}, api.NotImplemented("lb-v2-admin", "independent current workspace and branch namespace read")
	}
	s.mu.RLock()
	_, err := r.current(ctx, job)
	s.mu.RUnlock()
	if err != nil {
		return api.WorkspaceReadback{}, err
	}
	return s.deps.CleanupNative.ReadCleanupWorkspace(ctx, job)
}

func cleanupEvent(job api.CleanupJob, inventory api.CleanupInventory, receipt api.CleanupReceipt) (api.Event, api.EffectOutcome, error) {
	i, c := job.Intent, job.Intent.Cause
	removed, retained := []api.ID{}, []api.ID{}
	for _, object := range receipt.Objects {
		if object.Action == "remove" {
			removed = append(removed, object.ObjectID)
		} else {
			retained = append(retained, object.ObjectID)
		}
	}
	body, err := json.Marshal(api.CleanEvent{ArchiveReceipt: i.Archive, Quiescence: i.Release.Quiescence, RemovedObjectIDs: removed, RetainedObjectIDs: retained,
		UnownedRetained: api.CleanupUnownedRetained(inventory, receipt.Objects)})
	if err != nil {
		return api.Event{}, api.EffectOutcome{}, err
	}
	id, err := wire.NewID()
	if err != nil {
		return api.Event{}, api.EffectOutcome{}, err
	}
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: c.Config, Kind: "lane.cleaned", Actor: c.Actor, RequestedBy: c.RequestedBy,
		OperationID: c.CauseOperationID, RequestID: c.CauseRequestID, LifeID: c.Target.LifeID, Run: c.Target.Run, Origin: "service", StarterChain: []api.ID{}, Payload: body}
	outcome := api.EffectOutcome{EffectID: c.EffectID, ClaimID: job.Claim.ClaimID, ExpectedGeneration: job.Claim.Record.Generation, Status: "succeeded", Output: &receipt.Manifest}
	return event, outcome, nil
}

func journalUnowned(life api.ID, total api.UnownedRetained) {
	data, err := json.Marshal(struct {
		Event   string `json:"event"`
		Life    api.ID `json:"life"`
		Objects int    `json:"objects"`
		Bytes   int64  `json:"bytes"`
	}{"cleanup_unowned_retained", life, total.Objects, total.Bytes})
	if err == nil {
		_, _ = os.Stderr.Write(append(data, '\n'))
	}
}

func (s *Service) CompleteCleanup(ctx context.Context, scope api.Scope, job api.CleanupJob, proposed api.VerifiedCleanup) (commit api.Commit, resultErr error) {
	ctx, runtime, finishRuntime := s.runtimeOperation(ctx, job)
	defer finishRuntime()
	s.mu.RLock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		s.mu.RUnlock()
		return commit, err
	}
	var saved collectionRecord
	err := storedProjection(ctx, s.db, "collection", job.Intent.Cause.EffectID, &saved)
	if err != nil {
		s.mu.RUnlock()
		return commit, err
	}
	if saved.Commit != nil {
		current, err := effectRow(ctx, s.db, job.Intent.Cause.EffectID)
		s.mu.RUnlock()
		if err != nil {
			return commit, err
		}
		if saved.Receipt == nil || !sameValue(job.Intent, saved.Intent) || !sameValue(proposed.Receipt(), *saved.Receipt) || current.ClaimID != job.Claim.ClaimID || current.ClaimantID != scope.Actor.ID || current.Outcome == nil || current.Outcome.ExpectedGeneration != job.Claim.Record.Generation {
			return commit, fault(api.CodeConflict, "cleanup replay differs from its retained original completion")
		}
		commit = *saved.Commit
		commit.Replayed = true
		return commit, nil
	}
	s.mu.RUnlock()
	if saved.Inventory == nil || saved.Receipt == nil || !sameValue(proposed.Receipt(), *saved.Receipt) {
		return commit, fault(api.CodeIntegrity, "cleanup completion lacks its retained exact receipt")
	}
	// The service repeats all installed reads. A worker's serialized receipt or
	// a capability produced by another source does not replace this measurement.
	readbacks := collectionReads{store: s, scope: scope, pass: &collectionPass{}, runtime: runtime}
	verified, err := api.VerifyCleanup(ctx, readbacks, job, *saved.Inventory, *saved.Receipt, s.deps.Clock)
	if err != nil {
		return commit, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.collectionJob(ctx, s.db, scope, job)
	if err != nil {
		return commit, err
	}
	if r.Inventory == nil || r.Receipt == nil || !sameValue(*r.Inventory, *saved.Inventory) || !sameValue(*r.Receipt, *saved.Receipt) {
		return commit, fault(api.CodeConflict, "cleanup inventory or receipt changed during independent verification")
	}
	if err := s.checkCollectionGraph(ctx, job, r); err != nil {
		return commit, err
	}
	lane, err := s.cleanClaim(ctx, s.db, scope, job.Claim)
	if err != nil {
		return commit, err
	}
	next := lane
	next.Generation++
	next.Cleaned = true
	event, outcome, err := cleanupEvent(job, *r.Inventory, *r.Receipt)
	if err != nil {
		return commit, err
	}
	event.RootLifeID, event.ParentLifeID, event.StarterEventSeq = lane.RootLifeID, lane.ParentLifeID, lane.StarterEventSeq
	event.StarterChain = append([]api.ID{}, lane.StarterChain...)
	now := s.deps.Clock.Now()
	if err := api.ValidateCleanupCompletion(job, *r.Inventory, proposed, next, event, outcome, now); err != nil {
		return commit, err
	}
	if err := api.ValidateCleanupCompletion(job, *r.Inventory, verified, next, event, outcome, now); err != nil {
		return commit, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return commit, err
	}
	defer finish(tx, &resultErr)
	evidence, err := collectionJSON(verified.Evidence())
	if err != nil {
		return commit, err
	}
	r.Evidence, err = s.collectionBytes(ctx, tx, job, evidence)
	if err != nil {
		return commit, err
	}
	seq, err := appendPrivateEvent(ctx, tx, event, api.Timestamp(now.UTC().Format(time.RFC3339Nano)))
	if err != nil {
		return commit, err
	}
	next.LastSeq = seq
	if err := put(ctx, tx, "lane", next.LifeID, next.Generation, next); err != nil {
		return commit, err
	}
	commit, err = s.finishOwnedEffect(ctx, tx, scope, job.Claim, outcome, seq, nil)
	if err != nil {
		return commit, err
	}
	r.Commit = &commit
	if err := s.saveCollection(ctx, tx, r); err != nil {
		return commit, err
	}
	if err := tx.Commit(); err != nil {
		return commit, err
	}
	// Journal only the committed completion, never verification failures or replays.
	journalUnowned(lane.LifeID, api.CleanupUnownedRetained(*r.Inventory, r.Receipt.Objects))
	s.notifyChanged()
	return commit, nil
}
