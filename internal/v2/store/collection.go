package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// The administrator alone resolves the protected workspace registry and Git
// journal. This private installed port supplies no path-based deletion route.
type CleanupNative interface {
	ResolveCleanupWorkspace(context.Context, api.LifeRef, api.ID) (api.CleanupWorkspace, error)
	ReadWorkspaceRemoval(context.Context, api.CleanupJob) (api.WorkspaceRemoval, error)
	ReadCleanupWorkspace(context.Context, api.CleanupJob) (api.WorkspaceReadback, error)
}

type collectionRecord struct {
	Intent         api.CleanupIntent
	Inventory      *api.CleanupInventory
	Graph          api.Digest
	Receipt        *api.CleanupReceipt
	Commit         *api.Commit
	Evidence       api.BlobRef
	RemovalClaim   *api.EffectLease
	RemovalJournal *api.WorkspaceRemoval
}

var _ api.CleanupObjectStore = (*Service)(nil)

func (s *Service) cleanClaim(ctx context.Context, db queryer, scope api.Scope, lease api.EffectLease) (api.Lane, error) {
	var lane api.Lane
	if err := s.dataScope(ctx, db, scope); err != nil {
		return lane, err
	}
	current, err := effectRow(ctx, db, lease.Record.Effect.ID)
	if err != nil {
		return lane, err
	}
	if !api.EffectLeaseClaimed(lease) || !sameValue(current, lease.Record) || current.Outcome != nil || current.ClaimID != lease.ClaimID || current.ClaimantID != scope.Actor.ID || current.ClaimExpiresAt != lease.ExpiresAt || !future(lease.ExpiresAt, s.deps.Clock.Now()) || current.Effect.Clean == nil || current.Effect.Context == nil {
		return lane, fault(api.CodeConflict, "cleanup requires its actual current original clean claim")
	}
	c, request := current.Effect.Context, current.Effect.Clean
	var requester api.Actor
	if err := storedProjection(ctx, db, "reservation_actor", c.CauseOperationID, &requester); err != nil {
		return lane, err
	}
	if c.Kind != api.InternalLifecycleEffect || c.Config != s.deps.Config || c.RequestedBy != requester || c.EffectID != current.Effect.ID || c.CauseOperationID != current.Effect.OperationID || request.Target != c.Target {
		return lane, fault(api.CodeForbidden, "cleanup claim differs from its retained original requester or cause")
	}
	if err := s.currentLifecycleRequester(ctx, db, requester); err != nil {
		return lane, err
	}
	var originalRaw []byte
	if err := db.QueryRowContext(ctx, "SELECT request FROM receipts WHERE json_extract(operation,'$.id')=?", string(c.CauseOperationID)).Scan(&originalRaw); err != nil {
		return lane, err
	}
	original, err := wire.DecodeRequest(originalRaw)
	if err != nil {
		return lane, err
	}
	var originalClean api.CleanRequest
	if original.Method != "lane.clean" || original.RequestID != c.CauseRequestID || api.DecodeObject(original.Params, &originalClean) != nil || originalClean != *request {
		return lane, fault(api.CodeForbidden, "cleanup claim changed its retained exact clean request")
	}
	if original.Proof != nil {
		var proof api.VerifiedHumanProof
		if err := storedProjection(ctx, db, "proof", original.Proof.ID, &proof); err != nil {
			return lane, err
		}
		if proof.ConsumedBy != c.CauseOperationID {
			return lane, fault(api.CodeForbidden, "cleanup proof belongs to another operation")
		}
		if _, err := s.proofCredential(ctx, db, proof); err != nil {
			return lane, err
		}
	}
	if err := storedProjection(ctx, db, "lane", c.Target.LifeID, &lane); err != nil {
		return lane, err
	}
	if lane.Run != c.Target.Run || lane.Generation != request.ExpectedGeneration || lane.CancellationEpoch != c.CancellationEpoch || lane.Cleaned || lane.State != "merged" && lane.State != "abandoned" {
		return lane, fault(api.CodeConflict, "cleanup life, terminal decision or cancellation fence changed")
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return lane, err
	}
	var generation api.Generation
	if err := storedProjection(ctx, db, "reservation_policy", c.CauseOperationID, &generation); err != nil {
		return lane, err
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, db, "grants", lane.GrantSetID, &grants); err != nil {
		return lane, err
	}
	if policy.Generation != generation || grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return lane, fault(api.CodeForbidden, "cleanup policy or source grants changed")
	}
	return lane, ctx.Err()
}

func (s *Service) BeginCleanup(ctx context.Context, scope api.Scope, lease api.EffectLease) (job api.CleanupJob, resultErr error) {
	s.mu.RLock()
	lane, err := s.cleanClaim(ctx, s.db, scope, lease)
	if err != nil {
		s.mu.RUnlock()
		return job, err
	}
	var prior collectionRecord
	err = storedProjection(ctx, s.db, "collection", lease.Record.Effect.ID, &prior)
	s.mu.RUnlock()
	if err == nil {
		job = api.CleanupJob{Intent: prior.Intent, Claim: lease}
		return job, api.ValidateCleanupJob(job, s.deps.Clock.Now())
	}
	if !absent(err) {
		return job, err
	}
	if s.deps.CleanupNative == nil {
		return job, api.NotImplemented("lb-v2-admin", "protected cleanup workspace registry and removal readbacks")
	}
	workspace, err := s.deps.CleanupNative.ResolveCleanupWorkspace(ctx, lease.Record.Effect.Context.Target, lane.Workspace.ID)
	if err != nil {
		return job, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lane, err = s.cleanClaim(ctx, s.db, scope, lease)
	if err != nil {
		return job, err
	}
	if err := validateResolvedCleanupWorkspace(lane, workspace); err != nil {
		return job, err
	}
	err = storedProjection(ctx, s.db, "collection", lease.Record.Effect.ID, &prior)
	if err == nil {
		job = api.CleanupJob{Intent: prior.Intent, Claim: lease}
		return job, api.ValidateCleanupJob(job, s.deps.Clock.Now())
	}
	if !absent(err) {
		return job, err
	}
	request, cause := *lease.Record.Effect.Clean, *lease.Record.Effect.Context
	// Resolve the verified archive from this writer's actual committed job, not
	// an uploaded receipt or a same-shaped event selected by a worker.
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='archive_job' AND json_extract(data,'$.Input.receipt_id')=?", string(request.ArchiveReceiptID)).Scan(&raw); err != nil {
		return job, err
	}
	var archived archiveRecord
	if err := decodeStored(raw, &archived); err != nil {
		return job, err
	}
	if archived.Commit == nil || archived.Phase != "verified" || archived.Ack == nil || archived.Job.Intent.Request.Target != cause.Target {
		return job, fault(api.CodeIntegrity, "cleanup archive has no committed byte-exact verification")
	}
	result, err := s.verifyArchiveBytes(ctx, s.db, archived, archived.Ack.Submission.Result)
	if err != nil {
		return job, err
	}
	if result.Receipt.ID != request.ArchiveReceiptID {
		return job, fault(api.CodeIntegrity, "cleanup archive selector changed")
	}
	var release api.ReleaseReceipt
	var releaseRaw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT effect_states.data FROM effects JOIN effect_states USING(id) WHERE json_extract(effect_states.data,'$.Outcome.Release.quiescence.handle.target.life_id')=? AND json_extract(effect_states.data,'$.Outcome.Release.quiescence.handle.target.run')=? ORDER BY effects.seq DESC LIMIT 1", string(lane.LifeID), uint64(lane.Run)).Scan(&releaseRaw); err != nil {
		return job, err
	}
	var released api.EffectRecord
	if err := decodeStored(releaseRaw, &released); err != nil {
		return job, err
	}
	if released.Outcome == nil || released.State != api.EffectCompleted || released.Outcome.Status != "succeeded" || released.Outcome.Release == nil || measuredOutcome(released.Effect, *released.Outcome) != nil {
		return job, fault(api.CodeContainmentUnknown, "cleanup lacks the committed measured helper release")
	}
	release = *released.Outcome.Release
	binding, err := s.launchBinding(ctx, s.db, lane.LaunchID)
	if err != nil {
		return job, err
	}
	if release.LeaseID != binding.Record.UIDLeaseID || release.ContainmentID != binding.Record.ContainmentID || release.Quiescence.Handle.Generation != binding.Record.ProcessGeneration || workspace.ID != lane.Workspace.ID || workspace.Target != cause.Target {
		return job, fault(api.CodeIntegrity, "cleanup release or protected workspace differs from the original launch")
	}
	id, err := wire.NewID()
	if err != nil {
		return job, err
	}
	job = api.CleanupJob{Intent: api.CleanupIntent{ID: id, Cause: cause, ExpectedGeneration: request.ExpectedGeneration, Decision: lane.State, Archive: result.Receipt,
		ArchiveRequest: archived.Job.Intent.Request, Release: release, Workspace: workspace}, Claim: lease}
	if err := api.ValidateCleanupJob(job, s.deps.Clock.Now()); err != nil {
		return job, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return job, err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "collection", cause.EffectID, 1, collectionRecord{Intent: job.Intent}); err != nil {
		return job, err
	}
	if err := tx.Commit(); err != nil {
		return job, err
	}
	s.notifyChanged()
	return job, nil
}

// A native callback is a protected resolver, not authority to substitute a
// different life, branch or aliased directory after the writer's lock drops.
func validateResolvedCleanupWorkspace(lane api.Lane, w api.CleanupWorkspace) error {
	if w.ID != lane.Workspace.ID || w.Target != (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) ||
		w.Branch != lane.Workspace.Branch || w.Branch != "lane/"+string(lane.LifeID) ||
		!wire.ValidID(string(w.RootID)) || !wire.ValidID(string(w.RepositoryID)) || w.Generation == 0 || w.Generation > 1<<53-1 ||
		w.ID == w.RootID || w.ID == w.RepositoryID || w.RootID == w.RepositoryID ||
		w.RootIdentity == "" || w.DirectoryIdentity == "" || w.GitIdentity == "" ||
		w.RootIdentity == w.DirectoryIdentity || w.RootIdentity == w.GitIdentity || w.DirectoryIdentity == w.GitIdentity ||
		len(w.Head) != 40 && len(w.Head) != 64 {
		return fault(api.CodeIntegrity, "native cleanup workspace differs from its retained life or protected identities")
	}
	for _, c := range w.Head {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fault(api.CodeIntegrity, "native cleanup workspace has a malformed Git head")
		}
	}
	return nil
}

func (s *Service) collectionJob(ctx context.Context, db queryer, scope api.Scope, job api.CleanupJob) (collectionRecord, error) {
	var r collectionRecord
	if _, err := s.cleanClaim(ctx, db, scope, job.Claim); err != nil {
		return r, err
	}
	if err := api.ValidateCleanupJob(job, s.deps.Clock.Now()); err != nil {
		return r, err
	}
	if err := storedProjection(ctx, db, "collection", job.Intent.Cause.EffectID, &r); err != nil {
		return r, err
	}
	if !sameValue(r.Intent, job.Intent) || r.Commit != nil {
		return r, fault(api.CodeConflict, "cleanup lost its retained original intent")
	}
	return r, nil
}

func (s *Service) saveCollection(ctx context.Context, tx *sql.Tx, r collectionRecord) error {
	var generation api.Generation
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM projections WHERE kind='collection' AND id=?", string(r.Intent.Cause.EffectID)).Scan(&generation); err != nil {
		return err
	}
	return put(ctx, tx, "collection", r.Intent.Cause.EffectID, generation+1, r)
}

func (s *Service) collectionBytes(ctx context.Context, tx *sql.Tx, job api.CleanupJob, raw []byte) (api.BlobRef, error) {
	return s.archiveBytes(ctx, tx, archiveRecord{Job: archivejob.Job{Intent: archivejob.Intent{OperationID: job.Intent.Cause.CauseOperationID}}, Scope: api.Scope{Actor: job.Intent.Cause.RequestedBy}, Lane: api.Lane{LifeID: job.Intent.Cause.Target.LifeID}}, "manifest", raw)
}

func (s *Service) CleanupInventory(ctx context.Context, scope api.Scope, job api.CleanupJob) (inventory api.CleanupInventory, resultErr error) {
	ctx, _, finishRuntime := s.runtimeOperation(ctx, job)
	defer finishRuntime()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.collectionJob(ctx, s.db, scope, job)
	if err != nil {
		return inventory, err
	}
	if r.Inventory != nil {
		if err := s.checkCollectionGraph(ctx, job, r); err == nil {
			return s.readInventory(ctx, s.db, job, *r.Inventory)
		} else if !hasCode(err, api.CodeConflict) {
			return inventory, err
		}
		if started, err := s.collectionStarted(ctx, r); err != nil || started {
			if err != nil {
				return inventory, err
			}
			return inventory, fault(api.CodePrerequisite, "collection graph moved after object journals; preserve them and resolve the original cleanup")
		}
	}
	objects, graph, generation, err := s.collectionGraph(ctx, job, nil)
	if err != nil {
		return inventory, err
	}
	id, err := wire.NewID()
	if err != nil {
		return inventory, err
	}
	i, c := job.Intent, job.Intent.Cause
	inventory = api.CleanupInventory{ID: id, IntentID: i.ID, Config: c.Config, Target: c.Target, ExpectedGeneration: i.ExpectedGeneration, CancellationEpoch: c.CancellationEpoch, GraphGeneration: generation, Objects: objects}
	body, _, err := api.CleanupInventoryBytes(inventory)
	if err != nil {
		return inventory, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return inventory, err
	}
	defer finish(tx, &resultErr)
	inventory.Manifest, err = s.collectionBytes(ctx, tx, job, body)
	if err != nil {
		return inventory, err
	}
	if err := api.ValidateCleanupInventory(job, inventory, s.deps.Clock.Now()); err != nil {
		return inventory, err
	}
	r.Inventory, r.Graph = &inventory, graph
	if err := s.saveCollection(ctx, tx, r); err != nil {
		return inventory, err
	}
	if err := tx.Commit(); err != nil {
		return inventory, err
	}
	return inventory, nil
}

func (s *Service) collectionStarted(ctx context.Context, r collectionRecord) (bool, error) {
	if r.RemovalClaim != nil || r.RemovalJournal != nil || r.Receipt != nil {
		return true, nil
	}
	if r.Inventory == nil || len(r.Inventory.Objects) == 0 {
		return false, nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='collection_object' AND id=?", string(cleanupObjectID(r.Intent.ID, string(r.Inventory.Objects[0].Ref.ID)))).Scan(&count)
	return count != 0, err
}

func (s *Service) readInventory(ctx context.Context, db queryer, job api.CleanupJob, inventory api.CleanupInventory) (api.CleanupInventory, error) {
	meta, raw, err := objectRow(ctx, db, inventory.Manifest.ID)
	if err != nil {
		return api.CleanupInventory{}, err
	}
	expected, _, err := api.CleanupInventoryBytes(inventory)
	if err != nil || meta.Ref != inventory.Manifest || meta.SourceOperationID != job.Intent.Cause.CauseOperationID || string(raw) != string(expected) {
		return api.CleanupInventory{}, fault(api.CodeIntegrity, "cleanup inventory failed retained-byte readback")
	}
	return inventory, api.ValidateCleanupInventory(job, inventory, s.deps.Clock.Now())
}

func (s *Service) cleanupRead(ctx context.Context, db readDatabase, object api.CleanupObject) (api.ObjectReadback, error) {
	id, err := wire.NewID()
	if err != nil {
		return api.ObjectReadback{}, err
	}
	read := api.ObjectReadback{ID: id, ObjectID: object.Ref.ID, RootID: object.RootID, RootIdentity: object.RootIdentity, ObservedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))}
	if object.RootID != s.storeID {
		actual, err := s.measuredRuntime(ctx, db, object.Ref)
		if err != nil {
			return read, err
		}
		if object.Role != "runtime" || object.OwnerLifeID != "" || object.OwnershipGeneration != 0 || actual.object.Ref != object.Ref {
			return read, fault(api.CodeIntegrity, "cleanup runtime differs from its retained provenance")
		}
		read.State = actual.state
		if actual.state == "present" {
			// The protected inventory's identity names immutable provenance.
			// Native bytes/metadata were freshly checked for this operation.
			read.Identity, read.SHA256, read.Bytes = object.Identity, actual.object.Ref.SHA256, actual.object.Ref.Bytes
		}
		return read, nil
	}
	meta, _, err := objectRow(ctx, db, object.Ref.ID)
	if absent(err) {
		// An absent name is certain only with this writer's authenticated atomic
		// deletion journal. An arbitrary not-found is never removal evidence.
		var deleted collectionDeletion
		if err := storedProjection(ctx, db, "collection_delete", object.Ref.ID, &deleted); err != nil {
			return read, err
		}
		if !sameValue(deleted.Object, object) || deleted.Result.Action != "remove" {
			return read, fault(api.CodeIntegrity, "absent cleanup object lacks its original deletion journal")
		}
		read.State = "absent"
		return read, nil
	}
	if err != nil {
		return read, err
	}
	if meta.Ref != object.Ref || object.Identity != objectIdentity(meta) {
		return read, fault(api.CodeIntegrity, "cleanup object changed its protected content or identity")
	}
	read.State, read.Identity, read.SHA256, read.Bytes = "present", object.Identity, meta.Ref.SHA256, meta.Ref.Bytes
	return read, nil
}

// Same rule as api cleanupDisposition: no owning lane is unowned and preserved (item 36).
func cleanupAction(object api.CleanupObject, life api.ID) (string, string) {
	if object.Role == "unknown" {
		return "retain", "unknown"
	}
	if object.OwnerLifeID != life {
		return "retain", "unowned"
	}
	if object.References != 0 {
		return "retain", "referenced"
	}
	if object.Role != "transient" {
		return "retain", object.Role
	}
	if object.Ref.Class != "artifact" {
		return "retain", "history"
	}
	return "remove", "unreferenced"
}

type collectionDeletion struct {
	IntentID api.ID
	Object   api.CleanupObject
	Metadata string
	Outbound []api.BlobRef
	Result   api.ObjectDisposition
}

func (s *Service) CollectCleanupObjects(ctx context.Context, scope api.Scope, job api.CleanupJob, inventory api.CleanupInventory) (results []api.ObjectDisposition, resultErr error) {
	ctx, _, finishRuntime := s.runtimeOperation(ctx, job)
	defer finishRuntime()
	if s.deps.CleanupNative == nil {
		return nil, api.NotImplemented("lb-v2-admin", "known clean protected workspace before object collection")
	}
	workspace, err := s.deps.CleanupNative.ReadCleanupWorkspace(ctx, job)
	if err != nil {
		return nil, err
	}
	w := job.Intent.Workspace
	workspaceRemoved := workspace.WorktreeState == "absent" && workspace.BranchState == "absent"
	var removal *api.WorkspaceRemoval
	if workspaceRemoved {
		journal, err := s.deps.CleanupNative.ReadWorkspaceRemoval(ctx, job)
		if err != nil {
			return nil, err
		}
		if journal.Action != "remove_clean" {
			return nil, fault(api.CodeIntegrity, "absent workspace lacks its original clean unforced removal")
		}
		removal = &journal
	}
	observed, timeErr := time.Parse(time.RFC3339Nano, string(workspace.ObservedAt))
	archived, archiveErr := time.Parse(time.RFC3339Nano, string(job.Intent.Archive.VerifiedAt))
	if timeErr != nil || archiveErr != nil || observed.IsZero() || observed.Before(archived) || observed.After(s.deps.Clock.Now()) || !wire.ValidID(string(workspace.ID)) || workspace.WorkspaceID != w.ID || workspace.RootIdentity != w.RootIdentity || workspace.GitIdentity != w.GitIdentity || !workspaceRemoved && (workspace.DirectoryIdentity != w.DirectoryIdentity || workspace.Head != w.Head || workspace.WorktreeState != "present" || workspace.BranchState != "present" || workspace.Dirty == nil) {
		return nil, fault(api.CodeConflict, "dirty or unknown work must be retained before object collection")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.collectionJob(ctx, s.db, scope, job)
	if err != nil {
		return nil, err
	}
	if r.Inventory == nil || !sameValue(*r.Inventory, inventory) {
		return nil, fault(api.CodeForbidden, "collector cannot choose an object inventory")
	}
	if removal != nil {
		if err := s.validateRemovalClaim(job, r, *removal, &workspace); err != nil {
			return nil, err
		}
		r.RemovalJournal = removal
	}
	if err := s.checkCollectionGraph(ctx, job, r); err != nil {
		return nil, err
	}
	if _, err := s.readInventory(ctx, s.db, job, inventory); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer finish(tx, &resultErr)
	results = make([]api.ObjectDisposition, 0, len(inventory.Objects))
	for _, object := range inventory.Objects {
		key := cleanupObjectID(job.Intent.ID, string(object.Ref.ID))
		var previous api.ObjectDisposition
		err := storedProjection(ctx, tx, "collection_object", key, &previous)
		if err == nil {
			read, err := s.cleanupRead(ctx, tx, object)
			if err != nil {
				return nil, err
			}
			state := "present"
			if previous.Action == "remove" {
				state = "absent"
			}
			if read.State != state && !(object.Role == "runtime" && previous.Action == "retain" && (read.State == "present" || read.State == "absent")) {
				return nil, fault(api.CodeIntegrity, "cleanup journal differs from current object namespace")
			}
			results = append(results, previous)
			continue
		}
		if !absent(err) {
			return nil, err
		}
		if workspaceRemoved {
			return nil, fault(api.CodeIntegrity, "workspace removal preceded the retained object operation journal")
		}
		before, err := s.cleanupRead(ctx, tx, object)
		if err != nil {
			return nil, err
		}
		if before.State != "present" && !(object.Role == "runtime" && before.State == "absent") {
			return nil, fault(api.CodeIntegrity, "cleanup lacks the original present object observation")
		}
		action, reason := cleanupAction(object, job.Intent.Cause.Target.LifeID)
		result := api.ObjectDisposition{ObjectID: object.Ref.ID, Action: action, Reason: reason, Before: before}
		if action == "remove" {
			var encoded, raw []byte
			if err := tx.QueryRowContext(ctx, "SELECT metadata,data FROM objects WHERE id=?", string(object.Ref.ID)).Scan(&encoded, &raw); err != nil {
				return nil, err
			}
			journal := collectionDeletion{IntentID: job.Intent.ID, Object: object, Metadata: string(encoded), Outbound: blobEdges(raw), Result: result}
			if err := put(ctx, tx, "collection_delete", object.Ref.ID, 1, journal); err != nil {
				return nil, err
			}
			deleted, err := tx.ExecContext(ctx, "DELETE FROM objects WHERE id=? AND metadata=?", string(object.Ref.ID), encoded)
			if err != nil {
				return nil, err
			}
			n, err := deleted.RowsAffected()
			if err != nil || n != 1 {
				return nil, fault(api.CodeIntegrity, "cleanup deletion did not remove its original SQL object")
			}
		}
		after, err := s.cleanupRead(ctx, tx, object)
		if err != nil {
			return nil, err
		}
		result.After = after
		if action == "remove" {
			var journal collectionDeletion
			if err := storedProjection(ctx, tx, "collection_delete", object.Ref.ID, &journal); err != nil {
				return nil, err
			}
			journal.Result = result
			if err := put(ctx, tx, "collection_delete", object.Ref.ID, 2, journal); err != nil {
				return nil, err
			}
		}
		if err := put(ctx, tx, "collection_object", key, 1, result); err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	// Retain the actual removing authority before returning to the native
	// collector. Reclaim never replaces it after measured workspace absence.
	if !workspaceRemoved {
		claim := job.Claim
		r.RemovalClaim = &claim
	}
	if err := s.saveCollection(ctx, tx, r); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return results, nil
}

func (s *Service) RetainCleanupReceipt(ctx context.Context, scope api.Scope, job api.CleanupJob, receipt api.CleanupReceipt) (actual api.CleanupReceipt, resultErr error) {
	ctx, _, finishRuntime := s.runtimeOperation(ctx, job)
	defer finishRuntime()
	// Reopen the administrator's operation journal, never echo the worker's
	// proposed workspace result into a service-authenticated receipt.
	if s.deps.CleanupNative == nil {
		return actual, api.NotImplemented("lb-v2-admin", "unforced workspace removal journal")
	}
	workspace, err := s.deps.CleanupNative.ReadWorkspaceRemoval(ctx, job)
	if err != nil {
		return actual, err
	}
	if !sameValue(workspace, receipt.Workspace) {
		return actual, fault(api.CodeIntegrity, "cleanup receipt differs from the administrator removal journal")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.collectionJob(ctx, s.db, scope, job)
	if err != nil {
		return actual, err
	}
	if r.Inventory == nil {
		return actual, fault(api.CodeConflict, "cleanup has no protected complete inventory")
	}
	if err := s.validateRemovalClaim(job, r, workspace, nil); err != nil {
		return actual, err
	}
	r.RemovalJournal = &workspace
	if err := s.checkCollectionGraph(ctx, job, r); err != nil {
		return actual, err
	}
	if r.Receipt != nil && r.Receipt.ClaimID == job.Claim.ClaimID {
		candidate := receipt
		candidate.Manifest = r.Receipt.Manifest
		if !sameValue(candidate, *r.Receipt) {
			return actual, fault(api.CodeIdempotencyConflict, "cleanup receipt retry changed its retained bytes")
		}
		return s.readCollectionReceipt(ctx, s.db, job, *r.Receipt)
	}
	if r.Receipt != nil && r.Receipt.ID == receipt.ID {
		return actual, fault(api.CodeIdempotencyConflict, "reclaimed cleanup requires a fresh receipt and verification for the new claim")
	}
	if receipt.Manifest != (api.BlobRef{}) {
		return actual, fault(api.CodeForbidden, "collector cannot choose a receipt manifest")
	}
	for n, object := range r.Inventory.Objects {
		var journal api.ObjectDisposition
		if err := storedProjection(ctx, s.db, "collection_object", cleanupObjectID(job.Intent.ID, string(object.Ref.ID)), &journal); err != nil {
			return actual, err
		}
		if n >= len(receipt.Objects) || !sameValue(journal, receipt.Objects[n]) {
			return actual, fault(api.CodeIntegrity, "cleanup receipt differs from its protected object journal")
		}
		if _, err := s.cleanupRead(ctx, s.db, object); err != nil {
			return actual, err
		}
	}
	body, _, err := api.CleanupReceiptBytes(receipt)
	if err != nil {
		return actual, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return actual, err
	}
	defer finish(tx, &resultErr)
	receipt.Manifest, err = s.collectionBytes(ctx, tx, job, body)
	if err != nil {
		return actual, err
	}
	if err := api.ValidateCleanupReceiptWithRemoval(job, *r.Inventory, receipt, *r.RemovalClaim, s.deps.Clock.Now()); err != nil {
		return actual, err
	}
	r.Receipt = &receipt
	if err := s.saveCollection(ctx, tx, r); err != nil {
		return actual, err
	}
	if err := tx.Commit(); err != nil {
		return actual, err
	}
	return receipt, nil
}

func (s *Service) readCollectionReceipt(ctx context.Context, db queryer, job api.CleanupJob, receipt api.CleanupReceipt) (api.CleanupReceipt, error) {
	meta, raw, err := objectRow(ctx, db, receipt.Manifest.ID)
	if err != nil {
		return api.CleanupReceipt{}, err
	}
	body, _, err := api.CleanupReceiptBytes(receipt)
	if err != nil || meta.Ref != receipt.Manifest || meta.SourceOperationID != job.Intent.Cause.CauseOperationID || string(body) != string(raw) {
		return api.CleanupReceipt{}, fault(api.CodeIntegrity, "cleanup receipt failed independent retained-byte readback")
	}
	return receipt, nil
}

func (s *Service) CleanupReceipt(ctx context.Context, scope api.Scope, id api.ID) (api.CleanupReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return api.CleanupReceipt{}, err
	}
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='collection' AND json_extract(data,'$.Receipt.ID')=?", string(id)).Scan(&raw); err != nil {
		return api.CleanupReceipt{}, err
	}
	var r collectionRecord
	if err := decodeStored(raw, &r); err != nil {
		return api.CleanupReceipt{}, err
	}
	if r.Receipt == nil {
		return api.CleanupReceipt{}, fault(api.CodeNotFound, "cleanup receipt is pending")
	}
	return s.readCollectionReceipt(ctx, s.db, api.CleanupJob{Intent: r.Intent}, *r.Receipt)
}

func objectIdentity(meta api.ObjectMetadata) string {
	raw, err := json.Marshal(meta)
	if err != nil {
		return ""
	}
	return hash(raw)
}
