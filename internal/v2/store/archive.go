package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

var _ archivejob.Control = (*Service)(nil)

type archiveRecord struct {
	Job            archivejob.Job
	Scope          api.Scope
	Request        api.Request
	Lane           api.Lane
	Input          archivejob.Input
	Grants         api.GrantSet
	Phase          string
	Parts          []api.BlobRef
	Ack            *dataAcknowledgement
	Commit         *api.Commit
	Claim          api.EffectLease
	WorkerLaunchID api.ID
	WorkerActor    api.Actor
	Allocation     api.HelperLease
	Handoff        *api.PreparedSpecHandoff
	Endpoint       *api.InstalledBinding
	Process        api.ProcessHandle
	Failure        *api.Error
	FreezeAttempts uint32
	NextFreeze     api.Timestamp
	Limits         ArchiveLimits
	Allocating     bool
	Retirement     *archivejob.Retirement
}

func (s *Service) ownsMutation(ctx context.Context, scope api.Scope, key api.RequestKey, operation api.ID) (bool, error) {
	receipt, err := s.lookupReceipt(ctx, s.db, scope, key)
	if err != nil {
		return false, err
	}
	owner, _ := ctx.Value(reservationOwnerKey{}).(*reservationOwner)
	return receipt.Operation.ID == operation && receipt.Reply == nil && owner != nil && owner.store == s &&
		owner.live && owner.operation == operation && s.reservationOwners[operation] == owner, nil
}

func (s *Service) OwnsMutation(ctx context.Context, scope api.Scope, key api.RequestKey, operation api.ID) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return false, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return false, err
	}
	return s.ownsMutation(ctx, scope, key, operation)
}

// ReserveArchive first persists the original freeze intent. Native work occurs
// outside the writer lock; sealing rechecks every fence in the same transaction
// as the immutable input, grants, lease and sole worker effect.
func (s *Service) ReserveArchive(ctx context.Context, scope api.Scope, intent archivejob.Intent) (archivejob.Job, error) {
	record, err := s.reserveArchive(ctx, scope, intent)
	if err != nil {
		return archivejob.Job{}, err
	}
	return s.attemptArchive(ctx, record)
}

func (s *Service) reserveArchive(ctx context.Context, scope api.Scope, intent archivejob.Intent) (r archiveRecord, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return r, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return r, err
	}
	if scope.Request.Method != "lane.archive" || scope.Connection == nil || scope.Actor.Kind != "human" && scope.Actor.Kind != "lane" {
		return r, fault(api.CodeForbidden, "archive reservation requires the actual public dispatcher")
	}
	var request api.ArchiveRequest
	if api.DecodeObject(scope.Request.Params, &request) != nil || request != intent.Request {
		return r, fault(api.CodeConflict, "archive intent differs from the original request")
	}
	owned, err := s.ownsMutation(ctx, scope, requestKey(scope.Request), intent.OperationID)
	if err != nil {
		return r, err
	}
	if !owned {
		return r, fault(api.CodeForbidden, "archive reservation is not owned by this dispatcher invocation")
	}
	err = storedProjection(ctx, s.db, "archive_job", intent.OperationID, &r)
	if err == nil {
		if r.Job.Intent != intent || r.Scope.Actor != scope.Actor || !sameValue(r.Request, scope.Request) {
			return r, fault(api.CodeIdempotencyConflict, "archive retry changed its original intent")
		}
		return r, nil
	}
	if !absent(err) {
		return r, err
	}
	if s.deps.ArchiveNative == nil {
		return r, api.NotImplemented("lb-v2-admin", "protected current workspace/history/capture freeze")
	}
	r.Job.Intent, r.Scope = intent, api.Scope{Config: scope.Config, Actor: scope.Actor, Request: scope.Request, PolicyGeneration: scope.PolicyGeneration, LaunchID: scope.LaunchID, EndpointGeneration: scope.EndpointGeneration}
	r.Request = scope.Request
	if err := storedProjection(ctx, s.db, "lane", request.Target.LifeID, &r.Lane); err != nil {
		return r, err
	}
	if scope.Actor.Kind == "lane" && !slices.Contains(r.Lane.StarterChain, scope.Actor.LifeID) {
		return r, fault(api.CodeForbidden, "archive caller is outside the retained starter chain")
	}
	if err := s.archiveFence(ctx, s.db, r); err != nil {
		return r, err
	}
	binding, err := s.launchBinding(ctx, s.db, r.Lane.LaunchID)
	if err != nil {
		return r, err
	}
	if binding.Recovery == nil {
		return r, fault(api.CodeIntegrity, "archive lacks the original installed runtime and budget")
	}
	spec := binding.Recovery.Handoff.Spec
	meta, raw, err := objectRow(ctx, s.db, spec.RuntimeManifest.ID)
	if err != nil {
		return r, err
	}
	var runtime api.RuntimeManifest
	if meta.Ref != spec.RuntimeManifest || meta.Origin != "service" || api.DecodeObject(raw, &runtime) != nil || runtime.Schema != "laneboss.runtime.v2" || !wire.ValidDigest(string(runtime.Bootstrap.SHA256)) || !positiveBudget(spec.Budget) {
		return r, fault(api.CodeIntegrity, "archive runtime or fixed worker budget is not enrolled")
	}
	for _, id := range []*api.ID{&r.Job.ID, &r.Job.Lease.ID, &r.Job.Lease.EffectID, &r.Grants.ID, &r.Input.ReceiptID, &r.WorkerLaunchID, &r.WorkerActor.ID} {
		*id, err = wire.NewID()
		if err != nil {
			return r, err
		}
	}
	r.WorkerActor.Kind = "worker"
	var source api.GrantSet
	if err := storedProjection(ctx, s.db, "grants", r.Lane.GrantSetID, &source); err != nil {
		return r, err
	}
	r.Limits = s.deps.ArchiveLimits.resolved(spec.Budget)
	expires, err := archiveDeadline(s.deps.Clock.Now(), spec.Budget, r.Limits)
	if err != nil {
		return r, err
	}
	limit, err := time.Parse(time.RFC3339Nano, string(source.ExpiresAt))
	if err != nil {
		return r, err
	}
	if limit.Before(expires) {
		expires = limit
	}
	r.Grants = api.GrantSet{ID: r.Grants.ID, LifeID: request.Target.LifeID, ParentLifeID: request.Target.LifeID, Generation: 1,
		PolicyGeneration: scope.PolicyGeneration, ExpiresAt: api.Timestamp(expires.UTC().Format(timeFormat)), Data: []api.DataGrant{}, Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	grantBytes, err := canonicalValue(r.Grants)
	if err != nil {
		return r, err
	}
	r.Grants.SHA256 = api.Digest(hash(grantBytes))
	r.Job.Lease = api.WorkerLease{ID: r.Job.Lease.ID, EffectID: r.Job.Lease.EffectID, Kind: "archive", Target: request.Target, OperationID: intent.OperationID,
		RuntimeManifest: spec.RuntimeManifest, GrantSetID: r.Grants.ID, Generation: 1, ExpiresAt: r.Grants.ExpiresAt}
	r.Job.Plan = api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "archive", Executable: runtime.Bootstrap, GrantSetID: r.Grants.ID, Budget: spec.Budget,
		Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(r.Job.Lease.ID)}}
	r.Input.Schema, r.Input.JobID, r.Input.Intent, r.Input.StoreID, r.Input.Budget = "laneboss.archive-input.v2", r.Job.ID, intent, s.storeID, spec.Budget
	r.Phase, r.Parts = "freezing", []api.BlobRef{}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer finish(tx, &resultErr)
	if scope.Actor.Kind == "human" {
		if scope.Request.Proof == nil {
			return r, fault(api.CodeForbidden, "archive requires the original human proof")
		}
		target, err := s.authorizationTarget(ctx, tx, scope, scope.Request)
		if err != nil {
			return r, err
		}
		if err := s.guards(ctx, tx, api.Transaction{Scope: scope, Guards: []api.TransactionGuard{{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}}}}, intent.OperationID); err != nil {
			return r, err
		}
		var used api.ProofUseReceipt
		if err := storedProjection(ctx, tx, "proof_use", scope.Request.Proof.ID, &used); err != nil {
			return r, err
		}
		event, err := s.archiveEvent(r, "human.proof.used", used)
		if err != nil {
			return r, err
		}
		if _, err := appendPrivateEvent(ctx, tx, event, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))); err != nil {
			return r, err
		}
	}
	if err := put(ctx, tx, "archive_job", intent.OperationID, 1, r); err != nil {
		return r, err
	}
	if err := tx.Commit(); err != nil {
		return r, err
	}
	s.notifyChanged()
	return r, nil
}

func (s *Service) archiveFence(ctx context.Context, db queryer, r archiveRecord) error {
	i := r.Job.Intent
	if err := s.currentLifecycleRequester(ctx, db, r.Scope.Actor); err != nil {
		return err
	}
	if r.Scope.Actor.Kind == "lane" {
		if err := s.scope(ctx, db, r.Scope); err != nil {
			return err
		}
	}
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", i.Request.Target.LifeID, &lane); err != nil {
		return err
	}
	if lane.Run != i.Request.Target.Run || lane.Generation != i.Request.ExpectedGeneration || lane.CancellationEpoch != i.CancellationEpoch || lane.Cleaned || lane.LaunchID != r.Lane.LaunchID {
		return fault(api.CodeConflict, "archive lost its original life generation or cancellation fence")
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return err
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, db, "grants", lane.GrantSetID, &grants); err != nil {
		return err
	}
	if policy.Generation != r.Scope.PolicyGeneration || grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeForbidden, "archive policy or source grant authority changed")
	}
	if grants.ID != lane.GrantSetID || grants.LifeID != lane.LifeID {
		return fault(api.CodeForbidden, "archive source grants belong to another life")
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE id=? AND seq=?", string(i.EndEventID), uint64(i.EndSeq)).Scan(&raw); err != nil {
		return err
	}
	var event api.Event
	var end api.RunEndEvent
	if decodeStored(raw, &event) != nil || api.DecodeObject(event.Payload, &end) != nil || event.Kind != "lane.ended" || event.LifeID != lane.LifeID || event.Run != lane.Run || event.Origin != "service" ||
		end.LaunchID != lane.LaunchID || end.Reason == "service_lost" || end.Observation.State != "exited" || end.Observation.Survivors == nil || *end.Observation.Survivors != 0 {
		return fault(api.CodeContainmentUnknown, "archive has no exact committed quiescent end")
	}
	var measured struct {
		Observation api.ProcessObservation
		Generation  api.Generation
	}
	if err := storedProjection(ctx, db, "launch_observation", lane.LaunchID, &measured); err != nil {
		return err
	}
	if !sameValue(measured.Observation, end.Observation) {
		return fault(api.CodeContainmentUnknown, "archive end differs from the retained independent process observation")
	}
	// Stops drain captures (docs/design/v2-contracts.md:737-738), and after the stop only the retained drain claim for
	// the original run and its unacknowledged spool may continue (:3024-3026). So the ranges the run's release drain
	// committed after the end are its own source; every other late source event still changes it.
	for after := i.EndSeq; ; {
		var seq api.Sequence
		var raw []byte
		err := db.QueryRowContext(ctx, "SELECT seq,data FROM events WHERE seq>? AND json_extract(data,'$.life_id')=? AND json_extract(data,'$.kind') IN ('lane.started','lane.resumed','lane.turn','capture.appended','capture.gap','prompt.observed','data.materialized','lane.lost','runner.session') ORDER BY seq LIMIT 1", uint64(after), string(lane.LifeID)).Scan(&seq, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		drained, err := releaseDrained(ctx, db, seq, raw, i.Request.Target)
		if err != nil {
			return err
		}
		if !drained {
			return fault(api.CodeConflict, "archive source changed after its committed end")
		}
		after = seq
	}
	if r.Request.Proof != nil && r.Phase != "" {
		var proof api.VerifiedHumanProof
		if err := storedProjection(ctx, db, "proof", r.Request.Proof.ID, &proof); err != nil {
			return err
		}
		if proof.ConsumedBy != i.OperationID {
			return fault(api.CodeForbidden, "archive proof was not consumed by its original operation")
		}
		if _, err := s.proofCredential(ctx, db, proof); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// releaseDrained reports whether a late event is a range the run's release drain committed for its own unacknowledged
// spool (CommitCaptureDrain): the drained object of that binding, stream and offset, by the binding's producer and
// operation, at or before the last sequence of the run's committed capture_drain receipt.
func releaseDrained(ctx context.Context, db queryer, seq api.Sequence, raw []byte, target api.LifeRef) (bool, error) {
	var event api.Event
	if err := decodeStored(raw, &event); err != nil {
		return false, err
	}
	var record api.CaptureRecord
	if event.Kind != "capture.appended" || event.Run != target.Run || json.Unmarshal(event.Payload, &record) != nil ||
		record.BindingID == "" || record.ID != event.ID || record.Target != target || !record.Primary {
		return false, nil
	}
	var drain api.CaptureDrainReceipt
	if err := storedProjection(ctx, db, "capture_drain", record.BindingID, &drain); absent(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	b := drain.State.Binding
	if b.ID != record.BindingID || b.Target != target || event.OperationID != b.OperationID ||
		event.Actor != (api.Actor{Kind: "worker", ID: b.ProducerID}) || seq > drain.State.LastSeq {
		return false, nil
	}
	for _, stream := range b.Streams {
		name := stream.Stream
		if name == "vendor" {
			name = "structured"
		}
		if name == record.Stream {
			return record.Data.ID == drainObjectID(b.ID, stream.ID, record.Offset), nil
		}
	}
	return false, nil
}

func (s *Service) sealArchive(ctx context.Context, prior archiveRecord) (job archivejob.Job, resultErr error) {
	if prior.Failure != nil {
		return job, prior.Failure
	}
	if prior.Phase != "freezing" {
		return prior.Job, nil
	}
	if s.deps.ArchiveNative == nil {
		return job, api.NotImplemented("lb-v2-admin", "protected archive freeze reconciliation")
	}
	if !future(prior.Job.Lease.ExpiresAt, s.deps.Clock.Now()) {
		return job, fault(api.CodeDeadline, "archive lease expired before storage freeze")
	}
	s.mu.RLock()
	fenceErr := s.archiveFence(ctx, s.db, prior)
	s.mu.RUnlock()
	if fenceErr != nil {
		return job, fenceErr
	}
	if !future(prior.Job.Lease.ExpiresAt, s.deps.Clock.Now()) {
		return job, fault(api.CodeDeadline, "archive lease expired before storage freeze")
	}
	snapshot, err := s.deps.ArchiveNative.FreezeArchive(ctx, prior.Job.Intent, prior.Lane)
	if err != nil {
		return job, err
	}
	f := snapshot.Freeze
	if err := validateArchiveFreeze(prior, snapshot, s.deps.Clock.Now()); err != nil {
		return job, err
	}
	if err := s.deps.ArchiveNative.CheckArchiveFreeze(ctx, prior.Job.Intent, f); err != nil {
		return job, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return job, err
	}
	var r archiveRecord
	if err := storedProjection(ctx, s.db, "archive_job", prior.Job.Intent.OperationID, &r); err != nil {
		return job, err
	}
	if r.Phase != "freezing" {
		return r.Job, nil
	}
	if !sameValue(r, prior) {
		return job, fault(api.CodeConflict, "archive reservation changed during native freeze")
	}
	if err := s.archiveFence(ctx, s.db, r); err != nil {
		return job, err
	}
	if !future(r.Job.Lease.ExpiresAt, s.deps.Clock.Now()) {
		return job, fault(api.CodeDeadline, "archive fixed lease expired during freeze")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return job, err
	}
	defer finish(tx, &resultErr)
	var snapshotBytes uint64
	for _, object := range snapshot.Objects {
		if object.ACL.LifeID != r.Lane.LifeID || object.Origin != "service" {
			return job, fault(api.CodeForbidden, "native snapshot object has foreign ownership")
		}
		if uint64(len(object.Bytes)) > r.Job.Plan.Budget.DiskBytes-snapshotBytes {
			return job, fault(api.CodeBudget, "native archive snapshot exceeds its fixed disk budget")
		}
		snapshotBytes += uint64(len(object.Bytes))
		object.ACL = s.archiveACL(r)
		if _, err := s.retain(ctx, tx, api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: s.storeID}}, object, r.Job.Intent.OperationID, f.ObservedAt); err != nil {
			return job, err
		}
	}
	meta, raw, err := objectRow(ctx, tx, f.Snapshot.ID)
	if err != nil {
		return job, err
	}
	if meta.Ref != f.Snapshot || meta.SourceOperationID != r.Job.Intent.OperationID {
		return job, fault(api.CodeIntegrity, "frozen manifest was not retained by this archive operation")
	}
	tree, err := archivejob.Manifest(raw)
	if err != nil {
		return job, err
	}
	inlineSeen, inlineBytes := map[api.ID]bool{}, 0
	for _, entry := range tree.Entries {
		for _, ref := range manifest.ContentRefs(entry) {
			meta, content, err := objectRow(ctx, tx, ref.ID)
			if err != nil {
				return job, err
			}
			if meta.Ref != ref || meta.ACL.Config != s.deps.Config || meta.ACL.LifeID != r.Lane.LifeID {
				return job, fault(api.CodeIntegrity, "archive frozen content is missing or foreign")
			}
			if !inlineSeen[ref.ID] && len(content) <= 4096 && inlineBytes+len(content) <= archivejob.MaxInlineBytes {
				r.Input.Inline = append(r.Input.Inline, archivejob.FrozenObject{Ref: ref, Bytes: append([]byte{}, content...)})
				inlineSeen[ref.ID], inlineBytes = true, inlineBytes+len(content)
			}
		}
	}
	body, err := canonicalValue(f)
	if err != nil {
		return job, err
	}
	r.Job.Freeze, err = s.archiveBytes(ctx, tx, r, "manifest", body)
	if err != nil {
		return job, err
	}
	r.Input.Freeze = r.Job.Freeze
	body, err = canonicalValue(r.Input)
	if err != nil {
		return job, err
	}
	r.Job.Lease.Input, err = s.archiveBytes(ctx, tx, r, "archive_input", body)
	if err != nil {
		return job, err
	}
	r.Job.Plan.Input = r.Job.Lease.Input
	intentID, err := wire.NewID()
	if err != nil {
		return job, err
	}
	cause := api.InternalIntent{ID: intentID, Kind: api.InternalLifecycleEffect, Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: s.storeID}, RequestedBy: r.Scope.Actor,
		CauseOperationID: r.Job.Intent.OperationID, CauseRequestID: r.Request.RequestID, EffectID: r.Job.Lease.EffectID, Target: r.Job.Intent.Request.Target, CancellationEpoch: r.Job.Intent.CancellationEpoch}
	if err := insertLaunchEffect(ctx, tx, api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Worker: &r.Job.Plan}); err != nil {
		return job, err
	}
	if err := put(ctx, tx, "grants", r.Grants.ID, 1, r.Grants); err != nil {
		return job, err
	}
	if err := put(ctx, tx, "worker_lease", r.Job.Lease.ID, 1, r.Job.Lease); err != nil {
		return job, err
	}
	r.Phase = "sealed"
	if err := s.saveArchive(ctx, tx, r); err != nil {
		return job, err
	}
	if err := tx.Commit(); err != nil {
		return job, err
	}
	s.notifyChanged()
	return r.Job, nil
}

func validateArchiveFreeze(prior archiveRecord, snapshot archivejob.Snapshot, now time.Time) error {
	f := snapshot.Freeze
	observed, err := time.Parse(time.RFC3339Nano, string(f.ObservedAt))
	if err != nil || observed.IsZero() || observed.After(now) || f.Target != prior.Job.Intent.Request.Target || f.LaunchID != prior.Lane.LaunchID || f.CancellationEpoch != prior.Job.Intent.CancellationEpoch ||
		f.Writers == nil || *f.Writers != 0 || f.WritableExports == nil || *f.WritableExports != 0 || len(snapshot.Objects) == 0 {
		return fault(api.CodeContainmentUnknown, "archive freeze did not measure complete inputs and zero writable access")
	}
	if uint64(len(snapshot.Objects)) > prior.Limits.resolved(prior.Job.Plan.Budget).SnapshotObjects {
		return fault(api.CodeBudget, "native archive snapshot exceeds the installation object budget")
	}
	return nil
}

func (s *Service) archiveBytes(ctx context.Context, tx *sql.Tx, r archiveRecord, class string, raw []byte) (api.BlobRef, error) {
	id, err := wire.NewID()
	if err != nil {
		return api.BlobRef{}, err
	}
	actor := api.Actor{Kind: "service", ID: s.storeID}
	return s.retain(ctx, tx, api.Scope{Config: s.deps.Config, Actor: actor}, api.ObjectWrite{ObjectKey: id, Class: class, Bytes: raw, SHA256: api.Digest(hash(raw)), Origin: "service",
		ACL: s.archiveACL(r)}, r.Job.Intent.OperationID, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
}

func (s *Service) archiveACL(r archiveRecord) api.ObjectACL {
	participants := []api.ID{r.Scope.Actor.ID}
	if r.Scope.Actor.LifeID != "" {
		participants = append(participants, r.Scope.Actor.LifeID)
	}
	return api.ObjectACL{Config: s.deps.Config, Owner: api.Actor{Kind: "service", ID: s.storeID}, LifeID: r.Lane.LifeID, Audience: "participants", Participants: participants, Generation: 1}
}

func (s *Service) ArchiveJob(ctx context.Context, scope api.Scope, operation api.ID) (archivejob.Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return archivejob.Job{}, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return archivejob.Job{}, err
	}
	var r archiveRecord
	if err := storedProjection(ctx, s.db, "archive_job", operation, &r); err != nil {
		return archivejob.Job{}, err
	}
	if scope.Actor != r.Scope.Actor && !internalScope(scope) {
		return archivejob.Job{}, fault(api.CodeForbidden, "archive job belongs to another original requester")
	}
	if r.Phase == "freezing" {
		return archivejob.Job{}, fault(api.CodeUnavailable, "archive freeze is pending under its retained intent")
	}
	if r.Failure != nil {
		return archivejob.Job{}, r.Failure
	}
	return r.Job, nil
}
