package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func (s *Service) archiveClaim(ctx context.Context, db queryer, scope api.Scope, lease api.EffectLease) (archiveRecord, error) {
	var r archiveRecord
	if err := s.dataScope(ctx, db, scope); err != nil {
		return r, err
	}
	current, err := effectRow(ctx, db, lease.Record.Effect.ID)
	if err != nil {
		return r, err
	}
	if !api.EffectLeaseClaimed(lease) || !sameValue(current, lease.Record) || current.Outcome != nil || current.ClaimID != lease.ClaimID || current.ClaimantID != scope.Actor.ID || current.ClaimExpiresAt != lease.ExpiresAt || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return r, fault(api.CodeConflict, "archive worker lost its current original claim")
	}
	if err := storedProjection(ctx, db, "archive_job", current.Effect.OperationID, &r); err != nil {
		return r, err
	}
	if current.Effect.Worker == nil || !sameValue(*current.Effect.Worker, r.Job.Plan) || current.Effect.ID != r.Job.Lease.EffectID || r.Phase == "freezing" || r.Commit != nil {
		return r, fault(api.CodeForbidden, "archive claim does not select its retained fixed worker")
	}
	if err := s.archiveFence(ctx, db, r); err != nil {
		return r, err
	}
	if !future(r.Job.Lease.ExpiresAt, s.deps.Clock.Now()) {
		return r, fault(api.CodeDeadline, "archive worker fixed lease expired")
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, db, "grants", r.Grants.ID, &grants); err != nil {
		return r, err
	}
	if !sameValue(grants, r.Grants) || grants.Revoked {
		return r, fault(api.CodeForbidden, "archive worker grants changed or were revoked")
	}
	return r, nil
}

func (s *Service) saveArchive(ctx context.Context, tx *sql.Tx, r archiveRecord) error {
	var generation api.Generation
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM projections WHERE kind='archive_job' AND id=?", string(r.Job.Intent.OperationID)).Scan(&generation); err != nil {
		return err
	}
	return put(ctx, tx, "archive_job", r.Job.Intent.OperationID, generation+1, r)
}

// ArchiveHandoff seals the actual distinct helper allocation before preparing a
// gate. An exact retry reopens this record; another UID, endpoint or argv fails.
func (s *Service) ArchiveHandoff(ctx context.Context, scope api.Scope, lease api.EffectLease, allocation api.HelperLease, endpoint api.InstalledBinding) (handoff api.PreparedSpecHandoff, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.archiveClaim(ctx, s.db, scope, lease)
	if err != nil {
		return handoff, err
	}
	if r.Handoff != nil {
		if r.Allocation != allocation || r.Endpoint == nil || !sameValue(*r.Endpoint, endpoint) {
			return handoff, fault(api.CodeConflict, "archive native allocation or endpoint changed")
		}
		// A fresh reconciler claims the same immutable job/spec. Only its
		// authenticated service actor changes; the original cause/requester,
		// input, allocation and spec bytes remain pinned.
		h := *r.Handoff
		h.Cause.Actor = scope.Actor
		r.Handoff = &h
		r.Claim = lease
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return handoff, err
		}
		defer finish(tx, &resultErr)
		if err := s.saveArchive(ctx, tx, r); err != nil {
			return handoff, err
		}
		if err := tx.Commit(); err != nil {
			return handoff, err
		}
		return *r.Handoff, nil
	}
	agent, err := s.launchBinding(ctx, s.db, r.Lane.LaunchID)
	if err != nil {
		return handoff, err
	}
	if allocation.ID == "" || allocation.UID == 0 || allocation.GID == 0 || allocation.UID == agent.Record.HostUID || allocation.ContainmentID == agent.Record.ContainmentID || allocation.ID == agent.Record.UIDLeaseID || allocation.ContainmentID == "" || allocation.EndpointGeneration == 0 {
		return handoff, fault(api.CodeForbidden, "archive requires a distinct measured worker UID and containment")
	}
	if err := api.ValidateBinding(endpoint, scope.Config, r.Job.Plan.Executable.Version); err != nil {
		return handoff, err
	}
	if endpoint.Class != api.EndpointWorker || endpoint.Target == nil || *endpoint.Target != r.Job.Intent.Request.Target || endpoint.WorkerLeaseID != r.Job.Lease.ID || endpoint.LaunchID != r.WorkerLaunchID || endpoint.Socket != "/runtime/laneboss-worker.sock" || endpoint.EndpointGeneration != allocation.EndpointGeneration || endpoint.ArtifactSHA256 != r.Job.Plan.Executable.SHA256 {
		return handoff, fault(api.CodeForbidden, "archive endpoint differs from its reserved installed worker")
	}
	id, err := wire.NewID()
	if err != nil {
		return handoff, err
	}
	spec := api.LaunchSpec{Kind: "worker", PlanID: r.Job.ID, ID: id, Target: r.Job.Intent.Request.Target, LaunchID: r.WorkerLaunchID, Backend: endpoint.Backend,
		UIDLeaseID: allocation.ID, Worker: &r.Job.Plan, Grants: r.Grants, Budget: r.Job.Plan.Budget, EndpointGeneration: allocation.EndpointGeneration, RuntimeManifest: r.Job.Lease.RuntimeManifest, PolicyGeneration: r.Scope.PolicyGeneration,
		Materialization: api.Materialization{GrantSetID: r.Grants.ID, Manifest: r.Job.Freeze, Objects: []api.MaterializedObject{}}, Injection: api.Injection{Target: r.Job.Intent.Request.Target, SlotIDs: []api.ID{}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"}}
	raw, err := canonicalValue(spec)
	if err != nil {
		return handoff, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return handoff, err
	}
	defer finish(tx, &resultErr)
	ref, err := s.archiveBytes(ctx, tx, r, "launch_spec", raw)
	if err != nil {
		return handoff, err
	}
	cause := *lease.Record.Effect.Context
	cause.Kind, cause.Actor = api.InternalHelperRegister, scope.Actor
	handoff = api.PreparedSpecHandoff{Cause: cause, Config: scope.Config, Spec: spec, Original: ref, SpecSHA256: ref.SHA256, OperationID: r.Job.Intent.OperationID, RequestID: r.Request.RequestID}
	r.Handoff, r.Endpoint, r.Allocation, r.Claim = &handoff, &endpoint, allocation, lease
	if err := s.saveArchive(ctx, tx, r); err != nil {
		return handoff, err
	}
	if err := tx.Commit(); err != nil {
		return handoff, err
	}
	return handoff, nil
}

func (s *Service) ArchiveWorkerID(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.ID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, err := s.archiveClaim(ctx, s.db, scope, lease)
	return r.WorkerLaunchID, err
}

func (s *Service) BindArchiveWorker(ctx context.Context, scope api.Scope, lease api.EffectLease, prepared api.PreparedLaunch) (binding api.LaunchBindingRequest, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.archiveClaim(ctx, s.db, scope, lease)
	if err != nil {
		return binding, err
	}
	if r.Handoff == nil || r.Endpoint == nil || prepared.Target != r.Job.Intent.Request.Target || prepared.SpecSHA256 != r.Handoff.SpecSHA256 || prepared.ContainmentID != r.Allocation.ContainmentID || prepared.EndpointGeneration != r.Allocation.EndpointGeneration || prepared.ID == "" || prepared.GateID == "" || prepared.ProcessGeneration == "" {
		return binding, fault(api.CodeIntegrity, "archive prepared gate changed its sealed worker spec")
	}
	prior, err := s.launchBinding(ctx, s.db, r.WorkerLaunchID)
	if err == nil {
		if prior.Prepared != prepared || prior.Record.Actor != r.WorkerActor {
			return binding, fault(api.CodeConflict, "archive prepared worker was replaced")
		}
		return prior, nil
	}
	if !absent(err) {
		return binding, err
	}
	lane, a := r.Lane, r.Allocation
	record := api.LaunchRecord{Kind: "worker", ID: r.WorkerLaunchID, Config: s.deps.Config, Target: r.Job.Intent.Request.Target, RootLifeID: lane.RootLifeID, ParentLifeID: lane.ParentLifeID,
		StarterChain: append([]api.ID{}, lane.StarterChain...), StarterEventSeq: lane.StarterEventSeq, Actor: r.WorkerActor, UIDLeaseID: a.ID, HostUID: a.UID, ProcessGeneration: prepared.ProcessGeneration, ContainmentID: a.ContainmentID,
		GrantSetID: r.Grants.ID, GrantsSHA256: r.Grants.SHA256, PolicyGeneration: r.Scope.PolicyGeneration, EndpointGeneration: a.EndpointGeneration}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return binding, err
	}
	defer finish(tx, &resultErr)
	event, err := s.archiveEvent(r, "identity.bound", record)
	if err != nil {
		return binding, err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	seq, err := appendPrivateEvent(ctx, tx, event, now)
	if err != nil {
		return binding, err
	}
	raw, err := canonicalValue(record)
	if err != nil {
		return binding, err
	}
	binding = api.LaunchBindingRequest{Record: record, Prepared: prepared, Identity: api.IdentityCommit{LaunchID: record.ID, EventID: event.ID, CommittedSeq: seq, RecordSHA256: api.Digest(hash(raw))}}
	if err := put(ctx, tx, "launch", record.ID, 1, record); err != nil {
		return binding, err
	}
	if err := put(ctx, tx, "launch_binding", record.ID, 1, binding); err != nil {
		return binding, err
	}
	if err := put(ctx, tx, "endpoint", record.ID, 1, api.EndpointProjection{Binding: *r.Endpoint, Generation: 1}); err != nil {
		return binding, err
	}
	worker := r.Job.Lease
	worker.ConsumedBy = record.ID
	if err := put(ctx, tx, "worker_lease", worker.ID, worker.Generation, worker); err != nil {
		return binding, err
	}
	if err := tx.Commit(); err != nil {
		return binding, err
	}
	s.notifyChanged()
	return binding, nil
}

func (s *Service) RecordArchiveProcess(ctx context.Context, scope api.Scope, lease api.EffectLease, process api.ProcessHandle) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.archiveClaim(ctx, s.db, scope, lease)
	if err != nil {
		return err
	}
	binding, err := s.launchBinding(ctx, s.db, r.WorkerLaunchID)
	if err != nil {
		return err
	}
	if process.ID != binding.Record.ID || process.Target != binding.Record.Target || process.ContainmentID != binding.Record.ContainmentID || process.Generation != binding.Record.ProcessGeneration || r.Process.ID != "" && r.Process != process {
		return fault(api.CodeIntegrity, "archive process differs from its committed prepared identity")
	}
	r.Process = process
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := s.saveArchive(ctx, tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) archiveEvent(r archiveRecord, kind api.EventKind, body any) (api.Event, error) {
	id, err := wire.NewID()
	if err != nil {
		return api.Event{}, err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return api.Event{}, err
	}
	actor := api.Actor{Kind: "service", ID: s.storeID}
	if r.Claim.ClaimID != "" {
		actor.ID = r.Claim.Record.ClaimantID
	}
	lane := r.Lane
	return api.Event{Schema: api.SchemaVersion, ID: id, Config: s.deps.Config, Kind: kind, Actor: actor, RequestedBy: r.Scope.Actor, OperationID: r.Job.Intent.OperationID,
		RequestID: r.Request.RequestID, LifeID: lane.LifeID, Run: lane.Run, RootLifeID: lane.RootLifeID, ParentLifeID: lane.ParentLifeID, StarterChain: append([]api.ID{}, lane.StarterChain...), StarterEventSeq: lane.StarterEventSeq, Origin: "service", Payload: raw}, nil
}

func (s *Service) archivePrincipal(ctx context.Context, db queryer, endpoint api.InstalledBinding, peer api.PeerFacts, operation api.WorkerOperation) (p api.WorkerPrincipal, resultErr error) {
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='archive_job' AND json_extract(data,'$.Job.Lease.ID')=?", string(endpoint.WorkerLeaseID)).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return p, fault(api.CodeNotFound, "worker has no retained fixed job")
		}
		return p, err
	}
	var r archiveRecord
	if err := decodeStored(raw, &r); err != nil {
		return p, err
	}
	if r.Endpoint == nil || !sameValue(*r.Endpoint, endpoint) {
		return p, fault(api.CodeUnauthenticated, "archive worker endpoint changed")
	}
	if r.Retirement != nil {
		return p, fault(api.CodeForbidden, "retired archive worker has no remaining socket authority")
	}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: r.Claim.Record.ClaimantID}}
	if _, err := s.archiveClaim(ctx, db, scope, r.Claim); err != nil {
		return p, err
	}
	binding, err := s.launchBinding(ctx, db, r.WorkerLaunchID)
	if err != nil {
		return p, err
	}
	record := binding.Record
	var current api.EndpointProjection
	if err := storedProjection(ctx, db, "endpoint", record.ID, &current); err != nil {
		return p, err
	}
	if record.Revoked || current.Revoked || !sameValue(current.Binding, endpoint) || record.Actor != r.WorkerActor || record.HostUID != r.Allocation.UID || peer.HostGID != r.Allocation.GID || record.ContainmentID != r.Allocation.ContainmentID {
		return p, fault(api.CodeUnauthenticated, "archive worker is outside its native distinct allocation")
	}
	var worker api.WorkerLease
	if err := storedProjection(ctx, db, "worker_lease", r.Job.Lease.ID, &worker); err != nil {
		return p, err
	}
	want := r.Job.Lease
	want.ConsumedBy, want.Generation = record.ID, worker.Generation
	if worker != want || worker.Generation < r.Job.Lease.Generation || worker.Generation > r.Job.Lease.Generation+1 {
		return p, fault(api.CodeConflict, "archive worker lease changed")
	}
	boot, _, found := strings.Cut(record.ProcessGeneration, ":")
	peerBoot, _, peerFound := strings.Cut(peer.ProcessGeneration, ":")
	if !found || !peerFound || boot == "" || boot != peerBoot {
		return p, fault(api.CodeContainmentUnknown, "archive worker native boot differs")
	}
	want.Generation = r.Job.Lease.Generation
	p = api.WorkerPrincipal{StageID: r.Job.ID, Lease: want, Record: record, Endpoint: endpoint, Peer: peer, BootID: boot, AllocationGeneration: endpoint.InstallationGeneration, Claim: r.Claim, CancellationEpoch: r.Job.Intent.CancellationEpoch}
	return p, api.ValidateWorkerPrincipal(p, endpoint, peer, operation, s.deps.Clock.Now())
}

func (s *Service) archiveRefs(ctx context.Context, db queryer, r archiveRecord) (map[api.ID]api.BlobRef, archivejob.Freeze, error) {
	inputMeta, inputRaw, err := objectRow(ctx, db, r.Job.Lease.Input.ID)
	if err != nil {
		return nil, archivejob.Freeze{}, err
	}
	if inputMeta.Ref != r.Job.Lease.Input || inputMeta.SourceOperationID != r.Job.Intent.OperationID || inputMeta.Origin != "service" || !sameDataBytes(inputRaw, r.Input) || r.Input.Freeze != r.Job.Freeze || r.Input.Intent != r.Job.Intent || r.Input.JobID != r.Job.ID || r.Input.Budget != r.Job.Plan.Budget {
		return nil, archivejob.Freeze{}, fault(api.CodeIntegrity, "archive lost its exact retained input and provenance")
	}
	refs := map[api.ID]api.BlobRef{r.Job.Freeze.ID: r.Job.Freeze, r.Job.Lease.Input.ID: r.Job.Lease.Input}
	meta, raw, err := objectRow(ctx, db, r.Job.Freeze.ID)
	if err != nil {
		return nil, archivejob.Freeze{}, err
	}
	var f archivejob.Freeze
	if meta.Ref != r.Job.Freeze || meta.SourceOperationID != r.Job.Intent.OperationID || meta.Origin != "service" || api.DecodeObject(raw, &f) != nil || f.Target != r.Job.Intent.Request.Target || f.LaunchID != r.Lane.LaunchID || f.CancellationEpoch != r.Job.Intent.CancellationEpoch || f.Writers == nil || *f.Writers != 0 || f.WritableExports == nil || *f.WritableExports != 0 {
		return nil, f, fault(api.CodeIntegrity, "archive lost its retained native freeze")
	}
	meta, raw, err = objectRow(ctx, db, f.Snapshot.ID)
	if err != nil {
		return nil, f, err
	}
	if meta.Ref != f.Snapshot || meta.SourceOperationID != r.Job.Intent.OperationID {
		return nil, f, fault(api.CodeIntegrity, "archive frozen manifest changed provenance")
	}
	tree, err := archivejob.Manifest(raw)
	if err != nil {
		return nil, f, err
	}
	refs[f.Snapshot.ID] = f.Snapshot
	for _, entry := range tree.Entries {
		for _, ref := range manifest.ContentRefs(entry) {
			refs[ref.ID] = ref
		}
	}
	for _, ref := range r.Parts {
		meta, _, err := objectRow(ctx, db, ref.ID)
		if err != nil {
			return nil, f, err
		}
		if meta.Ref != ref || meta.SourceOperationID != r.Job.Intent.OperationID || meta.Origin != "service" || meta.ACL.Config != s.deps.Config || meta.ACL.LifeID != r.Lane.LifeID {
			return nil, f, fault(api.CodeIntegrity, "archive part has foreign operation or life provenance")
		}
		refs[ref.ID] = ref
	}
	return refs, f, nil
}

func (s *Service) archiveObject(ctx context.Context, db queryer, r archiveRecord, request api.BlobReadRequest) (api.BlobChunk, error) {
	if request.Offset < 0 || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
		return api.BlobChunk{}, wire.Invalid("invalid archive object range")
	}
	refs, _, err := s.archiveRefs(ctx, db, r)
	if err != nil {
		return api.BlobChunk{}, err
	}
	ref, ok := refs[request.ObjectID]
	if !ok {
		return api.BlobChunk{}, fault(api.CodeNotFound, "archive object is outside this exact job inventory")
	}
	meta, raw, err := objectRow(ctx, db, ref.ID)
	if err != nil {
		return api.BlobChunk{}, err
	}
	if meta.Ref != ref || meta.ACL.Config != s.deps.Config || meta.ACL.LifeID != r.Lane.LifeID || request.Offset > int64(len(raw)) {
		return api.BlobChunk{}, fault(api.CodeIntegrity, "archive object differs from its retained bytes or ownership")
	}
	data := append([]byte{}, raw[request.Offset:min(int64(len(raw)), request.Offset+int64(request.Limit))]...)
	return api.BlobChunk{ObjectID: ref.ID, Offset: request.Offset, Data: data, SHA256: api.Digest(hash(data))}, nil
}
