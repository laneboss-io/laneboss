package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) saveReview(ctx context.Context, tx *sql.Tx, r reviewRecord) error {
	var generation api.Generation
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM projections WHERE kind='review_job' AND id=?", string(r.Job.Intent.OperationID)).Scan(&generation); err != nil {
		return err
	}
	return put(ctx, tx, "review_job", r.Job.Intent.OperationID, generation+1, r)
}

// ReviewHandoff seals the actual distinct helper allocation before preparing a
// gate. An exact retry reopens this record; another UID, endpoint or argv fails.
func (s *Service) ReviewHandoff(ctx context.Context, scope api.Scope, lease api.EffectLease, allocation api.HelperLease, endpoint api.InstalledBinding) (handoff api.PreparedSpecHandoff, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.reviewClaim(ctx, s.db, scope, lease)
	if err != nil {
		return handoff, err
	}
	if r.Handoff != nil {
		if r.Allocation != allocation || r.Endpoint == nil || !sameValue(*r.Endpoint, endpoint) {
			return handoff, fault(api.CodeConflict, "review native allocation or endpoint changed")
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
		if err := s.saveReview(ctx, tx, r); err != nil {
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
		return handoff, fault(api.CodeForbidden, "review requires a distinct measured worker UID and containment")
	}
	if err := api.ValidateBinding(endpoint, scope.Config, r.Job.Plan.Executable.Version); err != nil {
		return handoff, err
	}
	if endpoint.Class != api.EndpointWorker || endpoint.Target == nil || *endpoint.Target != r.Job.Intent.Request.Target || endpoint.WorkerLeaseID != r.Job.Lease.ID || endpoint.LaunchID != r.WorkerLaunchID || endpoint.Socket != "/runtime/laneboss-worker.sock" || endpoint.EndpointGeneration != allocation.EndpointGeneration || endpoint.ArtifactSHA256 != r.Job.Plan.Executable.SHA256 {
		return handoff, fault(api.CodeForbidden, "review endpoint differs from its reserved installed worker")
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
	ref, err := s.reviewBytes(ctx, tx, r, "launch_spec", raw)
	if err != nil {
		return handoff, err
	}
	cause := *lease.Record.Effect.Context
	cause.Kind, cause.Actor = api.InternalHelperRegister, scope.Actor
	handoff = api.PreparedSpecHandoff{Cause: cause, Config: scope.Config, Spec: spec, Original: ref, SpecSHA256: ref.SHA256, OperationID: r.Job.Intent.OperationID, RequestID: r.Request.RequestID}
	r.Handoff, r.Endpoint, r.Allocation, r.Claim = &handoff, &endpoint, allocation, lease
	if err := s.saveReview(ctx, tx, r); err != nil {
		return handoff, err
	}
	if err := tx.Commit(); err != nil {
		return handoff, err
	}
	return handoff, nil
}

func (s *Service) ReviewWorkerID(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.ID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, err := s.reviewClaim(ctx, s.db, scope, lease)
	return r.WorkerLaunchID, err
}

func (s *Service) BindReviewWorker(ctx context.Context, scope api.Scope, lease api.EffectLease, prepared api.PreparedLaunch) (binding api.LaunchBindingRequest, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.reviewClaim(ctx, s.db, scope, lease)
	if err != nil {
		return binding, err
	}
	if r.Handoff == nil || r.Endpoint == nil || prepared.Target != r.Job.Intent.Request.Target || prepared.SpecSHA256 != r.Handoff.SpecSHA256 || prepared.ContainmentID != r.Allocation.ContainmentID || prepared.EndpointGeneration != r.Allocation.EndpointGeneration || prepared.ID == "" || prepared.GateID == "" || prepared.ProcessGeneration == "" {
		return binding, fault(api.CodeIntegrity, "review prepared gate changed its sealed worker spec")
	}
	prior, err := s.launchBinding(ctx, s.db, r.WorkerLaunchID)
	if err == nil {
		if prior.Prepared != prepared || prior.Record.Actor != r.WorkerActor {
			return binding, fault(api.CodeConflict, "review prepared worker was replaced")
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
	event, err := s.reviewEvent(r, "identity.bound", record)
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
	worker.ConsumedBy, worker.Generation = record.ID, worker.Generation+1
	if err := put(ctx, tx, "worker_lease", worker.ID, worker.Generation, worker); err != nil {
		return binding, err
	}
	if err := tx.Commit(); err != nil {
		return binding, err
	}
	s.notifyChanged()
	return binding, nil
}

func (s *Service) RecordReviewProcess(ctx context.Context, scope api.Scope, lease api.EffectLease, process api.ProcessHandle) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.reviewClaim(ctx, s.db, scope, lease)
	if err != nil {
		return err
	}
	binding, err := s.launchBinding(ctx, s.db, r.WorkerLaunchID)
	if err != nil {
		return err
	}
	if process.ID != binding.Record.ID || process.Target != binding.Record.Target || process.ContainmentID != binding.Record.ContainmentID || process.Generation != binding.Record.ProcessGeneration || r.Process.ID != "" && r.Process != process {
		return fault(api.CodeIntegrity, "review process differs from its committed prepared identity")
	}
	r.Process = process
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := s.saveReview(ctx, tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) reviewEvent(r reviewRecord, kind api.EventKind, body any) (api.Event, error) {
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

func (s *Service) reviewPrincipal(ctx context.Context, db queryer, endpoint api.InstalledBinding, peer api.PeerFacts, operation api.WorkerOperation) (p api.WorkerPrincipal, resultErr error) {
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='review_job' AND json_extract(data,'$.Job.Lease.ID')=?", string(endpoint.WorkerLeaseID)).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return p, fault(api.CodeNotFound, "worker has no retained fixed job")
		}
		return p, err
	}
	var r reviewRecord
	if err := decodeStored(raw, &r); err != nil {
		return p, err
	}
	if r.Endpoint == nil || !sameValue(*r.Endpoint, endpoint) {
		return p, fault(api.CodeUnauthenticated, "review worker endpoint changed")
	}
	if r.Retirement != nil {
		return p, fault(api.CodeForbidden, "retired archive worker has no remaining socket authority")
	}
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: r.Claim.Record.ClaimantID}}
	if _, err := s.reviewClaim(ctx, db, scope, r.Claim); err != nil {
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
		return p, fault(api.CodeUnauthenticated, "review worker is outside its native distinct allocation")
	}
	var worker api.WorkerLease
	if err := storedProjection(ctx, db, "worker_lease", r.Job.Lease.ID, &worker); err != nil {
		return p, err
	}
	want := r.Job.Lease
	want.ConsumedBy, want.Generation = record.ID, worker.Generation
	if worker != want || worker.Generation < r.Job.Lease.Generation+1 || worker.Generation > r.Job.Lease.Generation+2 {
		return p, fault(api.CodeConflict, "review worker lease changed")
	}
	boot, _, found := strings.Cut(record.ProcessGeneration, ":")
	peerBoot, _, peerFound := strings.Cut(peer.ProcessGeneration, ":")
	if !found || !peerFound || boot == "" || boot != peerBoot {
		return p, fault(api.CodeContainmentUnknown, "review worker native boot differs")
	}
	want.Generation = r.Job.Lease.Generation + 1
	p = api.WorkerPrincipal{StageID: r.Job.ID, Lease: want, Record: record, Endpoint: endpoint, Peer: peer, BootID: boot, AllocationGeneration: endpoint.InstallationGeneration, Claim: r.Claim, CancellationEpoch: r.Job.Intent.CancellationEpoch}
	return p, api.ValidateWorkerPrincipal(p, endpoint, peer, operation, s.deps.Clock.Now())
}
