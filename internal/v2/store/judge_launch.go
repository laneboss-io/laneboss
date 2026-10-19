package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/judge/job"
)

func (s *Service) judgeJob(ctx context.Context, db queryer, stage judgeNative) (job.Job, error) {
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", stage.Execution.Intent.Target.LifeID, &lane); err != nil {
		return job.Job{}, err
	}
	parent, err := s.launchBinding(ctx, db, lane.LaunchID)
	if err != nil {
		return job.Job{}, err
	}
	return job.Job{Execution: stage.Execution, Lease: stage.Worker, Plan: stage.Plan, Claim: stage.Claim,
		LaunchID: stage.LaunchID, Actor: stage.Actor, ParentLeaseID: parent.Record.UIDLeaseID}, nil
}

func (s *Service) JudgeWorkerJob(ctx context.Context, scope api.Scope, e api.JudgeExecution) (job.Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stage, err := s.judgeNativeClaim(ctx, s.db, scope, e)
	if err != nil {
		return job.Job{}, err
	}
	return s.judgeJob(ctx, s.db, stage)
}

func (s *Service) JudgeWorkerLookup(ctx context.Context, scope api.Scope, leaseID api.ID) (job.Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stage, err := judgeNativeByLease(ctx, s.db, leaseID)
	if err != nil {
		return job.Job{}, err
	}
	e := stage.Execution
	e.Acquired = true
	if _, err := s.judgeExecutionClaim(ctx, s.db, scope, e); err != nil {
		return job.Job{}, err
	}
	return s.judgeJob(ctx, s.db, stage)
}

func (s *Service) JudgeHandoff(ctx context.Context, scope api.Scope, e api.JudgeExecution, allocation api.HelperLease, endpoint api.InstalledBinding) (h api.PreparedSpecHandoff, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stage, err := s.judgeNativeClaim(ctx, s.db, scope, e)
	if err != nil {
		return h, err
	}
	if stage.Handoff != nil {
		if stage.Allocation != allocation || stage.Endpoint == nil || !sameValue(*stage.Endpoint, endpoint) {
			return h, fault(api.CodeConflict, "judge retry changed its original native allocation")
		}
		return *stage.Handoff, nil
	}
	job, err := s.judgeJob(ctx, s.db, stage)
	if err != nil {
		return h, err
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", e.Intent.Target.LifeID, &lane); err != nil {
		return h, err
	}
	bound, err := s.launchBinding(ctx, s.db, lane.LaunchID)
	if err != nil {
		return h, err
	}
	if allocation.UID == 0 || allocation.GID == 0 || allocation.UID == bound.Record.HostUID || allocation.ID == job.ParentLeaseID ||
		allocation.ContainmentID == bound.Record.ContainmentID || endpoint.Class != api.EndpointWorker || endpoint.LaunchID != stage.LaunchID ||
		endpoint.WorkerLeaseID != stage.Worker.ID || endpoint.Target == nil || *endpoint.Target != stage.Worker.Target ||
		endpoint.Socket != "/runtime/laneboss-worker.sock" || endpoint.EndpointGeneration != allocation.EndpointGeneration ||
		endpoint.ArtifactSHA256 != stage.Plan.Executable.SHA256 {
		return h, fault(api.CodeForbidden, "judge handoff differs from its distinct native worker")
	}
	if err := api.ValidateBinding(endpoint, scope.Config, stage.Plan.Executable.Version); err != nil {
		return h, err
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, s.db, "grants", stage.Worker.GrantSetID, &grants); err != nil {
		return h, err
	}
	id, err := wire.NewID()
	if err != nil {
		return h, err
	}
	spec := api.LaunchSpec{Kind: "worker", ID: id, LaunchID: stage.LaunchID, Target: stage.Worker.Target,
		Backend: endpoint.Backend, UIDLeaseID: allocation.ID, Worker: &stage.Plan, Grants: grants, Budget: stage.Plan.Budget,
		EndpointGeneration: allocation.EndpointGeneration, RuntimeManifest: stage.Worker.RuntimeManifest, PolicyGeneration: grants.PolicyGeneration,
		Materialization: api.Materialization{GrantSetID: grants.ID, Objects: []api.MaterializedObject{}},
		Injection: api.Injection{Target: stage.Worker.Target, Outcome: "prepared", SlotIDs: []api.ID{}, TaskSecretNames: []string{},
			TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}}}
	raw, err := canonicalValue(spec)
	if err != nil {
		return h, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return h, err
	}
	defer finish(tx, &resultErr)
	ref, err := s.retain(context.WithValue(ctx, dataObjectKey{}, s), tx, scope,
		api.ObjectWrite{ObjectKey: id, Class: "launch_spec", Bytes: raw, SHA256: api.Digest(hash(raw)), Origin: "service",
			ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: spec.Target.LifeID, Audience: "private", Generation: 1}},
		stage.Worker.OperationID, e.ReservedAt)
	if err != nil {
		return h, err
	}
	cause := *stage.Claim.Record.Effect.Context
	cause.Kind = api.InternalHelperRegister
	h = api.PreparedSpecHandoff{Config: scope.Config, Cause: cause, OperationID: stage.Worker.OperationID,
		RequestID: e.Intent.CauseRequestID, Original: ref, Spec: spec, SpecSHA256: ref.SHA256}
	stage.Allocation, stage.Endpoint, stage.Handoff = allocation, &endpoint, &h
	lease := stage.Worker
	lease.ConsumedBy, lease.Generation = stage.LaunchID, lease.Generation+1
	if err := put(ctx, tx, "worker_lease", lease.ID, lease.Generation, lease); err != nil {
		return h, err
	}
	if err := saveJudgeNative(ctx, tx, stage); err != nil {
		return h, err
	}
	return h, tx.Commit()
}

func (s *Service) BindJudgeWorker(ctx context.Context, scope api.Scope, e api.JudgeExecution, prepared api.PreparedLaunch) (binding api.LaunchBindingRequest, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stage, err := s.judgeNativeClaim(ctx, s.db, scope, e)
	if err != nil {
		return binding, err
	}
	if stage.Handoff == nil || stage.Endpoint == nil || prepared.SpecSHA256 != stage.Handoff.SpecSHA256 ||
		prepared.Target != stage.Worker.Target || prepared.ContainmentID != stage.Allocation.ContainmentID ||
		prepared.EndpointGeneration != stage.Allocation.EndpointGeneration || prepared.ProcessGeneration == "" {
		return binding, fault(api.CodeConflict, "judge identity changed its original prepared native gate")
	}
	if prior, err := s.launchBinding(ctx, s.db, stage.LaunchID); err == nil {
		if prior.Prepared != prepared || prior.Record.Actor != stage.Actor {
			return binding, fault(api.CodeConflict, "judge worker identity was replaced")
		}
		return prior, nil
	} else if !absent(err) {
		return binding, err
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", stage.Worker.Target.LifeID, &lane); err != nil {
		return binding, err
	}
	grants := stage.Handoff.Spec.Grants
	record := api.LaunchRecord{Kind: "worker", ID: stage.LaunchID, Config: scope.Config, Target: stage.Worker.Target, Actor: stage.Actor,
		RootLifeID: lane.RootLifeID, ParentLifeID: lane.ParentLifeID, StarterChain: append([]api.ID{}, lane.StarterChain...), StarterEventSeq: lane.StarterEventSeq,
		UIDLeaseID: stage.Allocation.ID, HostUID: stage.Allocation.UID, ContainmentID: stage.Allocation.ContainmentID, ProcessGeneration: prepared.ProcessGeneration,
		GrantSetID: grants.ID, GrantsSHA256: grants.SHA256, PolicyGeneration: grants.PolicyGeneration, EndpointGeneration: stage.Allocation.EndpointGeneration}
	raw, err := canonicalValue(record)
	if err != nil {
		return binding, err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return binding, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return binding, err
	}
	defer finish(tx, &resultErr)
	id, err := wire.NewID()
	if err != nil {
		return binding, err
	}
	seq, err := appendPrivateEvent(ctx, tx, api.Event{Schema: api.SchemaVersion, ID: id, Config: scope.Config, Kind: "identity.bound",
		Actor: scope.Actor, RequestedBy: e.Intent.RequestedBy, RequestID: e.Intent.CauseRequestID, OperationID: stage.Worker.OperationID,
		LifeID: lane.LifeID, Run: lane.Run, RootLifeID: lane.RootLifeID, ParentLifeID: lane.ParentLifeID,
		StarterChain: append([]api.ID{}, lane.StarterChain...), StarterEventSeq: lane.StarterEventSeq, Origin: "service", Payload: payload},
		api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return binding, err
	}
	binding = api.LaunchBindingRequest{Record: record, Prepared: prepared,
		Identity: api.IdentityCommit{LaunchID: record.ID, EventID: id, CommittedSeq: seq, RecordSHA256: api.Digest(hash(raw))}}
	for _, item := range []struct {
		kind string
		data any
	}{{"launch", record}, {"launch_binding", binding}, {"endpoint", api.EndpointProjection{Binding: *stage.Endpoint, Generation: 1}}} {
		if err := put(ctx, tx, item.kind, record.ID, 1, item.data); err != nil {
			return binding, err
		}
	}
	return binding, tx.Commit()
}

func (s *Service) RecordJudgeProcess(ctx context.Context, scope api.Scope, e api.JudgeExecution, process api.ProcessHandle) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stage, err := s.judgeNativeClaim(ctx, s.db, scope, e)
	if err != nil {
		return err
	}
	binding, err := s.launchBinding(ctx, s.db, stage.LaunchID)
	if err != nil || process.ID != binding.Record.ID || process.Target != binding.Record.Target ||
		process.ContainmentID != binding.Record.ContainmentID || process.Generation != binding.Record.ProcessGeneration {
		return fault(api.CodeIntegrity, "judge process differs from its committed native identity")
	}
	if stage.Process != nil && *stage.Process != process {
		return fault(api.CodeConflict, "judge process was already bound to another lifetime")
	}
	stage.Process = &process
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := saveJudgeNative(ctx, tx, stage); err != nil {
		return err
	}
	return tx.Commit()
}
