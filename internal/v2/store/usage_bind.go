package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) UsageHandoff(ctx context.Context, scope api.Scope, lease api.EffectLease, allocation api.HelperLease, endpoint api.InstalledBinding, injection api.Injection) (handoff api.PreparedSpecHandoff, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stage, err := s.usageClaim(ctx, s.db, scope, lease, true)
	if err != nil {
		return handoff, err
	}
	n := stage.Native
	if n == nil {
		return handoff, fault(api.CodePrerequisite, "usage has no writer-reserved native worker")
	}
	if n.Handoff != nil {
		if n.Allocation != allocation || n.Endpoint == nil || !sameValue(*n.Endpoint, endpoint) || !sameValue(n.Handoff.Spec.Injection, injection) {
			return handoff, fault(api.CodeConflict, "usage replay changed its original native handoff")
		}
		handoff = *n.Handoff
		handoff.Cause.Actor = scope.Actor
		return handoff, nil
	}
	job := stage.Job
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", job.Lease.Target.LifeID, &lane); err != nil {
		return handoff, err
	}
	agent, err := s.launchBinding(ctx, s.db, lane.LaunchID)
	if err != nil {
		return handoff, err
	}
	if allocation.UID == 0 || allocation.GID == 0 || allocation.UID == agent.Record.HostUID || allocation.ID == agent.Record.UIDLeaseID || allocation.ContainmentID == agent.Record.ContainmentID ||
		endpoint.Class != api.EndpointWorker || endpoint.LaunchID != n.ID || endpoint.WorkerLeaseID != job.Lease.ID || endpoint.Target == nil || *endpoint.Target != job.Lease.Target ||
		endpoint.EndpointGeneration != allocation.EndpointGeneration || injection.Target != job.Lease.Target || injection.Outcome != "prepared" {
		return handoff, fault(api.CodeConflict, "usage handoff changed its distinct native allocation or selected injection")
	}
	if err := api.ValidateBinding(endpoint, scope.Config, job.Runtime.Executable.Version); err != nil {
		return handoff, err
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, s.db, "grants", job.Lease.GrantSetID, &grants); err != nil {
		return handoff, err
	}
	if grants.Revoked || !sameValue(grants, job.Grants) || grants.ID == lane.GrantSetID || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return handoff, fault(api.CodeConflict, "usage worker grants changed")
	}
	id, err := wire.NewID()
	if err != nil {
		return handoff, err
	}
	spec := api.LaunchSpec{ID: id, Kind: "worker", LaunchID: n.ID, Target: job.Lease.Target, Worker: &n.Plan, RuntimeManifest: job.Lease.RuntimeManifest,
		UIDLeaseID: allocation.ID, Backend: endpoint.Backend, EndpointGeneration: allocation.EndpointGeneration, PolicyGeneration: grants.PolicyGeneration,
		Grants: grants, Budget: n.Plan.Budget, Injection: injection, Materialization: api.Materialization{GrantSetID: grants.ID, Objects: []api.MaterializedObject{}}}
	raw, err := canonicalValue(spec)
	if err != nil {
		return handoff, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return handoff, err
	}
	defer finish(tx, &resultErr)
	objectID, err := wire.NewID()
	if err != nil {
		return handoff, err
	}
	ref, err := s.retain(context.WithValue(ctx, dataObjectKey{}, s), tx, scope, api.ObjectWrite{ObjectKey: objectID, Class: "launch_spec", Bytes: raw,
		SHA256: api.Digest(hash(raw)), Origin: "service", ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: job.Lease.Target.LifeID, Audience: "private", Generation: 1}},
		job.Lease.OperationID, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return handoff, err
	}
	cause := *lease.Record.Effect.Context
	cause.Kind, cause.Actor = api.InternalHelperRegister, scope.Actor
	handoff = api.PreparedSpecHandoff{Config: scope.Config, Cause: cause, OperationID: job.Lease.OperationID, RequestID: stage.Job.Cause.CauseRequestID,
		Original: ref, Spec: spec, SpecSHA256: ref.SHA256}
	n.Handoff, n.Endpoint, n.Allocation = &handoff, &endpoint, allocation
	worker := job.Lease
	worker.ConsumedBy, worker.Generation = n.ID, worker.Generation+1
	if err := put(ctx, tx, "worker_lease", worker.ID, worker.Generation, worker); err != nil {
		return handoff, err
	}
	if err := saveUsage(ctx, tx, stage); err != nil {
		return handoff, err
	}
	return handoff, tx.Commit()
}

func (s *Service) BindUsageWorker(ctx context.Context, scope api.Scope, lease api.EffectLease, prepared api.PreparedLaunch) (binding api.LaunchBindingRequest, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stage, err := s.usageClaim(ctx, s.db, scope, lease, true)
	if err != nil {
		return binding, err
	}
	n := stage.Native
	if n == nil || n.Handoff == nil || n.Endpoint == nil || prepared.SpecSHA256 != n.Handoff.SpecSHA256 || prepared.Target != stage.Job.Lease.Target ||
		prepared.ContainmentID != n.Allocation.ContainmentID || prepared.EndpointGeneration != n.Allocation.EndpointGeneration || prepared.ID == "" || prepared.GateID == "" || prepared.ProcessGeneration == "" {
		return binding, fault(api.CodeConflict, "usage identity differs from its original prepared native gate")
	}
	prior, err := s.launchBinding(ctx, s.db, n.ID)
	if err == nil {
		if prior.Prepared != prepared || prior.Record.Actor != n.Actor {
			return binding, fault(api.CodeConflict, "usage worker identity was replaced")
		}
		return prior, nil
	}
	if !absent(err) {
		return binding, err
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", stage.Job.Lease.Target.LifeID, &lane); err != nil {
		return binding, err
	}
	grants := n.Handoff.Spec.Grants
	record := api.LaunchRecord{Kind: "worker", ID: n.ID, Config: scope.Config, Target: stage.Job.Lease.Target, Actor: n.Actor,
		RootLifeID: lane.RootLifeID, ParentLifeID: lane.ParentLifeID, StarterChain: append([]api.ID{}, lane.StarterChain...), StarterEventSeq: lane.StarterEventSeq,
		UIDLeaseID: n.Allocation.ID, HostUID: n.Allocation.UID, ContainmentID: n.Allocation.ContainmentID, ProcessGeneration: prepared.ProcessGeneration,
		GrantSetID: grants.ID, GrantsSHA256: grants.SHA256, PolicyGeneration: grants.PolicyGeneration, EndpointGeneration: n.Allocation.EndpointGeneration}
	raw, err := canonicalValue(record)
	if err != nil {
		return binding, err
	}
	eventBytes, err := json.Marshal(record)
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
	seq, err := appendPrivateEvent(ctx, tx, api.Event{Schema: api.SchemaVersion, ID: id, Config: scope.Config, Kind: "identity.bound", Actor: scope.Actor, RequestedBy: stage.Job.Cause.RequestedBy,
		RequestID: stage.Job.Cause.CauseRequestID, OperationID: stage.Job.Lease.OperationID, LifeID: lane.LifeID, Run: stage.Job.Lease.Target.Run, RootLifeID: lane.RootLifeID,
		ParentLifeID: lane.ParentLifeID, StarterChain: append([]api.ID{}, lane.StarterChain...), StarterEventSeq: lane.StarterEventSeq, Origin: "service", Payload: eventBytes},
		api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return binding, err
	}
	binding = api.LaunchBindingRequest{Record: record, Prepared: prepared, Identity: api.IdentityCommit{LaunchID: record.ID, EventID: id, CommittedSeq: seq, RecordSHA256: api.Digest(hash(raw))}}
	if err := put(ctx, tx, "launch", record.ID, 1, record); err != nil {
		return binding, err
	}
	if err := put(ctx, tx, "launch_binding", record.ID, 1, binding); err != nil {
		return binding, err
	}
	if err := put(ctx, tx, "endpoint", record.ID, 1, api.EndpointProjection{Binding: *n.Endpoint, Generation: 1}); err != nil {
		return binding, err
	}
	return binding, tx.Commit()
}
