package store

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/testjob"
)

// Staging retains inert immutable inputs. No worker lease/effect exists until
// Transact consumes the original proof and publishes that exact job atomically.
func (s *Service) StageChildTest(ctx context.Context, scope api.Scope, request api.TestChildRequest, grants api.GrantSet, subject api.ReviewSubject) (result testjob.Reservation, resultErr error) {
	s.mu.RLock()
	native, ok := s.reviewNative.(interface {
		TestCheckNames(context.Context, api.Scope, api.LifeRef) ([]string, error)
	})
	s.mu.RUnlock()
	if !ok {
		return result, fault(api.CodePrerequisite, "TestChild protected check selector is unavailable")
	}
	names, err := native.TestCheckNames(ctx, s.reviewScope(), request.Child)
	if err != nil {
		return result, err
	}
	if len(names) > 1 {
		return result, fault(api.CodeUnsupported, "one TestChild plan cannot stand in for multiple protected checks")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	var original api.TestChildRequest
	if scope.Request.Method != "grants.test-child" || api.DecodeObject(scope.Request.Params, &original) != nil || !sameValue(original, request) || request.Child != subject.Target {
		return result, fault(api.CodeForbidden, "TestChild staging changed the original request")
	}
	pending, err := s.lookupReceipt(ctx, s.db, scope, requestKey(scope.Request))
	if err != nil {
		return result, err
	}
	owned, err := s.ownsMutation(ctx, scope, requestKey(scope.Request), pending.Operation.ID)
	if err != nil {
		return result, err
	}
	if !owned || pending.Reply != nil || pending.Operation.Status != "pending" {
		return result, fault(api.CodeConflict, "TestChild lost its dispatcher reservation")
	}
	var frozen reviewFrozen
	if err := storedProjection(ctx, s.db, "review_snapshot", reviewSnapshotID(request.Child), &frozen); err != nil {
		return result, err
	}
	if frozen.Phase != "sealed" || !sameValue(frozen.Subject, subject) {
		return result, fault(api.CodeConflict, "TestChild selected another frozen run")
	}
	if err := s.reviewFreezeFence(ctx, s.db, frozen); err != nil {
		return result, err
	}
	var actual api.GrantSet
	if err := storedProjection(ctx, s.db, "grants", grants.ID, &actual); err != nil {
		return result, err
	}
	if !sameValue(actual, grants) || grants.ID != frozen.Lane.GrantSetID || grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return result, fault(api.CodeForbidden, "TestChild lost the exact current child grants")
	}
	reservation := func(r reviewRecord) testjob.Reservation {
		cause := api.InternalIntent{ID: r.Job.Lease.EffectID, Kind: api.InternalLifecycleEffect, Config: scope.Config, Actor: s.reviewScope().Actor,
			RequestedBy: scope.Actor, CauseOperationID: pending.Operation.ID, CauseRequestID: scope.Request.RequestID,
			EffectID: r.Job.Lease.EffectID, Target: request.Child, CancellationEpoch: frozen.Intent.CancellationEpoch}
		return testjob.Reservation{Job: r.Job, Effect: api.Effect{ID: cause.EffectID, OperationID: pending.Operation.ID, Context: &cause, Worker: &r.Job.Plan},
			Compare: []api.Compare{{Kind: api.CompareLane, ID: frozen.Lane.LifeID, Generation: frozen.Lane.Generation},
				{Kind: api.CompareGrants, ID: grants.ID, Generation: grants.Generation}}}
	}
	var r reviewRecord
	err = storedProjection(ctx, s.db, "review_job", pending.Operation.ID, &r)
	if err == nil {
		if r.Test == nil || !sameValue(r.Test.Request, request) || !sameValue(r.Request, scope.Request) || r.Scope.Actor != scope.Actor {
			return result, fault(api.CodeConflict, "TestChild retry changed its staged bytes")
		}
		return reservation(r), nil
	}
	if !absent(err) {
		return result, err
	}
	meta, raw, err := objectRow(ctx, s.db, request.TestPlan.ID)
	if err != nil {
		return result, err
	}
	var plan api.WorkerPlan
	if meta.Ref != request.TestPlan || api.DecodeObject(raw, &plan) != nil || plan.Kind != "test" || plan.Input != request.Candidate || plan.GrantSetID != grants.ID {
		return result, fault(api.CodeIntegrity, "TestChild lost its exact retained plan")
	}
	bound, err := s.launchBinding(ctx, s.db, frozen.Lane.LaunchID)
	if err != nil {
		return result, err
	}
	if bound.Recovery == nil {
		return result, fault(api.CodeIntegrity, "TestChild lacks its installed runtime")
	}
	meta, raw, err = objectRow(ctx, s.db, bound.Recovery.Handoff.Spec.RuntimeManifest.ID)
	if err != nil {
		return result, err
	}
	var runtime api.RuntimeManifest
	if meta.Ref != bound.Recovery.Handoff.Spec.RuntimeManifest || api.DecodeObject(raw, &runtime) != nil {
		return result, fault(api.CodeIntegrity, "TestChild runtime changed")
	}
	matched := false
	for _, object := range runtime.Objects {
		matched = matched || object.ID == plan.Executable.ID && object.Content.SHA256 == plan.Executable.SHA256 && object.Mode == 0555
	}
	if !matched || !withinTestBudget(plan.Budget, request.Budget) || !withinTestBudget(plan.Budget, bound.Recovery.Handoff.Spec.Budget) {
		return result, fault(api.CodeForbidden, "TestChild plan exceeds its enrolled executable or budget")
	}
	r = reviewRecord{Lane: frozen.Lane, Request: scope.Request, Scope: api.Scope{Config: scope.Config, Actor: scope.Actor, PolicyGeneration: scope.PolicyGeneration}}
	r.Job.Intent = archivejob.Intent{Request: api.ArchiveRequest{Target: request.Child, ExpectedGeneration: subject.Generation}, OperationID: pending.Operation.ID,
		EndEventID: subject.EndEventID, EndSeq: subject.EndSeq, CancellationEpoch: frozen.Intent.CancellationEpoch}
	for _, id := range []*api.ID{&r.Job.ID, &r.Job.Lease.ID, &r.Job.Lease.EffectID, &r.Grants.ID, &r.WorkerLaunchID, &r.WorkerActor.ID} {
		*id, err = wire.NewID()
		if err != nil {
			return result, err
		}
	}
	r.WorkerActor.Kind = "worker"
	r.Grants = api.GrantSet{ID: r.Grants.ID, LifeID: grants.LifeID, ParentLifeID: grants.LifeID, PolicyGeneration: grants.PolicyGeneration, Generation: 1,
		ExpiresAt: grants.ExpiresAt, Data: []api.DataGrant{}, Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	encoded, err := canonicalValue(r.Grants)
	if err != nil {
		return result, err
	}
	r.Grants.SHA256 = api.Digest(hash(encoded))
	r.Job.Lease = api.WorkerLease{ID: r.Job.Lease.ID, EffectID: r.Job.Lease.EffectID, Kind: "test", Target: request.Child, OperationID: pending.Operation.ID,
		RuntimeManifest: bound.Recovery.Handoff.Spec.RuntimeManifest, GrantSetID: r.Grants.ID, Generation: 1, ExpiresAt: grants.ExpiresAt}
	r.Test = &testjob.Input{Schema: "laneboss.test-input.v2", Request: request, Plan: plan, Subject: subject, Name: string(plan.Executable.ID)}
	// Protected administrator requirements choose the check name. A request
	// cannot supply a passing label, snapshot digest or verdict.
	if len(names) == 1 {
		r.Test.Name = names[0]
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	raw, err = canonicalValue(frozen.Freeze)
	if err != nil {
		return result, err
	}
	r.Job.Freeze, err = s.reviewBytes(ctx, tx, r, "manifest", raw)
	if err != nil {
		return result, err
	}
	raw, err = canonicalValue(r.Test)
	if err != nil {
		return result, err
	}
	r.Job.Lease.Input, err = s.reviewBytes(ctx, tx, r, "manifest", raw)
	if err != nil {
		return result, err
	}
	r.Job.Plan = api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", Executable: runtime.Bootstrap, Input: r.Job.Lease.Input,
		GrantSetID: r.Grants.ID, Budget: plan.Budget, Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(r.Job.Lease.ID)}}
	if err := put(ctx, tx, "grants", r.Grants.ID, 1, r.Grants); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "review_job", pending.Operation.ID, 1, r); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return reservation(r), nil
}

func withinTestBudget(a, b api.Budget) bool {
	return manifest.Budget(a) == nil && a.Currency == b.Currency && a.WallMS <= b.WallMS && a.CPUSeconds <= b.CPUSeconds && a.MemoryBytes <= b.MemoryBytes && a.Processes <= b.Processes && a.DiskBytes <= b.DiskBytes && a.SpendMicros <= b.SpendMicros
}

func (s *Service) checkTestTransaction(ctx context.Context, db queryer, input api.Transaction) error {
	if input.Scope.Request.Method != "grants.test-child" || input.Reply != nil && input.Reply.Error != nil {
		return nil
	}
	if len(input.Effects) != 1 || len(input.Writes.WorkerLeases) != 1 {
		return fault(api.CodeForbidden, "TestChild must commit its single retained native worker")
	}
	e := input.Effects[0]
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return err
	}
	if policy.Generation != input.Scope.PolicyGeneration {
		return fault(api.CodeConflict, "TestChild policy changed before atomic admission")
	}
	var r reviewRecord
	if err := storedProjection(ctx, db, "review_job", e.OperationID, &r); err != nil {
		return err
	}
	if r.Test == nil || !sameValue(r.Request, input.Scope.Request) || r.Scope.Actor != input.Scope.Actor || !reflect.DeepEqual(e.Worker, &r.Job.Plan) ||
		e.ID != r.Job.Lease.EffectID || input.Writes.WorkerLeases[0] != r.Job.Lease {
		return fault(api.CodeForbidden, "TestChild transaction changed its staged effect or lease")
	}
	return nil
}

func (s *Service) testAdmissionEvent(ctx context.Context, db queryer, input api.Transaction) (api.Event, error) {
	var r reviewRecord
	if err := storedProjection(ctx, db, "review_job", input.Effects[0].OperationID, &r); err != nil {
		return api.Event{}, err
	}
	return s.reviewEvent(r, "operation.accepted", api.OperationEvent{Operation: api.Operation{ID: r.Job.Intent.OperationID, Status: "pending", LifeID: r.Lane.LifeID, Run: r.Lane.Run}, RequestSHA256: input.Scope.Request.RequestSHA256})
}

func (s *Service) AdmittedChildTest(ctx context.Context, scope api.Scope, effect api.Effect) (archivejob.Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return archivejob.Job{}, err
	}
	var r reviewRecord
	if err := storedProjection(ctx, s.db, "review_job", effect.OperationID, &r); err != nil {
		return archivejob.Job{}, err
	}
	if r.Test == nil || r.Request.Method != "grants.test-child" || r.Job.Lease.Kind != "test" || effect.ID != r.Job.Lease.EffectID || effect.Worker == nil || !sameValue(*effect.Worker, r.Job.Plan) {
		return archivejob.Job{}, fault(api.CodeForbidden, "TestChild recovery changed its original native effect")
	}
	var saved storedReceipt
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM replies WHERE principal=? AND method=? AND key=?", principal(r.Scope), string(r.Request.Method), string(r.Request.IdempotencyKey)).Scan(&raw); err != nil {
		return archivejob.Job{}, err
	}
	if decodeStored(raw, &saved) != nil || saved.Receipt.Operation.ID != effect.OperationID || saved.Receipt.Reply == nil || saved.Receipt.Reply.Error != nil {
		return archivejob.Job{}, fault(api.CodeIntegrity, "TestChild recovery has no actual committed admission")
	}
	return r.Job, nil
}
