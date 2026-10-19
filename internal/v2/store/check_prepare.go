package store

import (
	"context"
	"reflect"
	"slices"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

func (s *Service) checkPending(ctx context.Context, scope api.Scope, request api.TestChildRequest) (api.MutationReceipt, error) {
	if err := s.scope(ctx, s.db, scope); err != nil {
		return api.MutationReceipt{}, err
	}
	var original api.TestChildRequest
	if scope.Request.Method != "grants.test-child" || scope.Actor.Kind != "lane" || scope.Actor.LifeID == request.Child.LifeID || scope.Connection == nil || scope.Frame == nil ||
		api.DecodeObject(scope.Request.Params, &original) != nil || original != request {
		return api.MutationReceipt{}, fault(api.CodeForbidden, "check requires its actual distinct child-test caller")
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return api.MutationReceipt{}, err
	}
	var framed api.Request
	if api.DecodeObject(scope.Frame.Bytes(), &framed) != nil || !sameValue(framed, scope.Request) {
		return api.MutationReceipt{}, fault(api.CodeUnauthenticated, "child test lost its original request frame")
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", request.Child.LifeID, &lane); err != nil {
		return api.MutationReceipt{}, err
	}
	if scope.Actor.Level <= lane.Level || !slices.Contains(lane.StarterChain, scope.Actor.LifeID) && lane.ParentLifeID != scope.Actor.LifeID {
		return api.MutationReceipt{}, fault(api.CodeForbidden, "check caller is outside the child's supervising tree")
	}
	retained, err := s.lookupReceipt(ctx, s.db, scope, requestKey(scope.Request))
	if err != nil {
		return retained, err
	}
	owned, err := s.ownsMutation(ctx, scope, requestKey(scope.Request), retained.Operation.ID)
	if err != nil {
		return retained, err
	}
	if !owned || retained.Reply != nil || retained.Operation.Status != "pending" {
		return retained, fault(api.CodeConflict, "child test lost its actual pending dispatcher operation")
	}
	return retained, nil
}

// PrepareCheckWorker uses the same native frozen subject and launch journal as
// the export verifier, but issues a distinct real test lease and fixed input.
func (s *Service) PrepareCheckWorker(ctx context.Context, caller, control api.Scope, request api.TestChildRequest, grants api.GrantSet) (job archivejob.Job, resultErr error) {
	s.mu.RLock()
	_, err := s.checkPending(ctx, caller, request)
	native := s.reviewNative
	s.mu.RUnlock()
	if err != nil {
		return job, err
	}
	if native == nil {
		return job, fault(api.CodePrerequisite, "native review freeze is not installed")
	}
	lane, err := s.Lane(ctx, control, request.Child)
	if err != nil {
		return job, err
	}
	binding, err := s.LaunchBinding(ctx, lane.LaunchID)
	if err != nil {
		return job, err
	}
	if binding.Recovery == nil {
		return job, fault(api.CodeIntegrity, "checker has no original capture binding")
	}
	if _, err := s.FrameCapture(ctx, control, binding.Recovery.Capture.ID); err != nil {
		return job, err
	}
	subject, err := s.ReviewSnapshot(ctx, control, request.Child)
	if err != nil {
		return job, err
	}
	required, err := native.RequiredReviewChecks(ctx, control, request.Child)
	if err != nil {
		return job, err
	}
	if !slices.Equal(required, []string{reviewjob.SnapshotIntegrity}) {
		return job, fault(api.CodeUnsupported, "protected check requirements have no installed fixed checker")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	retained, err := s.checkPending(ctx, caller, request)
	if err != nil {
		return job, err
	}
	var previous reviewRecord
	if err := storedProjection(ctx, s.db, "review_job", retained.Operation.ID, &previous); err == nil {
		if previous.Preparation == nil || previous.Preparation.Request != request || requestKey(previous.Request) != requestKey(caller.Request) {
			return job, fault(api.CodeIdempotencyConflict, "child test retry changed its original job")
		}
		return previous.Job, nil
	} else if !absent(err) {
		return job, err
	}
	var frozen reviewFrozen
	if err := storedProjection(ctx, s.db, "review_snapshot", reviewSnapshotID(request.Child), &frozen); err != nil {
		return job, err
	}
	if frozen.Phase != "sealed" || !sameValue(frozen.Subject, subject) {
		return job, fault(api.CodeIntegrity, "child test lost its measured frozen subject")
	}
	if err := s.reviewFreezeFence(ctx, s.db, frozen); err != nil {
		return job, err
	}
	var current api.GrantSet
	if err := storedProjection(ctx, s.db, "grants", frozen.Lane.GrantSetID, &current); err != nil {
		return job, err
	}
	if !sameValue(current, grants) || grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return job, fault(api.CodeConflict, "child test grants changed")
	}
	binding, err = s.launchBinding(ctx, s.db, frozen.Lane.LaunchID)
	if err != nil {
		return job, err
	}
	if binding.Recovery == nil {
		return job, fault(api.CodeIntegrity, "child test has no retained runtime")
	}
	var source api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", binding.Recovery.PlanID, &source); err != nil {
		return job, err
	}
	if source.Inputs == nil {
		return job, fault(api.CodeIntegrity, "child test lost its actual project source")
	}
	meta, raw, err := objectRow(ctx, s.db, binding.Recovery.Handoff.Spec.RuntimeManifest.ID)
	if err != nil {
		return job, err
	}
	var runtime api.RuntimeManifest
	if meta.Ref != binding.Recovery.Handoff.Spec.RuntimeManifest || meta.Origin != "service" || api.DecodeObject(raw, &runtime) != nil {
		return job, fault(api.CodeIntegrity, "child test runtime is not protected")
	}
	planMeta, planRaw, err := objectRow(ctx, s.db, request.TestPlan.ID)
	if err != nil {
		return job, err
	}
	candidate, _, err := objectRow(ctx, s.db, request.Candidate.ID)
	if err != nil {
		return job, err
	}
	var declared api.WorkerPlan
	if planMeta.Ref != request.TestPlan || candidate.Ref != request.Candidate || candidate.ACL.Owner.Kind != "lane" || candidate.ACL.Owner.LifeID != request.Child.LifeID || candidate.ACL.LifeID != request.Child.LifeID ||
		api.DecodeObject(planRaw, &declared) != nil || declared.Schema != "laneboss.worker-plan.v2" || declared.Kind != "test" || declared.Executable != runtime.Bootstrap || declared.Input != request.Candidate || declared.GrantSetID != grants.ID ||
		!slices.Equal(declared.Argv, []string{"laneboss", "check", reviewjob.SnapshotIntegrity}) || manifest.Budget(declared.Budget) != nil || declared.Budget != request.Budget || declared.Budget.WallMS > 60000 || declared.Budget.CPUSeconds > 10 || declared.Budget.MemoryBytes > 256<<20 || declared.Budget.Processes > 16 || declared.Budget.DiskBytes > 4<<20 || declared.Budget.SpendMicros != 0 {
		return job, fault(api.CodeForbidden, "child test differs from its owned candidate and installed fixed declaration")
	}
	r := reviewRecord{Scope: api.Scope{Config: caller.Config, Actor: caller.Actor, PolicyGeneration: caller.PolicyGeneration}, Request: caller.Request, Lane: frozen.Lane,
		Input: reviewjob.Input{Subject: subject, Required: required, Base: source.Inputs.Sources.Project.Object}}
	r.Preparation = &reviewjob.CheckInput{Schema: "laneboss.check-input.v2", Subject: subject, Request: request, Plan: declared, Required: required, Base: r.Input.Base}
	for _, id := range []*api.ID{&r.Job.ID, &r.Job.Lease.ID, &r.Job.Lease.EffectID, &r.Grants.ID, &r.WorkerLaunchID, &r.WorkerActor.ID} {
		*id, err = wire.NewID()
		if err != nil {
			return job, err
		}
	}
	r.WorkerActor.Kind = "worker"
	expiry := s.deps.Clock.Now().Add(time.Duration(request.Budget.WallMS) * time.Millisecond)
	bound, err := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt))
	if err != nil {
		return job, err
	}
	if bound.Before(expiry) {
		expiry = bound
	}
	r.Grants = api.GrantSet{ID: r.Grants.ID, LifeID: request.Child.LifeID, ParentLifeID: request.Child.LifeID, Generation: 1, PolicyGeneration: caller.PolicyGeneration, ExpiresAt: api.Timestamp(expiry.UTC().Format(timeFormat)),
		Data: []api.DataGrant{}, Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	raw, err = canonicalValue(r.Grants)
	if err != nil {
		return job, err
	}
	r.Grants.SHA256 = api.Digest(hash(raw))
	r.Job.Intent = archivejob.Intent{Request: api.ArchiveRequest{Target: request.Child, ExpectedGeneration: subject.Generation}, OperationID: retained.Operation.ID, EndEventID: subject.EndEventID, EndSeq: subject.EndSeq, CancellationEpoch: frozen.Intent.CancellationEpoch}
	r.Job.Lease = api.WorkerLease{ID: r.Job.Lease.ID, Kind: "test", Target: request.Child, OperationID: retained.Operation.ID, EffectID: r.Job.Lease.EffectID, RuntimeManifest: binding.Recovery.Handoff.Spec.RuntimeManifest, GrantSetID: r.Grants.ID, Generation: 1, ExpiresAt: r.Grants.ExpiresAt}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return job, err
	}
	defer finish(tx, &resultErr)
	raw, err = canonicalValue(frozen.Freeze)
	if err != nil {
		return job, err
	}
	r.Job.Freeze, err = s.reviewBytes(ctx, tx, r, "manifest", raw)
	if err != nil {
		return job, err
	}
	raw, err = canonicalValue(r.Preparation)
	if err != nil {
		return job, err
	}
	r.Job.Lease.Input, err = s.reviewBytes(ctx, tx, r, "manifest", raw)
	if err != nil {
		return job, err
	}
	r.Job.Plan = api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", Executable: runtime.Bootstrap, GrantSetID: r.Grants.ID, Input: r.Job.Lease.Input, Budget: declared.Budget,
		Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(r.Job.Lease.ID)}}
	causeID, err := wire.NewID()
	if err != nil {
		return job, err
	}
	cause := api.InternalIntent{ID: causeID, Kind: api.InternalLifecycleEffect, Config: caller.Config, Actor: control.Actor, RequestedBy: caller.Actor, CauseOperationID: retained.Operation.ID, CauseRequestID: caller.Request.RequestID,
		EffectID: r.Job.Lease.EffectID, Target: request.Child, CancellationEpoch: frozen.Intent.CancellationEpoch}
	if err := insertLaunchEffect(ctx, tx, api.Effect{ID: cause.EffectID, OperationID: retained.Operation.ID, Context: &cause, Worker: &r.Job.Plan}); err != nil {
		return job, err
	}
	for _, value := range []struct {
		kind  string
		id    api.ID
		value any
	}{{"grants", r.Grants.ID, r.Grants}, {"worker_lease", r.Job.Lease.ID, r.Job.Lease}, {"review_job", retained.Operation.ID, r}} {
		if err := put(ctx, tx, value.kind, value.id, 1, value.value); err != nil {
			return job, err
		}
	}
	if err := tx.Commit(); err != nil {
		return job, err
	}
	s.notifyChanged()
	return r.Job, nil
}

func validateCheckOutput(r reviewRecord, raw []byte) error {
	var output reviewjob.CheckResult
	in := r.Preparation
	if in == nil || api.DecodeObject(raw, &output) != nil || !sameDataBytes(raw, output) || output.Schema != "laneboss.check-result.v2" || !reflect.DeepEqual(output.Subject, in.Subject) || output.Candidate != in.Request.Candidate ||
		output.Diff.Schema != "laneboss.review-diff.v2" || output.Diff.Base != in.Base.SHA256 || output.Diff.Current != in.Subject.Snapshot.SHA256 || len(output.Checks) != len(in.Required) {
		return fault(api.CodeIntegrity, "test result changed its actual frozen input")
	}
	for i, check := range output.Checks {
		if check.Schema != "laneboss.check.v2" || check.Name != in.Required[i] || check.Target != r.Job.Lease.Target || check.EndSeq != in.Subject.EndSeq || check.SnapshotSHA256 != in.Subject.Snapshot.SHA256 || check.WorkerLeaseID != r.Job.Lease.ID || check.OperationID != r.Job.Intent.OperationID || check.ExitCode != 0 {
			return fault(api.CodeIntegrity, "test result changed its original checker or job")
		}
	}
	return nil
}
