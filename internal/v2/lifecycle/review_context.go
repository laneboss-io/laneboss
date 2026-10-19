package lifecycle

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// ReviewControl is an installed service boundary, never a public request field.
// The shared fix-10 DTOs do not expose the service's job/snapshot preparation
// port. Missing wiring refuses; an upload cannot provide these authority facts.
// This Go-only handoff is recorded as an exact integration request.
type ReviewControl interface {
	PrepareReview(context.Context, api.Scope, api.ReviewRequest, api.Generation, api.ID, api.Sequence) (api.ReviewVerifyRequest, error)
	ResolveReview(context.Context, api.Scope, api.LifeRef) (api.ReviewSubject, []string, error)
}

func (s *Service) reviewSubject(ctx context.Context, scope api.Scope, lane api.Lane, facts runFacts) (api.ReviewSubject, []string, error) {
	if absent(s.deps.ReviewControl) {
		return api.ReviewSubject{}, nil, api.NotImplemented("lb-v2-service", "installed review subject and worker preparation")
	}
	subject, required, err := s.deps.ReviewControl.ResolveReview(ctx, scope, api.LifeRef{LifeID: lane.LifeID, Run: lane.Run})
	if err != nil {
		return api.ReviewSubject{}, nil, failure(err)
	}
	if subject.Target != (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) || subject.LaunchID != facts.launchID ||
		subject.EndEventID != facts.endID || subject.EndSeq != facts.endSeq || subject.SessionID != lane.Session.ID ||
		!validGeneration(subject.Generation) || subject.InventorySeq < subject.EndSeq ||
		!validBlob(subject.Snapshot) || subject.Snapshot.Class != "manifest" || !validID(subject.CaptureBindingID) || required == nil {
		return api.ReviewSubject{}, nil, integrity("review subject differs from the actual ended run")
	}
	if subject.Generation != lane.Generation && !(lane.State == "accepted" && subject.Generation+1 == lane.Generation) {
		return api.ReviewSubject{}, nil, integrity("review subject has a stale life generation")
	}
	if _, err := s.reviewCaptureState(ctx, scope, subject); err != nil {
		return api.ReviewSubject{}, nil, err
	}
	seen := map[string]bool{}
	for _, name := range required {
		if !validID(api.ID(name)) || seen[name] {
			return api.ReviewSubject{}, nil, integrity("protected review requirements are invalid")
		}
		seen[name] = true
	}
	return subject, append([]string{}, required...), nil
}

func (s *Service) verifyReviewLease(ctx context.Context, scope api.Scope, request api.ReviewRequest, lane api.Lane, facts runFacts,
	subject api.ReviewSubject) (api.ReviewVerifyRequest, error) {
	if absent(s.deps.ReviewControl) {
		return api.ReviewVerifyRequest{}, api.NotImplemented("lb-v2-service", "installed review worker preparation")
	}
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	original, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		return api.ReviewVerifyRequest{}, failure(err)
	}
	if !receiptMatches(scope, key, original) || original.Reply != nil || !validID(original.Operation.ID) || original.Operation.Status != "pending" {
		return api.ReviewVerifyRequest{}, integrity("review worker changed the original dispatcher operation")
	}
	owned, err := s.ownsMutation(ctx, scope, key, original)
	if err != nil {
		return api.ReviewVerifyRequest{}, err
	}
	if !owned {
		return api.ReviewVerifyRequest{}, integrity("mutation cannot complete another executor's reservation")
	}
	prepared, err := s.deps.ReviewControl.PrepareReview(ctx, scope, request, lane.Generation, facts.endID, facts.endSeq)
	if err != nil {
		return api.ReviewVerifyRequest{}, failure(err)
	}
	lease := prepared.Lease
	if original.Operation.ID != lease.OperationID {
		return api.ReviewVerifyRequest{}, integrity("review worker changed the original dispatcher operation")
	}
	if !reflect.DeepEqual(prepared.Request, request) || prepared.ExpectedGeneration != lane.Generation ||
		prepared.EndEventID != facts.endID || prepared.EndSeq != facts.endSeq || lease.Target != request.Target ||
		lease.Kind != "test" && lease.Kind != "export" || !validID(lease.ID) || !validID(lease.OperationID) || !validID(lease.EffectID) ||
		lease.GrantSetID != lane.GrantSetID || !validGeneration(lease.Generation) || !validBlob(lease.RuntimeManifest) || lease.RuntimeManifest.Class != "manifest" {
		return api.ReviewVerifyRequest{}, integrity("review worker handoff differs from its frozen subject")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
	if err != nil || !s.deps.Clock.Now().Before(expires) {
		return api.ReviewVerifyRequest{}, problem(api.CodeConflict, "review worker lease expired", "Reconcile the original verifier job; do not replace its identity.")
	}
	retained, err := s.deps.Store.WorkerLease(ctx, scope, lease.ID)
	if err != nil {
		return api.ReviewVerifyRequest{}, failure(err)
	}
	if !reflect.DeepEqual(retained, lease) {
		return api.ReviewVerifyRequest{}, integrity("review worker lease is not the retained service job")
	}
	meta, err := s.deps.Store.ObjectMetadata(ctx, scope, lease.Input.ID)
	if err != nil {
		return api.ReviewVerifyRequest{}, failure(err)
	}
	if meta.SourceOperationID != lease.OperationID || meta.Origin != "service" && meta.Origin != "worker" {
		allowAndLog("review_input_provenance")
	}
	if _, err := s.readBlob(ctx, scope, lease.RuntimeManifest); err != nil {
		return api.ReviewVerifyRequest{}, err
	}
	raw, err := s.readBlob(ctx, scope, lease.Input)
	if err != nil {
		return api.ReviewVerifyRequest{}, err
	}
	var frozen api.ReviewSubject
	if api.DecodeObject(raw, &frozen) != nil {
		var input reviewjob.Input
		if api.DecodeObject(raw, &input) != nil || input.Schema != "laneboss.review-input.v2" ||
			!reflect.DeepEqual(input.Request, request) || input.Required == nil {
			return api.ReviewVerifyRequest{}, integrity("review worker input changed its frozen subject")
		}
		frozen = input.Subject
	}
	if !reflect.DeepEqual(frozen, subject) {
		return api.ReviewVerifyRequest{}, integrity("review worker input changed its frozen subject")
	}
	return prepared, nil
}

func (s *Service) readReviewEvidence(ctx context.Context, scope api.Scope, evidence api.ReviewEvidence) error {
	capture, err := s.reviewCaptureState(ctx, scope, evidence.Subject)
	if err != nil {
		return err
	}
	for _, stream := range evidence.Inventory.Streams {
		found := false
		for _, position := range capture.Positions {
			if position.StreamID == stream.StreamID {
				if position.NextOffset != stream.EndOffset || stream.EOF && !position.EOF {
					return integrity("review stream range or EOF differs from retained primary capture")
				}
				found = true
			}
		}
		if !found {
			return integrity("review stream has no retained primary position")
		}
	}
	verifier, err := s.deps.Store.WorkerLease(ctx, scope, evidence.VerifierLeaseID)
	if err != nil {
		return failure(err)
	}
	if verifier.ID != evidence.VerifierLeaseID || verifier.Target != evidence.Subject.Target || verifier.Kind != "test" && verifier.Kind != "export" {
		return integrity("review evidence has no retained verifier job")
	}
	if err := s.reviewJob(ctx, scope, verifier, evidence.Subject, true); err != nil {
		return err
	}
	if err := s.reviewExecution(ctx, scope, verifier, evidence.Subject); err != nil {
		return err
	}
	refs := []api.BlobRef{evidence.Subject.Snapshot, evidence.Diff, evidence.Inventory.Manifest, evidence.Inventory.ToolRecords}
	for _, check := range evidence.Checks {
		refs = append(refs, check.Receipt)
		lease, err := s.deps.Store.WorkerLease(ctx, scope, check.WorkerLeaseID)
		if err != nil {
			return failure(err)
		}
		if lease.ID != check.WorkerLeaseID || lease.Target != evidence.Subject.Target || lease.OperationID != check.OperationID || lease.Kind != "test" {
			return integrity("review check lost its actual worker or operation")
		}
		if err := s.reviewJob(ctx, scope, lease, evidence.Subject, false); err != nil {
			return err
		}
		if err := s.reviewExecution(ctx, scope, lease, evidence.Subject); err != nil {
			return err
		}
		meta, err := s.deps.Store.ObjectMetadata(ctx, scope, check.Receipt.ID)
		if err != nil {
			return failure(err)
		}
		if meta.SourceOperationID != check.OperationID {
			allowAndLog("review_check_provenance")
		}
	}
	for _, resolution := range evidence.Resolutions {
		refs = append(refs, resolution.Evidence)
	}
	for _, ref := range refs {
		meta, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
		if err != nil {
			return failure(err)
		}
		if meta.Origin != "service" && meta.Origin != "worker" || !validID(meta.SourceOperationID) {
			allowAndLog("review_evidence_provenance")
		}
		if (ref == evidence.Diff || ref == evidence.Inventory.Manifest || ref == evidence.Inventory.ToolRecords) && meta.SourceOperationID != verifier.OperationID {
			allowAndLog("review_verifier_provenance")
		}
		if err := s.readReviewObject(ctx, scope, ref); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reviewCaptureState(ctx context.Context, scope api.Scope, subject api.ReviewSubject) (api.CaptureState, error) {
	capture, err := s.deps.Store.CaptureState(ctx, scope, subject.CaptureBindingID)
	if err != nil {
		return api.CaptureState{}, failure(err)
	}
	binding := capture.Binding
	if api.ValidateCaptureBinding(binding) != nil || binding.ID != subject.CaptureBindingID || binding.Status != "registered" ||
		binding.Config != scope.Config || binding.Target != subject.Target || binding.LaunchID != subject.LaunchID ||
		!reflect.DeepEqual(binding.Streams, subject.Streams) || !validGeneration(capture.Generation) || capture.LastSeq > subject.InventorySeq {
		return api.CaptureState{}, integrity("review subject has no matching retained primary capture")
	}
	seen := map[api.ID]bool{}
	for _, position := range capture.Positions {
		if seen[position.StreamID] || position.NextOffset < 0 || uint64(position.NextOffset) > maxInteger {
			return api.CaptureState{}, integrity("review primary capture has invalid retained positions")
		}
		seen[position.StreamID] = true
	}
	return capture, nil
}

func (s *Service) readReviewObject(ctx context.Context, scope api.Scope, ref api.BlobRef) error {
	_, err := s.readBlob(ctx, scope, ref)
	return err
}

func (s *Service) reviewJob(ctx context.Context, scope api.Scope, lease api.WorkerLease, subject api.ReviewSubject, verifier bool) error {
	operation, err := s.deps.Store.Operation(ctx, scope, lease.OperationID)
	if err != nil {
		return failure(err)
	}
	pendingVerifier := verifier && scope.Request.Method == "lane.review" && (operation.Status == "pending" || operation.Status == "running")
	if operation.ID != lease.OperationID || operation.Status != "succeeded" && !pendingVerifier || operation.Error != nil ||
		(!pendingVerifier || operation.LifeID != "" || operation.Run != 0) &&
			(operation.LifeID != subject.Target.LifeID || operation.Run != subject.Target.Run) {
		return integrity("review job has no successful run-correlated operation")
	}
	return nil
}

func (s *Service) reviewExecution(ctx context.Context, scope api.Scope, lease api.WorkerLease, subject api.ReviewSubject) error {
	// A pending public review operation is not a worker execution. Its fixed
	// child effect must already retain the actual consumed identity, successful
	// terminal observation and authenticated result before evidence can count.
	if !validID(lease.ConsumedBy) {
		return integrity("review job has no consumed worker identity")
	}
	record, err := s.deps.Store.Launch(ctx, lease.ConsumedBy)
	if err != nil {
		return failure(err)
	}
	if record.ID != lease.ConsumedBy || record.Config != scope.Config || record.Kind != "worker" ||
		record.Actor.Kind != "worker" || !validID(record.Actor.ID) || record.Actor.LifeID != "" ||
		record.Target != subject.Target || record.GrantSetID != lease.GrantSetID || record.HostUID == 0 ||
		!validID(record.ContainmentID) || record.ProcessGeneration == "" {
		return integrity("review job differs from its retained worker identity")
	}
	effect, err := s.deps.Store.Effect(ctx, scope, lease.EffectID)
	if err != nil {
		return failure(err)
	}
	plan, outcome := effect.Effect.Worker, effect.Outcome
	if effect.Effect.ID != lease.EffectID || effect.Effect.OperationID != lease.OperationID ||
		plan == nil || plan.Schema != "laneboss.worker-plan.v2" || plan.Kind != lease.Kind ||
		plan.Input != lease.Input || plan.GrantSetID != lease.GrantSetID ||
		effect.State != api.EffectCompleted || !validGeneration(effect.Generation) || !validID(effect.ClaimID) ||
		outcome == nil || outcome.Status != "succeeded" || outcome.Error != nil ||
		outcome.EffectID != lease.EffectID || outcome.ClaimID != effect.ClaimID ||
		!validGeneration(outcome.ExpectedGeneration) || outcome.ExpectedGeneration >= api.Generation(maxInteger) ||
		outcome.ExpectedGeneration+1 != effect.Generation || outcome.Observation == nil ||
		outcome.Output == nil || !validBlob(*outcome.Output) || outcome.Output.Class != "worker_result" {
		return integrity("review job has no completed measured worker result")
	}
	observed := outcome.Observation
	if observed.Handle.ID != record.ID || observed.Handle.Target != subject.Target ||
		observed.Handle.ContainmentID != record.ContainmentID || observed.Handle.Generation != record.ProcessGeneration ||
		observed.State != "exited" || observed.Survivors == nil || *observed.Survivors != 0 ||
		observed.ExitCode == nil || *observed.ExitCode != 0 || observed.Signal != nil || !validTime(observed.ObservedAt) {
		return integrity("review worker lacks a successful known-zero terminal observation")
	}
	meta, err := s.deps.Store.ObjectMetadata(ctx, scope, outcome.Output.ID)
	if err != nil {
		return failure(err)
	}
	if meta.Ref != *outcome.Output || meta.SourceOperationID != lease.OperationID ||
		meta.Origin != "worker" && meta.Origin != "service" || meta.ACL.Config != scope.Config || meta.ACL.LifeID != subject.Target.LifeID {
		return integrity("review worker result differs from its authenticated job")
	}
	return s.readReviewObject(ctx, scope, *outcome.Output)
}
