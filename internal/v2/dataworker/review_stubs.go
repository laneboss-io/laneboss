package dataworker

import (
	"context"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

var _ api.ReviewVerifier = (*Service)(nil)

func (s *Service) VerifyReview(ctx context.Context, caller api.Scope, request api.ReviewVerifyRequest) (result api.ReviewEvidence, resultErr error) {
	defer func() {
		if resultErr != nil {
			result = api.ReviewEvidence{}
		}
	}()
	if err := checkContext(ctx); err != nil {
		return result, err
	}
	if request.Request.Target != request.Lease.Target || !manifest.ValidID(request.EndEventID) || request.EndSeq == 0 ||
		uint64(request.EndSeq) > manifest.MaxInteger || request.ExpectedGeneration == 0 || uint64(request.ExpectedGeneration) > manifest.MaxInteger ||
		request.Lease.Kind != "test" && request.Lease.Kind != "export" || len(request.Request.Checks) > 200 || len(request.Request.RefusalResolution) > 200 {
		return result, manifest.Invalid("review verifier requires its exact ended run and confined test/export job")
	}
	for _, item := range []struct {
		ref   api.BlobRef
		class string
	}{{request.Request.Diff, "diff"}, {request.Request.RecordInventory, "manifest"}} {
		if err := manifest.Blob(item.ref); err != nil {
			return result, err
		}
		if item.ref.Class != item.class {
			return result, manifest.Invalid("review candidate reference has the wrong evidence class")
		}
	}
	for _, check := range request.Request.Checks {
		if err := manifest.Blob(check); err != nil {
			return result, err
		}
		if check.Class != "check" {
			return result, manifest.Invalid("review candidate check must name a check object")
		}
	}
	control, ok := s.deps.Controls.(reviewjob.ResultControl)
	if !ok || missing(control) {
		return result, lstate.Error(api.CodePrerequisite, "review requires its installed native execution and result coordinator")
	}
	called := false
	err := control.WithReviewResult(ctx, caller, request, func(execution api.Scope, output api.BlobRef) (callbackErr error) {
		if called {
			return lstate.Error(api.CodeIntegrity, "review coordinator repeated its result handoff")
		}
		called = true
		scope, view, err := s.jobScope(ctx, execution)
		if err != nil {
			return err
		}
		defer func() { callbackErr = errors.Join(callbackErr, view.Close()) }()
		lease, err := s.deps.Store.WorkerLease(ctx, scope, request.Lease.ID)
		if err != nil {
			return err
		}
		expected := request.Lease
		expected.ConsumedBy, expected.Generation = lease.ConsumedBy, lease.Generation
		if !reflect.DeepEqual(lease, expected) || !manifest.ValidID(lease.ConsumedBy) || lease.Kind != "export" ||
			!reviewjob.CompletedGeneration(request.Lease, lease) {
			return lstate.Error(api.CodeIntegrity, "review result changed its original consumed worker lease")
		}
		effect, err := s.deps.Store.Effect(ctx, scope, lease.EffectID)
		if err != nil {
			return err
		}
		plan, outcome := effect.Effect.Worker, effect.Outcome
		if effect.Effect.ID != lease.EffectID || effect.Effect.OperationID != lease.OperationID ||
			plan == nil || plan.Schema != "laneboss.worker-plan.v2" || plan.Kind != lease.Kind || plan.Input != lease.Input || plan.GrantSetID != lease.GrantSetID ||
			effect.State != api.EffectCompleted || !manifest.ValidID(effect.ClaimID) || outcome == nil || outcome.Status != "succeeded" || outcome.Error != nil ||
			outcome.EffectID != lease.EffectID || outcome.ClaimID != effect.ClaimID || outcome.ExpectedGeneration == 0 ||
			uint64(outcome.ExpectedGeneration) >= manifest.MaxInteger || effect.Generation != outcome.ExpectedGeneration+1 ||
			outcome.Observation == nil || outcome.Output == nil || *outcome.Output != output || output.Class != "worker_result" {
			return lstate.Error(api.CodeIntegrity, "review result lacks its exact completed native worker effect")
		}
		record, err := s.deps.Store.Launch(ctx, lease.ConsumedBy)
		if err != nil {
			return err
		}
		observed := outcome.Observation
		observedAt, timeErr := time.Parse(time.RFC3339Nano, string(observed.ObservedAt))
		if record.ID != lease.ConsumedBy || record.Config != scope.Config || record.Kind != "worker" || record.Actor.Kind != "worker" ||
			record.Actor.LifeID != "" || record.Actor.Level != 0 || record.Actor.Role != "" || record.HostUID == 0 ||
			record.Target != request.Request.Target || record.GrantSetID != lease.GrantSetID ||
			observed.Handle.ID != record.ID || observed.Handle.Target != record.Target || observed.Handle.ContainmentID != record.ContainmentID ||
			observed.Handle.Generation != record.ProcessGeneration || observed.State != "exited" || observed.Survivors == nil || *observed.Survivors != 0 ||
			observed.ExitCode == nil || *observed.ExitCode != 0 || observed.Signal != nil || timeErr != nil || observedAt.After(s.deps.Clock.Now()) {
			return lstate.Error(api.CodeContainmentUnknown, "review worker has no successful measured known-zero terminal observation")
		}
		raw, err := s.jobObject(ctx, scope, lease, lease.Input)
		if err != nil {
			return err
		}
		var input reviewjob.Input
		if api.DecodeObject(raw, &input) != nil || input.Schema != "laneboss.review-input.v2" || !reflect.DeepEqual(input.Request, request.Request) ||
			input.Subject.Generation != request.ExpectedGeneration || input.Subject.EndEventID != request.EndEventID || input.Subject.EndSeq != request.EndSeq ||
			input.Subject.Target != request.Request.Target || input.Required == nil {
			return lstate.Error(api.CodeIntegrity, "review result differs from its sealed frozen input")
		}
		raw, err = s.reviewResultObject(ctx, scope, lease, output)
		if err != nil {
			return err
		}
		var evidence api.ReviewEvidence
		if api.DecodeObject(raw, &evidence) != nil || api.ValidateReviewEvidence(evidence, input.Subject) != nil ||
			evidence.VerifierLeaseID != lease.ID || evidence.Diff != request.Request.Diff || evidence.Inventory.Manifest != request.Request.RecordInventory ||
			!reflect.DeepEqual(evidence.Checks, input.Checks) || !reflect.DeepEqual(evidence.Inventory, input.Inventory) || !reflect.DeepEqual(evidence.Resolutions, input.Resolutions) {
			return lstate.Error(api.CodeIntegrity, "review worker output changed its exact requested evidence set")
		}
		if evidence.Coverage == api.CoverageComplete {
			receipt := api.ReviewReceipt{ID: lease.ID, Reviewer: caller.Actor, Diff: evidence.Diff, Checks: request.Request.Checks,
				RecordInventory: evidence.Inventory.Manifest, RefusalResolution: request.Request.RefusalResolution, Coverage: evidence.Coverage, Evidence: &evidence}
			if err := api.ValidateReviewAcceptance(caller, receipt, input.Subject, input.Required); err != nil {
				return err
			}
		}
		result = evidence
		return nil
	})
	if err != nil {
		return result, err
	}
	if !called {
		return result, lstate.Error(api.CodeIntegrity, "review coordinator returned without a measured result")
	}
	return result, nil
}

func (s *Service) reviewResultObject(ctx context.Context, scope api.Scope, lease api.WorkerLease, ref api.BlobRef) ([]byte, error) {
	if err := manifest.Blob(ref); err != nil {
		return nil, err
	}
	if ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes {
		return nil, manifest.Invalid("review result exceeds its fixed bound")
	}
	meta, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if meta.Ref != ref || meta.SourceOperationID != lease.OperationID || meta.ACL.Config != scope.Config || meta.ACL.LifeID != lease.Target.LifeID ||
		meta.Origin != "worker" && meta.Origin != "service" {
		return nil, lstate.Error(api.CodeIntegrity, "review result lacks its authenticated worker provenance")
	}
	return readWorkerObject(ctx, func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
		return s.deps.Store.Blob(ctx, scope, request)
	}, ref)
}
