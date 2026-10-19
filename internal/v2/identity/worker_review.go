package identity

import (
	"context"
	"encoding/json"
	"os"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/reviewjob"
	"laneboss.io/laneboss/internal/v2/testjob"
)

// Export review consumes an ended run's immutable job, not a materialization
// reservation. The common handoff checks still pin its executable, fixed argv,
// original spec, committed identity, endpoint and current native lifetime.
func checkReviewWorkerHandoff(a WorkerLaunchAuthority) error {
	p, spec := a.Principal, a.Handoff.Spec
	freeze := spec.Materialization.Manifest
	if spec.PlanID != p.StageID || !validID(p.StageID) || spec.Materialization.GrantSetID != p.Lease.GrantSetID ||
		freeze.Class != "manifest" || !validID(freeze.ID) || !validDigest(freeze.SHA256) || freeze.Bytes <= 0 || freeze.Bytes > api.MaxObjectBytes ||
		!validID(p.Lease.Input.ID) || len(spec.Materialization.Objects) != 0 ||
		len(spec.Grants.Resources)+len(spec.Grants.Secrets)+len(spec.Grants.Profiles)+len(spec.Grants.Network)+len(spec.Grants.Channels) != 0 ||
		p.Claim.Record.Effect.Context == nil || !validID(p.Claim.Record.ClaimantID) {
		return refusal(api.CodeIntegrity, "review handoff changed its original job, freeze or narrow authority")
	}
	for _, grant := range spec.Grants.Data {
		if grant.Access != "ro" || grant.Delegate {
			return refusal(api.CodeIntegrity, "review handoff acquired writable or delegable data")
		}
	}
	// Keep the immutable effect author separate from the current service
	// claimant. No other part of the original causal intent may change.
	cause := *p.Claim.Record.Effect.Context
	cause.Kind, cause.Actor = api.InternalHelperRegister, api.Actor{Kind: "service", ID: p.Claim.Record.ClaimantID}
	if a.Handoff.Cause != cause {
		return refusal(api.CodeIntegrity, "review handoff differs from its original claimed cause")
	}
	return nil
}

// Re-read the single writer's original review job and the actual sealed input
// on both sides of native lifetime validation. Plausible copied metadata does
// not replace the retained job, its freeze, or its exact ended-run fence.
func (s *Service) checkReviewWorker(ctx context.Context, a WorkerLaunchAuthority, input *os.File) error {
	p, spec := a.Principal, a.Handoff.Spec
	reader, ok := s.deps.Store.(interface {
		ReviewJob(context.Context, api.Scope, api.ID) (archivejob.Job, error)
	})
	if !ok {
		return api.NotImplemented("lb-v2-service", "retained review worker job lookup")
	}
	scope := api.Scope{Config: p.Record.Config, Actor: a.Handoff.Cause.Actor, EndpointGeneration: p.Endpoint.EndpointGeneration, PolicyGeneration: p.Record.PolicyGeneration}
	job, err := reader.ReviewJob(ctx, scope, p.Lease.OperationID)
	if err != nil {
		return err
	}
	lease := job.Lease
	lease.ConsumedBy, lease.Generation = p.Record.ID, lease.Generation+1
	if job.Lease.Generation == 0 || lease != p.Lease || job.ID != p.StageID || spec.PlanID != job.ID || !reflect.DeepEqual(job.Plan, *spec.Worker) ||
		job.Freeze != spec.Materialization.Manifest || job.Intent.Request.Target != p.Lease.Target || job.Intent.OperationID != p.Lease.OperationID ||
		job.Intent.CancellationEpoch != p.CancellationEpoch || job.Intent.Request.ExpectedGeneration == 0 || !validID(job.Intent.EndEventID) || job.Intent.EndSeq == 0 {
		return refusal(api.CodeIntegrity, "review handoff differs from its retained job, freeze or end fence")
	}
	raw := make([]byte, p.Lease.Input.Bytes) // Bounded by checkWorkerHandoff.
	if n, err := input.ReadAt(raw, 0); err != nil || n != len(raw) || digestBytes(raw) != p.Lease.Input.SHA256 {
		return refusal(api.CodeIntegrity, "review handoff lost its exact sealed input")
	}
	var subject api.ReviewSubject
	if p.Lease.Kind == "test" {
		var protocol struct {
			Schema string `json:"schema"`
		}
		if json.Unmarshal(raw, &protocol) != nil {
			return refusal(api.CodeIntegrity, "test worker lost its sealed protocol")
		}
		if protocol.Schema == "laneboss.test-input.v2" {
			var test testjob.Input
			if api.DecodeObject(raw, &test) != nil || test.Schema != "laneboss.test-input.v2" || test.Request.Child != job.Lease.Target ||
				test.Subject.Target != job.Lease.Target || test.Subject.EndEventID != job.Intent.EndEventID || test.Subject.EndSeq != job.Intent.EndSeq ||
				test.Subject.Generation != job.Intent.Request.ExpectedGeneration || test.Plan.Kind != "test" || test.Plan.Input != test.Request.Candidate {
				return refusal(api.CodeIntegrity, "TestChild sealed input changed its candidate or frozen subject")
			}
			subject = test.Subject
		} else {
			var sealed reviewjob.CheckInput
			if api.DecodeObject(raw, &sealed) != nil || reviewjob.ValidateCheckInput(sealed, job.Lease, job.Plan) != nil {
				return refusal(api.CodeIntegrity, "check sealed input changed its original declared test")
			}
			subject = sealed.Subject
		}
	} else {
		var sealed reviewjob.Input
		if api.DecodeObject(raw, &sealed) != nil || sealed.Schema != "laneboss.review-input.v2" || sealed.Request.Target != job.Lease.Target || len(sealed.Required) == 0 || len(sealed.Required) > 200 || len(sealed.Checks) == 0 || len(sealed.Checks) > 200 {
			return refusal(api.CodeIntegrity, "review sealed input changed its retained requirements")
		}
		subject = sealed.Subject
	}
	if subject.Target != job.Lease.Target || subject.Generation != job.Intent.Request.ExpectedGeneration || subject.EndEventID != job.Intent.EndEventID || subject.EndSeq != job.Intent.EndSeq || !validID(subject.LaunchID) || !validID(subject.SessionID) {
		return refusal(api.CodeIntegrity, "review sealed input changed its retained subject or end")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, job.Lease.Target)
	if err != nil {
		return err
	}
	if lane.Cleaned || lane.LifeID != job.Lease.Target.LifeID || lane.Run != job.Lease.Target.Run || lane.State != "verifying" || lane.Containment != "quiescent" ||
		lane.Generation != job.Intent.Request.ExpectedGeneration || lane.CancellationEpoch != job.Intent.CancellationEpoch ||
		lane.LaunchID != subject.LaunchID || lane.Session.ID != subject.SessionID {
		return refusal(api.CodeConflict, "review worker lost its exact ended life, generation or cancellation fence")
	}
	return nil
}

func (s *Service) checkReviewWorkerBoundEvent(ctx context.Context, scope api.Scope, binding api.LaunchBindingRequest, a WorkerLaunchAuthority) error {
	// Reclaimed attempts keep the original committed identity event. Its
	// actual service author is checked separately from the live job claimant.
	page, err := s.deps.Store.Events(ctx, scope, api.EventTailRequest{LifeID: binding.Record.Target.LifeID, Run: binding.Record.Target.Run, Since: binding.Identity.CommittedSeq - 1})
	if err != nil {
		return err
	}
	for _, event := range page.Events {
		if event.Seq == binding.Identity.CommittedSeq {
			return s.checkBoundEventActor(ctx, scope, binding, a.Handoff, event.Actor)
		}
	}
	return refusal(api.CodeIntegrity, "retained review identity commit event is missing")
}
