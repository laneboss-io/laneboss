package lifecycle

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

func distinctReviewer(scope api.Scope, target api.LifeRef) error {
	if scope.Actor.Kind == "lane" && scope.Actor.LifeID == target.LifeID {
		return problem(api.CodeForbidden, "an executor cannot accept or review its own life",
			"Request an authorized independent supervisor or reviewer.")
	}
	return nil
}

func reviewCoverage(coverage string) bool {
	return coverage == api.CoverageComplete || coverage == api.CoveragePartial || coverage == api.CoverageUnsupported || coverage == api.CoverageMissing
}

func reviewInputs(request api.ReviewRequest) error {
	if !validBlob(request.Diff) || !validBlob(request.RecordInventory) ||
		request.RecordInventory.Class != "manifest" || request.Checks == nil ||
		len(request.Checks) == 0 || len(request.Checks) > 200 ||
		request.RefusalResolution == nil || len(request.RefusalResolution) > 200 {
		return invalid("review requires diff, checks and a record inventory")
	}
	for _, check := range request.Checks {
		if !validBlob(check) {
			return invalid("invalid required check receipt reference")
		}
	}
	seen := make(map[api.ID]bool, len(request.RefusalResolution))
	for _, id := range request.RefusalResolution {
		if !validID(id) || seen[id] {
			return invalid("invalid or repeated refusal resolution")
		}
		seen[id] = true
	}
	return nil
}

func (s *Service) LaneReview(ctx context.Context, scope api.Scope,
	request api.ReviewRequest) (api.ReviewReceipt, error) {
	if err := s.authorize(ctx, scope, "lane.review", request); err != nil {
		return api.ReviewReceipt{}, err
	}
	if err := distinctReviewer(scope, request.Target); err != nil {
		return api.ReviewReceipt{}, err
	}
	if err := reviewInputs(request); err != nil {
		return api.ReviewReceipt{}, err
	}
	unlock, err := s.lockLife(ctx, request.Target.LifeID)
	if err != nil {
		return api.ReviewReceipt{}, err
	}
	defer func() { unlock() }()
	lane, err := s.lane(ctx, scope, request.Target, false)
	if err != nil {
		return api.ReviewReceipt{}, err
	}
	if result, found, err := replayReply[api.ReviewReceipt](s, ctx, scope); found || err != nil {
		return result, err
	}
	if lane.Cleaned || lane.Run != request.Target.Run || lane.State != "verifying" {
		return api.ReviewReceipt{}, problem(api.CodeConflict, "life is not ready for independent review",
			"Stop and reconcile the current run before reviewing its exact output.")
	}
	observation, facts, err := s.observe(ctx, scope, lane, request.Target)
	if err != nil {
		return api.ReviewReceipt{}, err
	}
	if err := requireQuiescence(observation); err != nil {
		return api.ReviewReceipt{}, err
	}
	if facts.end == nil || facts.endSeq == 0 || facts.end.Reason == "service_lost" {
		return api.ReviewReceipt{}, problem(api.CodeConflict, "review requires a committed run end",
			"Reconcile the ended run before reviewing its exact evidence.")
	}
	if err := requireQuiescence(facts.end.Observation); err != nil {
		return api.ReviewReceipt{}, err
	}
	if err := requireReviewCapture(facts); err != nil {
		return api.ReviewReceipt{}, err
	}
	inputs := append([]api.BlobRef{request.Diff}, request.Checks...)
	inputs = append(inputs, request.RecordInventory)
	for _, ref := range inputs {
		if err := s.readReviewObject(ctx, scope, ref); err != nil {
			return api.ReviewReceipt{}, err
		}
	}
	subject, required, err := s.reviewSubject(ctx, scope, lane, facts)
	if err != nil {
		return api.ReviewReceipt{}, err
	}
	prepared, err := s.verifyReviewLease(ctx, scope, request, lane, facts, subject)
	if err != nil {
		return api.ReviewReceipt{}, err
	}
	if absent(s.deps.Review) {
		return api.ReviewReceipt{}, api.NotImplemented("lb-v2-grants", "ReviewVerifier.VerifyReview")
	}
	unlock()
	unlock = func() {}
	evidence, err := s.deps.Review.VerifyReview(ctx, scope, prepared)
	if err != nil {
		return api.ReviewReceipt{}, failure(err)
	}
	if err := api.ValidateReviewEvidence(evidence, subject); err != nil {
		return api.ReviewReceipt{}, failure(err)
	}
	if evidence.VerifierLeaseID != prepared.Lease.ID || evidence.Diff != request.Diff || evidence.Inventory.Manifest != request.RecordInventory || len(evidence.Checks) != len(request.Checks) {
		return api.ReviewReceipt{}, integrity("verifier changed the requested review object set")
	}
	retainedLease, err := s.deps.Store.WorkerLease(ctx, scope, prepared.Lease.ID)
	if err != nil {
		return api.ReviewReceipt{}, failure(err)
	}
	expectedLease := prepared.Lease
	expectedLease.ConsumedBy = retainedLease.ConsumedBy
	expectedLease.Generation = retainedLease.Generation
	if !reflect.DeepEqual(retainedLease, expectedLease) || !reviewjob.CompletedGeneration(prepared.Lease, retainedLease) {
		return api.ReviewReceipt{}, integrity("verifier changed its original worker lease")
	}
	checks := make([]api.BlobRef, len(evidence.Checks))
	for i, check := range evidence.Checks {
		if check.Receipt != request.Checks[i] {
			return api.ReviewReceipt{}, integrity("verifier changed the ordered check receipts")
		}
		checks[i] = check.Receipt
	}
	if err := s.readReviewEvidence(ctx, scope, evidence); err != nil {
		return api.ReviewReceipt{}, err
	}
	id, err := newID()
	if err != nil {
		return api.ReviewReceipt{}, err
	}
	receipt := api.ReviewReceipt{ID: id, Reviewer: scope.Actor, Diff: evidence.Diff, Checks: checks, RecordInventory: evidence.Inventory.Manifest,
		RefusalResolution: append([]api.ID{}, request.RefusalResolution...), Coverage: evidence.Coverage, Evidence: &evidence}
	if receipt.Coverage == api.CoverageComplete {
		if err := api.ValidateReviewAcceptance(scope, receipt, subject, required); err != nil {
			return api.ReviewReceipt{}, failure(err)
		}
	}
	unlock, err = s.lockLife(ctx, request.Target.LifeID)
	if err != nil {
		unlock = func() {}
		return api.ReviewReceipt{}, err
	}
	if err := s.authorize(ctx, scope, "lane.review", request); err != nil {
		return api.ReviewReceipt{}, err
	}
	if prior, found, err := replayReply[api.ReviewReceipt](s, ctx, scope); found || err != nil {
		return prior, err
	}
	current, err := s.lane(ctx, scope, request.Target, true)
	if err != nil {
		return api.ReviewReceipt{}, err
	}
	if current.Generation != lane.Generation || current.State != "verifying" || current.Cleaned || current.CancellationEpoch != lane.CancellationEpoch {
		return api.ReviewReceipt{}, problem(api.CodeConflict, "review subject changed during verification", "Review the current ended snapshot under its original worker claim.")
	}
	currentFacts, err := s.facts(ctx, scope, current, request.Target)
	if err != nil {
		return api.ReviewReceipt{}, err
	}
	latest, latestRequired, err := s.reviewSubject(ctx, scope, current, currentFacts)
	if err != nil {
		return api.ReviewReceipt{}, err
	}
	if !reflect.DeepEqual(latest, subject) || !reflect.DeepEqual(latestRequired, required) {
		return api.ReviewReceipt{}, problem(api.CodeConflict, "frozen review context changed", "Retain the verifier receipt and resolve the current snapshot.")
	}
	event, err := s.event(scope, lane, "lane.reviewed", receipt, scope.Actor)
	if err != nil {
		return api.ReviewReceipt{}, err
	}
	commit, err := s.commitLifecycle(ctx, scope, lane, []api.Event{event}, nil)
	if err != nil {
		return api.ReviewReceipt{}, err
	}
	var retained api.ReviewReceipt
	if commit.Reply == nil || api.DecodeObject(commit.Reply.Result, &retained) != nil || !reflect.DeepEqual(retained, receipt) {
		return api.ReviewReceipt{}, integrity("review commit did not retain its exact verified receipt")
	}
	return retained, nil
}

func (s *Service) storedReview(ctx context.Context, scope api.Scope,
	lane api.Lane, target api.LifeRef, requested api.ReviewReceipt,
	endSeq api.Sequence) error {
	if !validID(requested.ID) ||
		requested.Reviewer.Kind != "human" && requested.Reviewer.Kind != "lane" ||
		requested.Reviewer.Kind == "lane" && requested.Reviewer.LifeID == lane.LifeID {
		return problem(api.CodeForbidden, "review is incomplete or not independent",
			"Obtain the service's independent review receipt for this run.")
	}
	if err := reviewInputs(api.ReviewRequest{Target: target, Diff: requested.Diff,
		Checks: requested.Checks, RecordInventory: requested.RecordInventory,
		RefusalResolution: requested.RefusalResolution}); err != nil {
		return err
	}
	found := false
	var reviewedSeq, changedSeq api.Sequence
	err := s.walkEvents(ctx, scope, lane, target, func(event api.Event) error {
		switch event.Kind {
		case "lane.reviewed":
			var receipt api.ReviewReceipt
			if err := decode(event.Payload, &receipt); err != nil {
				return integrity("invalid stored review receipt")
			}
			if receipt.ID == requested.ID {
				if !reflect.DeepEqual(receipt, requested) || receipt.Reviewer != event.Actor ||
					event.Seq <= endSeq {
					return problem(api.CodeForbidden, "review receipt does not match this ended run",
						"Use the exact service-created receipt after the selected run end.")
				}
				if receipt.Evidence != nil {
					lease, err := s.deps.Store.WorkerLease(ctx, scope, receipt.Evidence.VerifierLeaseID)
					if err != nil {
						return failure(err)
					}
					if event.OperationID != lease.OperationID {
						allowAndLog("review_verifier_operation")
					}
				}
				found, reviewedSeq = true, event.Seq
			}
		case "capture.appended", "capture.gap", "prompt.observed", "data.materialized", "lane.lost", "runner.session",
			"lane.started", "lane.resumed", "lane.turn":
			changedSeq = event.Seq
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !found || changedSeq > reviewedSeq {
		return problem(api.CodeForbidden, "no current trusted review receipt",
			"Review the current diff, required checks and complete record inventory independently.")
	}
	if requested.Evidence == nil {
		return problem(api.CodeForbidden, "historical review has no live verifier evidence", "Obtain a complete read-back review for the actual ended run.")
	}
	facts, err := s.facts(ctx, scope, lane, target)
	if err != nil {
		return err
	}
	subject, required, err := s.reviewSubject(ctx, scope, lane, facts)
	if err != nil {
		return err
	}
	if err := s.readReviewEvidence(ctx, scope, *requested.Evidence); err != nil {
		return err
	}
	if err := api.ValidateReviewAcceptance(scope, requested, subject, required); err != nil {
		return problem(api.CodeForbidden, "review does not authorize acceptance", "Obtain complete independent evidence for the current frozen subject.")
	}
	return nil
}

func (s *Service) LaneMark(ctx context.Context, scope api.Scope,
	request api.MarkRequest) (api.Operation, error) {
	if err := s.authorize(ctx, scope, "lane.mark", request); err != nil {
		return api.Operation{}, err
	}
	if err := distinctReviewer(scope, request.Target); err != nil {
		return api.Operation{}, err
	}
	if request.State != "accepted" && request.State != "merged" && request.State != "abandoned" {
		return api.Operation{}, invalid("unknown reviewed lifecycle state")
	}
	unlock, err := s.lockLife(ctx, request.Target.LifeID)
	if err != nil {
		return api.Operation{}, err
	}
	defer unlock()
	lane, err := s.lane(ctx, scope, request.Target, false)
	if err != nil {
		return api.Operation{}, err
	}
	if operation, done, err := s.staleReplay(ctx, scope, lane,
		request.ExpectedGeneration); done {
		return operation, err
	}
	allowed := request.State == "accepted" && lane.State == "verifying" ||
		request.State == "merged" && lane.State == "accepted" ||
		request.State == "abandoned" && (lane.State == "verifying" || lane.State == "idle" ||
			lane.State == "accepted" || lane.State == "profile_wait" || lane.State == "lost")
	if !allowed || lane.Cleaned || lane.Run != request.Target.Run {
		return api.Operation{}, problem(api.CodeConflict, "invalid reviewed lifecycle transition",
			"Read the current state; accept only verifying work and merge only accepted work.")
	}
	observed, facts, err := s.observe(ctx, scope, lane, request.Target)
	if err != nil {
		return api.Operation{}, err
	}
	if err := requireQuiescence(observed); err != nil {
		return api.Operation{}, err
	}
	if request.State != "abandoned" {
		if err := requireReviewCapture(facts); err != nil {
			return api.Operation{}, err
		}
		if facts.end == nil || facts.endSeq == 0 || facts.end.Reason == "service_lost" ||
			requireQuiescence(facts.end.Observation) != nil {
			return api.Operation{}, problem(api.CodeConflict, "run end has not been committed",
				"Reconcile the real terminal observation before accepting work.")
		}
		if err := s.storedReview(ctx, scope, lane, request.Target,
			request.Review, facts.endSeq); err != nil {
			return api.Operation{}, err
		}
	}
	if lane.Generation == api.Generation(maxInteger) {
		return api.Operation{}, integrity("life generation exhausted")
	}
	state := api.StateEvent{From: lane.State, To: request.State,
		Generation: lane.Generation + 1}
	if request.State != "abandoned" {
		state.ReviewID = request.Review.ID
	}
	event, err := s.event(scope, lane, "lane.state", state, scope.Actor)
	if err != nil {
		return api.Operation{}, err
	}
	// This records a decision. It performs no Git merge or deployment.
	return s.transact(ctx, scope, lane, []api.Event{event}, []api.Effect{})
}
