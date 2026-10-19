package lifecycle

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) LaneArchive(ctx context.Context, scope api.Scope,
	request api.ArchiveRequest) (api.ArchiveReceipt, error) {
	if err := s.authorize(ctx, scope, "lane.archive", request); err != nil {
		return api.ArchiveReceipt{}, err
	}
	unlock, err := s.lockLife(ctx, request.Target.LifeID)
	if err != nil {
		return api.ArchiveReceipt{}, err
	}
	defer func() { unlock() }()
	lane, err := s.lane(ctx, scope, request.Target, false)
	if err != nil {
		return api.ArchiveReceipt{}, err
	}
	if result, found, err := replayReply[api.ArchiveReceipt](s, ctx, scope); found || err != nil {
		return result, err
	}
	if request.ExpectedGeneration != lane.Generation || lane.Cleaned || lane.Run != request.Target.Run {
		return api.ArchiveReceipt{}, problem(api.CodeConflict, "archive generation changed or life is cleaned",
			"Read the current life before requesting a verified archive.")
	}
	observation, facts, err := s.observe(ctx, scope, lane, request.Target)
	if err != nil {
		return api.ArchiveReceipt{}, err
	}
	if err := requireQuiescence(observation); err != nil {
		return api.ArchiveReceipt{}, err
	}
	if facts.end == nil || facts.endSeq == 0 || facts.end.Reason == "service_lost" || requireQuiescence(facts.end.Observation) != nil {
		return api.ArchiveReceipt{}, problem(api.CodeContainmentUnknown, "archive requires a committed quiescent end", "Reconcile the actual run and its capture before freezing archive inputs.")
	}
	control := s.deps.Archives
	if absent(control) {
		control, _ = s.deps.Store.(ArchiveControl)
	}
	if absent(control) {
		return api.ArchiveReceipt{}, api.NotImplemented("lb-v2-service", "atomic archive worker reservation and completion")
	}
	original, err := s.pendingMutation(ctx, scope)
	if err != nil {
		return api.ArchiveReceipt{}, err
	}
	intent := ArchiveIntent{Request: request, OperationID: original.Operation.ID,
		CancellationEpoch: lane.CancellationEpoch, EndEventID: facts.endID, EndSeq: facts.endSeq}
	job, err := control.ReserveArchive(ctx, scope, intent)
	if err != nil {
		return api.ArchiveReceipt{}, failure(err)
	}
	if err := s.archiveJob(ctx, scope, control, lane, intent, job); err != nil {
		return api.ArchiveReceipt{}, err
	}
	// The outbox owns the fixed worker and its claim. A synchronous archive
	// reply waits outside the life gate; it never reports intent as a receipt.
	unlock()
	unlock = func() {}
	key := original.Key
	completed, err := s.deps.Store.AwaitReceipt(ctx, scope, key)
	if err != nil {
		return api.ArchiveReceipt{}, failure(err)
	}
	if err := s.deps.Identity.Authorize(ctx, scope, scope.Request); err != nil {
		return api.ArchiveReceipt{}, failure(err)
	}
	if !receiptMatches(scope, key, completed) || completed.Operation.ID != original.Operation.ID || completed.Reply == nil ||
		(completed.Reply.Error == nil) == (len(completed.Reply.Result) == 0) {
		return api.ArchiveReceipt{}, integrity("archive completion lost its exact dispatcher reply")
	}
	if err := s.receiptPolicy(ctx, scope, completed); err != nil {
		return api.ArchiveReceipt{}, err
	}
	if completed.Reply.Error != nil {
		return api.ArchiveReceipt{}, completed.Reply.Error
	}
	if completed.Operation.Status != "succeeded" || completed.Operation.Error != nil {
		return api.ArchiveReceipt{}, integrity("archive reply preceded its completed operation")
	}
	current, err := s.lane(ctx, scope, request.Target, false)
	if err != nil {
		return api.ArchiveReceipt{}, err
	}
	if current.Generation != lane.Generation || current.CancellationEpoch != intent.CancellationEpoch || current.Cleaned || current.Run != lane.Run {
		return api.ArchiveReceipt{}, problem(api.CodeConflict, "archive completion lost its original life fence", "Inspect the retained operation and current life before requesting another archive.")
	}
	var result api.ArchiveReceipt
	if api.DecodeObject(completed.Reply.Result, &result) != nil || result.LifeID != lane.LifeID {
		return api.ArchiveReceipt{}, integrity("archive completion changed its target")
	}
	if err := s.archiveCompletion(ctx, scope, lane, job, result); err != nil {
		return api.ArchiveReceipt{}, err
	}
	return result, nil
}

func (s *Service) archiveReceipt(ctx context.Context, scope api.Scope,
	lane api.Lane, request api.CleanRequest, endSeq api.Sequence) (api.ArchiveReceipt, error) {
	var receipt api.ArchiveReceipt
	found := false
	var receiptSeq, changedSeq api.Sequence
	err := s.walkEvents(ctx, scope, lane, request.Target, func(event api.Event) error {
		switch event.Kind {
		case "capture.appended", "capture.gap", "prompt.observed", "data.materialized", "lane.lost", "runner.session",
			"lane.started", "lane.resumed", "lane.turn":
			changedSeq = event.Seq
		}
		if event.Kind != "archive.verified" {
			return nil
		}
		var candidate api.ArchiveReceipt
		if err := decode(event.Payload, &candidate); err != nil {
			return integrity("invalid stored archive receipt")
		}
		if candidate.ID == request.ArchiveReceiptID && event.Seq > endSeq {
			receipt, found = candidate, true
			receiptSeq = event.Seq
		}
		return nil
	})
	if err != nil {
		return api.ArchiveReceipt{}, err
	}
	if !found || changedSeq > receiptSeq || receipt.LifeID != lane.LifeID || !validID(receipt.ID) ||
		!validID(receipt.StoreID) || !validBlob(receipt.Manifest) ||
		receipt.Manifest.Class != "manifest" || !validDigest(receipt.ArchiveSHA256) ||
		receipt.ArchiveSHA256 != receipt.ReadBackSHA256 || !validTime(receipt.VerifiedAt) {
		return api.ArchiveReceipt{}, problem(api.CodeIntegrity, "no matching verified archive read-back",
			"Preserve all work and obtain the service's verified archive receipt first.")
	}
	raw, err := s.readBlob(ctx, scope, receipt.Manifest)
	if err != nil {
		return api.ArchiveReceipt{}, err
	}
	if err := archiveManifest(raw); err != nil {
		return api.ArchiveReceipt{}, err
	}
	return receipt, nil
}

func (s *Service) LaneClean(ctx context.Context, scope api.Scope,
	request api.CleanRequest) (api.Operation, error) {
	if err := s.authorize(ctx, scope, "lane.clean", request); err != nil {
		return api.Operation{}, err
	}
	if !validID(request.ArchiveReceiptID) {
		return api.Operation{}, invalid("clean requires a verified archive receipt ID")
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
	if lane.Cleaned || lane.Run != request.Target.Run ||
		(lane.State != "merged" && lane.State != "abandoned") {
		return api.Operation{}, problem(api.CodeConflict, "clean requires merged or abandoned work",
			"Retain the workspace until its reviewed lifecycle decision is recorded.")
	}
	observation, facts, err := s.observe(ctx, scope, lane, request.Target)
	if err != nil {
		return api.Operation{}, err
	}
	if err := requireQuiescence(observation); err != nil {
		return api.Operation{}, err
	}
	if facts.end == nil || facts.endSeq == 0 || facts.end.Reason == "service_lost" ||
		requireQuiescence(facts.end.Observation) != nil {
		return api.Operation{}, problem(api.CodeContainmentUnknown, "no committed run end before clean",
			"Reconcile capture and containment while preserving the workspace.")
	}
	if _, err := s.archiveReceipt(ctx, scope, lane, request, facts.endSeq); err != nil {
		return api.Operation{}, err
	}
	effectID, err := newID()
	if err != nil {
		return api.Operation{}, err
	}
	// The collector owns the physical removal. This transaction retains its
	// exact archive selector and cancellation fence without claiming cleaned.
	return s.transact(ctx, scope, lane, nil, []api.Effect{{ID: effectID, Clean: &request}})
}
