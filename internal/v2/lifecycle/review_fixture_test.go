package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// This confined-verifier double retains actual input/output bytes and job
// records. It provides fixture evidence only, never an installed worker pass.
type fixtureReviewControl struct {
	f           *fixture
	subject     api.ReviewSubject
	required    []string
	evidence    api.ReviewEvidence
	lease       api.WorkerLease
	calls       int
	prepareHook func(*api.ReviewVerifyRequest)
	verifyHook  func(*api.ReviewEvidence)
	resolveHook func(*api.ReviewSubject)
	err         error
}

func (store *fixtureStore) WorkerLease(_ context.Context, _ api.Scope, id api.ID) (api.WorkerLease, error) {
	lease, ok := store.reviewWorkers[id]
	if !ok {
		return api.WorkerLease{}, launchMissing()
	}
	return lease, nil
}

func (store *fixtureStore) CaptureState(_ context.Context, _ api.Scope, id api.ID) (api.CaptureState, error) {
	capture, ok := store.reviewCaptures[id]
	if !ok {
		return api.CaptureState{}, launchMissing()
	}
	return capture, nil
}

func (store *fixtureStore) Effect(_ context.Context, _ api.Scope, id api.ID) (api.EffectRecord, error) {
	row, ok := store.reviewEffects[id]
	if !ok {
		return api.EffectRecord{}, launchMissing()
	}
	return row, nil
}

func (f *fixture) measuredBlob(id api.ID, class string, raw []byte, operation api.ID, target api.LifeRef) api.BlobRef {
	ref := f.blob(id, class, raw)
	meta := f.store.metadata[id]
	meta.Origin, meta.SourceOperationID = "worker", operation
	meta.ACL.Owner = api.Actor{Kind: "worker", ID: "review-worker-actor"}
	meta.ACL.LifeID, meta.ACL.Generation = target.LifeID, 1
	f.store.metadata[id] = meta
	return ref
}

func fixtureReviewFor(f *fixture, lane api.Lane) api.ReviewReceipt {
	f.t.Helper()
	target := api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}
	endID, endSeq := api.ID("not-yet-ended"), api.Sequence(1)
	for _, event := range f.store.events {
		if event.LifeID == target.LifeID && event.Run == target.Run && event.Kind == "lane.ended" && event.Origin == "service" {
			endID, endSeq = event.ID, event.Seq
		}
	}
	subject := api.ReviewSubject{Target: target, LaunchID: lane.LaunchID, Generation: lane.Generation,
		EndEventID: endID, EndSeq: endSeq, InventorySeq: endSeq, SessionID: lane.Session.ID,
		Snapshot:         f.measuredBlob("review-snapshot", "manifest", []byte("frozen workspace snapshot\n"), "snapshot-operation", target),
		CaptureBindingID: "review-capture", Streams: []api.CaptureStreamBinding{
			{ID: "review-stdout", PipeID: "stdout-pipe", Stream: "stdout"},
			{ID: "review-stderr", PipeID: "stderr-pipe", Stream: "stderr"}}, RefusalIDs: []api.ID{}}
	binding := api.CaptureBinding{ID: subject.CaptureBindingID, Config: "example", ReservationID: "review-reservation", Target: target, LaunchID: lane.LaunchID,
		HelperLeaseID: "review-helper", OperationID: "capture-operation", RequestID: "capture-request", RequestedBy: f.parent, Generation: 1, Status: "registered",
		WorkerLeaseID: "capture-worker", EffectID: "capture-effect", ProducerID: "capture-producer", ProducerGeneration: "capture-process", BootID: "fixture-boot",
		Supervisor: &api.Executable{ID: "capture-supervisor", SHA256: digestOf([]byte("installed fixture supervisor")), Version: "fixture-1"}, Streams: subject.Streams}
	for _, event := range f.store.events {
		if (event.Kind == "capture.bound" || event.Kind == "capture.refused") && event.LifeID == lane.LifeID && event.Run == lane.Run {
			if err := api.DecodeObject(event.Payload, &binding); err != nil {
				f.t.Fatal(err)
			}
			subject.CaptureBindingID, subject.Streams = binding.ID, binding.Streams
		}
	}
	inputBytes, err := json.Marshal(subject)
	if err != nil {
		f.t.Fatal(err)
	}
	runtime := f.measuredBlob("review-runtime", "manifest", []byte("fixed test runtime\n"), "verifier-operation", target)
	lease := api.WorkerLease{ID: "review-verifier", Kind: "export", Target: target,
		OperationID: "verifier-operation", EffectID: "verifier-effect", GrantSetID: lane.GrantSetID,
		Generation: 1, ExpiresAt: "2031-01-01T00:00:00Z", RuntimeManifest: runtime,
		Input: f.measuredBlob("review-input", "manifest", inputBytes, "verifier-operation", target)}
	checkLease := lease
	checkLease.ID, checkLease.Kind, checkLease.OperationID, checkLease.EffectID = "check-worker", "test", "check-operation", "check-effect"
	f.store.reviewWorkers[lease.ID], f.store.reviewWorkers[checkLease.ID] = lease, checkLease
	if f.store.reviewEffects == nil {
		f.store.reviewEffects = make(map[api.ID]api.EffectRecord)
	}
	// Component inputs model the retained native result. They are not an
	// installed execution or a claim that the fixture ran a confined process.
	for _, worker := range []api.WorkerLease{lease, checkLease} {
		worker.ConsumedBy = api.ID(string(worker.ID) + "-launch")
		f.store.reviewWorkers[worker.ID] = worker
		if worker.ID == lease.ID {
			lease = worker
		}
		record := api.LaunchRecord{Kind: "worker", ID: worker.ConsumedBy, Config: "example", Target: target,
			Actor:   api.Actor{Kind: "worker", ID: api.ID(string(worker.ID) + "-actor")},
			HostUID: 22002, ContainmentID: api.ID(string(worker.ID) + "-containment"),
			ProcessGeneration: "fixture-worker-lifetime", GrantSetID: worker.GrantSetID}
		f.store.launches[record.ID] = record
		zero, exit := uint64(0), 0
		output := f.measuredBlob(api.ID(string(worker.ID)+"-result"), "worker_result", []byte("component result\n"), worker.OperationID, target)
		observation := api.ProcessObservation{Handle: api.ProcessHandle{ID: record.ID, Target: target,
			ContainmentID: record.ContainmentID, Generation: record.ProcessGeneration},
			State: "exited", Survivors: &zero, ExitCode: &exit, ObservedAt: "2030-01-01T00:00:00Z"}
		f.store.reviewEffects[worker.EffectID] = api.EffectRecord{State: api.EffectCompleted, Generation: 3, ClaimID: "review-claim",
			Effect: api.Effect{ID: worker.EffectID, OperationID: worker.OperationID,
				Worker: &api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: worker.Kind, Input: worker.Input, GrantSetID: worker.GrantSetID}},
			Outcome: &api.EffectOutcome{EffectID: worker.EffectID, ClaimID: "review-claim", ExpectedGeneration: 2,
				Status: "succeeded", Observation: &observation, Output: &output}}
	}
	for _, operation := range []api.ID{lease.OperationID, checkLease.OperationID} {
		f.store.operations[operation] = api.Operation{ID: operation, Status: "succeeded", LifeID: target.LifeID, Run: target.Run}
	}
	check := api.ReviewCheckFact{Name: "unit", Receipt: f.measuredBlob("check", "check", []byte("measured unit result\n"), "check-operation", target),
		Target: target, EndSeq: endSeq, SnapshotSHA256: subject.Snapshot.SHA256, WorkerLeaseID: checkLease.ID, OperationID: checkLease.OperationID}
	inventory := api.ReviewInventory{Manifest: f.measuredBlob("inventory", "manifest", []byte("drained primary stream inventory\n"), lease.OperationID, target),
		ThroughSeq: subject.InventorySeq, ToolRecords: f.measuredBlob("review-tools", "manifest", []byte("measured tool records\n"), lease.OperationID, target),
		ToolCoverage: api.CoverageComplete, Streams: []api.ReviewStreamFact{}}
	for _, stream := range subject.Streams {
		inventory.Streams = append(inventory.Streams, api.ReviewStreamFact{
			BindingID: subject.CaptureBindingID, StreamID: stream.ID, EndOffset: int64(len(stream.ID)), EOF: true, GapIDs: []api.ID{}})
	}
	capture := api.CaptureState{Binding: binding, Generation: 1, LastSeq: subject.InventorySeq, Positions: []api.CapturePosition{}}
	for _, stream := range inventory.Streams {
		capture.Positions = append(capture.Positions, api.CapturePosition{StreamID: stream.StreamID, NextOffset: stream.EndOffset, EOF: stream.EOF})
	}
	f.store.reviewCaptures[binding.ID] = capture
	evidence := api.ReviewEvidence{Schema: "laneboss.review.v2", Subject: subject, VerifierLeaseID: lease.ID,
		Diff:   f.measuredBlob("diff", "diff", []byte("measured workspace diff\n"), lease.OperationID, target),
		Checks: []api.ReviewCheckFact{check}, Inventory: inventory, Resolutions: []api.ReviewResolution{}, Coverage: api.CoverageComplete}
	control := &fixtureReviewControl{f: f, subject: subject, required: []string{"unit"}, evidence: evidence, lease: lease}
	f.service.deps.ReviewControl, f.service.deps.Review = control, control
	return api.ReviewReceipt{ID: "review", Reviewer: f.parent, Diff: evidence.Diff, Checks: []api.BlobRef{check.Receipt},
		RecordInventory: inventory.Manifest, RefusalResolution: []api.ID{}, Coverage: api.CoverageComplete, Evidence: &evidence}
}

func (c *fixtureReviewControl) ResolveReview(_ context.Context, _ api.Scope, target api.LifeRef) (api.ReviewSubject, []string, error) {
	if target != c.subject.Target {
		return api.ReviewSubject{}, nil, launchMissing()
	}
	subject := launchClone(c.f.t, c.subject)
	if c.resolveHook != nil {
		c.resolveHook(&subject)
	}
	return subject, append([]string{}, c.required...), nil
}

func (c *fixtureReviewControl) PrepareReview(_ context.Context, scope api.Scope, request api.ReviewRequest,
	generation api.Generation, endID api.ID, endSeq api.Sequence) (api.ReviewVerifyRequest, error) {
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	original := c.f.store.receipts[fixtureReceiptKey(scope, key)]
	old := c.lease.OperationID
	c.lease.OperationID = original.Operation.ID
	for id, meta := range c.f.store.metadata {
		if meta.SourceOperationID == old {
			meta.SourceOperationID = c.lease.OperationID
			c.f.store.metadata[id] = meta
		}
	}
	for id, row := range c.f.store.reviewEffects {
		if row.Effect.OperationID == old {
			row.Effect.OperationID = c.lease.OperationID
			c.f.store.reviewEffects[id] = row
		}
	}
	c.f.store.reviewWorkers[c.lease.ID] = c.lease
	prepared := api.ReviewVerifyRequest{Lease: c.lease, Request: request, ExpectedGeneration: generation, EndEventID: endID, EndSeq: endSeq}
	if c.prepareHook != nil {
		c.prepareHook(&prepared)
	}
	return prepared, nil
}

func (c *fixtureReviewControl) VerifyReview(_ context.Context, _ api.Scope, request api.ReviewVerifyRequest) (api.ReviewEvidence, error) {
	c.calls++
	if c.err != nil {
		return api.ReviewEvidence{}, c.err
	}
	if !reflect.DeepEqual(request.Lease, c.lease) || request.Request.Target != c.subject.Target ||
		request.EndEventID != c.subject.EndEventID || request.EndSeq != c.subject.EndSeq {
		return api.ReviewEvidence{}, launchConflict()
	}
	evidence := launchClone(c.f.t, c.evidence)
	if c.verifyHook != nil {
		c.verifyHook(&evidence)
	}
	return evidence, nil
}

func resealReviewInput(c *fixtureReviewControl) {
	c.f.t.Helper()
	raw, err := json.Marshal(c.subject)
	if err != nil {
		c.f.t.Fatal(err)
	}
	c.lease.Input = c.f.measuredBlob(c.lease.Input.ID, "manifest", raw, c.lease.OperationID, c.subject.Target)
	c.f.store.reviewWorkers[c.lease.ID] = c.lease
	effect := c.f.store.reviewEffects[c.lease.EffectID]
	effect.Effect.Worker.Input = c.lease.Input
	c.f.store.reviewEffects[c.lease.EffectID] = effect
}

func (f *launchFixture) allowCaptureRefusal() {
	f.store.policy.AllowCaptureRefusal = true
	f.store.policy.CaptureRefusalApprovalID = "consumed-capture-exception"
}
