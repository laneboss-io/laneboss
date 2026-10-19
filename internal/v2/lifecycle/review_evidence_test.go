package lifecycle

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func reviewRequest(receipt api.ReviewReceipt, target api.LifeRef) api.ReviewRequest {
	return api.ReviewRequest{Target: target, Diff: receipt.Diff, Checks: receipt.Checks,
		RecordInventory: receipt.RecordInventory, RefusalResolution: receipt.RefusalResolution}
}

func TestReviewVerifiedCommit(t *testing.T) {
	f := newFixture(t)
	f.ended()
	candidate := fixtureReview(f)
	control := f.service.deps.ReviewControl.(*fixtureReviewControl)
	request := reviewRequest(candidate, f.target)
	scope := f.scope("lane.review", request, f.parent)
	read := map[api.ID]bool{}
	f.store.blobHook = func(chunk api.BlobChunk) (api.BlobChunk, error) { read[chunk.ObjectID] = true; return chunk, nil }
	receipt, err := f.service.LaneReview(context.Background(), scope, request)
	if err != nil || control.calls != 1 || receipt.ID == "" || receipt.Evidence == nil ||
		!reflect.DeepEqual(*receipt.Evidence, control.evidence) || len(f.store.transactions) != 1 {
		t.Fatalf("complete read-back review did not commit its verifier evidence: %v", err)
	}
	for _, ref := range []api.BlobRef{candidate.Diff, candidate.Checks[0], candidate.RecordInventory,
		control.subject.Snapshot, control.evidence.Inventory.ToolRecords, control.lease.Input, control.lease.RuntimeManifest} {
		if !read[ref.ID] {
			t.Fatalf("complete review omitted actual bytes for %s", ref.Class)
		}
	}
	tx := f.store.transactions[0]
	var stored api.ReviewReceipt
	if len(tx.Events) != 1 || tx.Events[0].Kind != "lane.reviewed" ||
		api.DecodeObject(tx.Events[0].Payload, &stored) != nil || !reflect.DeepEqual(stored, receipt) ||
		tx.Reply == nil || api.DecodeObject(tx.Reply.Result, &stored) != nil || !reflect.DeepEqual(stored, receipt) {
		t.Fatal("review event and original reply lost the exact verified receipt")
	}
	replayed, err := f.service.LaneReview(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(replayed, receipt) || control.calls != 1 || len(f.store.transactions) != 1 {
		t.Fatalf("review retry replaced its actual worker or receipt: %v", err)
	}
	mark := api.MarkRequest{Target: f.target, ExpectedGeneration: f.child.Generation, State: "accepted", Review: receipt}
	if _, err := f.service.LaneMark(context.Background(), f.scope("lane.mark", mark, f.parent), mark); err != nil || f.store.lanes[f.target.LifeID].State != "accepted" {
		t.Fatalf("read-back verifier receipt could not authorize acceptance: %v", err)
	}
}

func TestReviewEvidence(t *testing.T) {
	for _, mode := range []string{"run", "end", "snapshot", "inventory", "coverage", "failed-check", "required-check", "tool-gap", "eof", "claimed-eof", "range", "capture-binding", "capture-streams", "capture-sequence", "capture-position", "stream-gap", "refusal", "objects", "check-job", "job-operation", "provenance", "foreign-verifier", "request-set"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			candidate := fixtureReview(f)
			control := f.service.deps.ReviewControl.(*fixtureReviewControl)
			request := reviewRequest(candidate, f.target)
			switch mode {
			case "run":
				control.evidence.Subject.Target.Run++
			case "end":
				control.evidence.Subject.EndSeq++
			case "snapshot":
				control.evidence.Subject.Snapshot.SHA256 = digestOf([]byte("changed snapshot"))
			case "inventory":
				control.evidence.Inventory.ThroughSeq++
			case "coverage":
				control.evidence.Coverage = "invented"
			case "failed-check":
				control.evidence.Checks[0].ExitCode = 7
			case "required-check":
				control.required = append(control.required, "integration")
			case "tool-gap":
				control.evidence.Inventory.ToolCoverage = api.CoveragePartial
			case "eof":
				control.evidence.Inventory.Streams[0].EOF = false
			case "claimed-eof":
				capture := f.store.reviewCaptures[control.subject.CaptureBindingID]
				capture.Positions[0].EOF = false
				f.store.reviewCaptures[capture.Binding.ID] = capture
			case "range":
				control.evidence.Inventory.Streams[0].EndOffset++
			case "capture-binding", "capture-streams", "capture-sequence", "capture-position":
				capture := launchClone(t, f.store.reviewCaptures[control.subject.CaptureBindingID])
				switch mode {
				case "capture-binding":
					capture.Binding.LaunchID = "foreign-launch"
				case "capture-streams":
					capture.Binding.Streams[0].PipeID = "foreign-pipe"
				case "capture-sequence":
					capture.LastSeq = control.subject.InventorySeq + 1
				case "capture-position":
					capture.Positions = nil
				}
				f.store.reviewCaptures[capture.Binding.ID] = capture
			case "stream-gap":
				control.evidence.Inventory.Streams[0].GapIDs = []api.ID{"unresolved-gap"}
			case "refusal":
				control.subject.RefusalIDs = []api.ID{"unresolved-refusal"}
				control.evidence.Subject = control.subject
				resealReviewInput(control)
			case "objects":
				delete(f.store.blobs, control.evidence.Inventory.ToolRecords.ID)
			case "check-job":
				delete(f.store.reviewWorkers, control.evidence.Checks[0].WorkerLeaseID)
			case "job-operation":
				operation := f.store.operations["check-operation"]
				operation.Status = "running"
				f.store.operations[operation.ID] = operation
			case "provenance":
				meta := f.store.metadata[control.evidence.Inventory.ToolRecords.ID]
				meta.Origin = "upload"
				f.store.metadata[meta.Ref.ID] = meta
			case "foreign-verifier":
				meta := f.store.metadata[control.evidence.Diff.ID]
				meta.SourceOperationID = "foreign-job"
				f.store.metadata[meta.Ref.ID] = meta
			case "request-set":
				request.Diff = f.measuredBlob("candidate-diff", "diff", []byte("different valid diff"), control.lease.OperationID, f.target)
			}
			allowed := captureAllowed(t)
			_, err := f.service.LaneReview(context.Background(), f.scope("lane.review", request, f.parent), request)
			if word := map[string]string{"provenance": "review_evidence_provenance", "foreign-verifier": "review_verifier_provenance"}[mode]; word != "" {
				// Owner R181-R192: verifier evidence provenance is allowed and logged, so the review proceeds.
				if err != nil || !slices.Contains(allowed(), word) {
					t.Fatalf("verifier evidence provenance was not allowed and logged: %s: %v %v", mode, err, allowed())
				}
				return
			}
			if err == nil || len(f.store.transactions) != 0 || f.store.lanes[f.target.LifeID].State != "verifying" {
				t.Fatalf("invalid verifier evidence authorized a review: %s: %v", mode, err)
			}
		})
	}
}

func TestReviewLeaseHandoff(t *testing.T) {
	for _, mode := range []string{"missing", "target", "operation", "runtime", "input", "expiry", "end", "request", "retained", "generation", "owner-error"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			candidate := fixtureReview(f)
			control := f.service.deps.ReviewControl.(*fixtureReviewControl)
			request := reviewRequest(candidate, f.target)
			switch mode {
			case "missing":
				f.service.deps.Review = nil
			case "target":
				control.prepareHook = func(r *api.ReviewVerifyRequest) { r.Lease.Target.Run++ }
			case "operation":
				control.prepareHook = func(r *api.ReviewVerifyRequest) { r.Lease.OperationID = "foreign-operation" }
			case "runtime":
				delete(f.store.blobs, control.lease.RuntimeManifest.ID)
			case "input":
				f.store.blobs[control.lease.Input.ID][0] ^= 1
			case "expiry":
				control.prepareHook = func(r *api.ReviewVerifyRequest) { r.Lease.ExpiresAt = "2029-01-01T00:00:00Z" }
			case "end":
				control.prepareHook = func(r *api.ReviewVerifyRequest) { r.EndEventID = "foreign-end" }
			case "request":
				control.prepareHook = func(r *api.ReviewVerifyRequest) { r.Request.Diff = candidate.RecordInventory }
			case "retained":
				control.prepareHook = func(r *api.ReviewVerifyRequest) { delete(f.store.reviewWorkers, r.Lease.ID) }
			case "generation":
				control.resolveHook = func(s *api.ReviewSubject) { s.Generation++ }
			case "owner-error":
				control.err = api.NotImplemented("lb-v2-grants", "fixture real review worker")
			}
			_, err := f.service.LaneReview(context.Background(), f.scope("lane.review", request, f.parent), request)
			if err == nil || len(f.store.transactions) != 0 {
				t.Fatalf("foreign review worker handoff produced a receipt: %s: %v", mode, err)
			}
			if mode == "owner-error" && err != control.err {
				t.Fatal("review hid its owning verifier error")
			}
		})
	}
}

func TestReviewMarkRechecks(t *testing.T) {
	for _, mode := range []string{"historical", "snapshot", "required-check", "tool-bytes", "check-job", "end", "operation"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			receipt := fixtureReview(f)
			control := f.service.deps.ReviewControl.(*fixtureReviewControl)
			if mode == "historical" {
				receipt.Evidence = nil
			}
			f.add("lane.reviewed", receipt, f.target.Run, "service", f.parent)
			switch mode {
			case "snapshot":
				control.subject.Snapshot = f.measuredBlob("changed-snapshot", "manifest", []byte("changed tree"), "snapshot-operation", f.target)
			case "required-check":
				control.required = append(control.required, "integration")
			case "tool-bytes":
				delete(f.store.blobs, control.evidence.Inventory.ToolRecords.ID)
			case "check-job":
				delete(f.store.reviewWorkers, "check-worker")
			case "end":
				f.ended()
			case "operation":
				f.store.events[len(f.store.events)-1].OperationID = "foreign-review-job"
			}
			request := api.MarkRequest{Target: f.target, ExpectedGeneration: f.child.Generation, State: "accepted", Review: receipt}
			allowed := captureAllowed(t)
			_, err := f.service.LaneMark(context.Background(), f.scope("lane.mark", request, f.parent), request)
			if mode == "operation" {
				// Owner R181-R192: the review event's verifier operation provenance is allowed and logged, so the mark commits.
				if err != nil || len(f.store.transactions) == 0 || !slices.Contains(allowed(), "review_verifier_operation") {
					t.Fatalf("review verifier operation was not allowed and logged: %v %v", err, allowed())
				}
				return
			}
			if err == nil || len(f.store.transactions) != 0 || f.store.lanes[f.target.LifeID].State != "verifying" {
				t.Fatalf("stale or historical review authorized acceptance: %s: %v", mode, err)
			}
		})
	}
}

func TestReviewPartialRetained(t *testing.T) {
	f := newFixture(t)
	f.ended()
	candidate := fixtureReview(f)
	control := f.service.deps.ReviewControl.(*fixtureReviewControl)
	control.evidence.Coverage, control.evidence.Inventory.ToolCoverage = api.CoveragePartial, api.CoveragePartial
	request := reviewRequest(candidate, f.target)
	scope := f.scope("lane.review", request, f.parent)
	receipt, err := f.service.LaneReview(context.Background(), scope, request)
	if err != nil || receipt.Coverage != api.CoveragePartial || len(f.store.transactions) != 1 {
		t.Fatalf("measured partial review was not retained: %v", err)
	}
	replayed, err := f.service.LaneReview(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(replayed, receipt) || control.calls != 1 {
		t.Fatalf("partial review replay lost its retained evidence: %v", err)
	}
	mark := api.MarkRequest{Target: f.target, ExpectedGeneration: f.child.Generation, State: "accepted", Review: receipt}
	_, err = f.service.LaneMark(context.Background(), f.scope("lane.mark", mark, f.parent), mark)
	if err == nil || len(f.store.transactions) != 1 {
		t.Fatalf("partial review authorized acceptance: %v", err)
	}
}

func TestReviewWaitRechecks(t *testing.T) {
	f := newFixture(t)
	f.ended()
	candidate := fixtureReview(f)
	control := f.service.deps.ReviewControl.(*fixtureReviewControl)
	control.verifyHook = func(*api.ReviewEvidence) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		unlock, err := f.service.lockLife(ctx, f.target.LifeID)
		if err != nil {
			t.Fatal("review held the life gate while waiting for its verifier")
		}
		defer unlock()
		lane := f.store.lanes[f.target.LifeID]
		lane.CancellationEpoch++
		f.store.lanes[lane.LifeID] = lane
	}
	request := reviewRequest(candidate, f.target)
	_, err := f.service.LaneReview(context.Background(), f.scope("lane.review", request, f.parent), request)
	if err == nil || len(f.store.transactions) != 0 {
		t.Fatalf("review committed after cancellation during its worker wait: %v", err)
	}
}
