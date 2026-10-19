package api

import (
	"encoding/json"
	"testing"
)

func reviewFixture(t *testing.T) (Scope, ReviewSubject, ReviewReceipt) {
	t.Helper()
	p := launchFixture(t)
	subject := ReviewSubject{Target: p.Reservation.Target, LaunchID: p.Reservation.LaunchID, Generation: 2, EndEventID: "end-event", EndSeq: 10,
		Snapshot: p.Data.Workspace.Snapshot, SessionID: p.Runner.Session.ID, InventorySeq: 20, CaptureBindingID: p.Capture.ID,
		Streams: p.Capture.Streams, RefusalIDs: []ID{"refusal-one"}}
	evidence := &ReviewEvidence{Schema: "laneboss.review.v2", Subject: subject, VerifierLeaseID: "review-worker", Diff: launchFixtureBlob("diff-one", "diff"),
		Checks: []ReviewCheckFact{{Name: "unit", Receipt: launchFixtureBlob("check-one", "check"), Target: subject.Target, EndSeq: subject.EndSeq,
			SnapshotSHA256: subject.Snapshot.SHA256, ExitCode: 0, WorkerLeaseID: "check-worker", OperationID: "check-operation"}},
		Inventory: ReviewInventory{Manifest: launchFixtureBlob("inventory", "manifest"), ThroughSeq: subject.InventorySeq,
			ToolRecords: launchFixtureBlob("tool-records", "manifest"), ToolCoverage: CoverageComplete, Streams: []ReviewStreamFact{}},
		Resolutions: []ReviewResolution{{RefusalID: "refusal-one", EventSeq: 9, Evidence: launchFixtureBlob("resolution", "manifest")}}, Coverage: CoverageComplete}
	for _, stream := range subject.Streams {
		evidence.Inventory.Streams = append(evidence.Inventory.Streams, ReviewStreamFact{BindingID: subject.CaptureBindingID, StreamID: stream.ID,
			EndOffset: 32, EOF: true, GapIDs: []ID{}})
	}
	scope := Scope{Config: "demo", Actor: Actor{Kind: "human", ID: "reviewer-one"}}
	receipt := ReviewReceipt{ID: "review-one", Reviewer: scope.Actor, Diff: evidence.Diff, Checks: []BlobRef{evidence.Checks[0].Receipt},
		RecordInventory: evidence.Inventory.Manifest, RefusalResolution: []ID{"refusal-one"}, Coverage: CoverageComplete, Evidence: evidence}
	return scope, subject, receipt
}

func TestReviewCoverageSchema(t *testing.T) {
	_, subject, receipt := reviewFixture(t)
	for _, coverage := range []string{CoverageComplete, CoveragePartial, CoverageUnsupported, CoverageMissing} {
		evidence := *receipt.Evidence
		evidence.Coverage = coverage
		if err := ValidateReviewEvidence(evidence, subject); err != nil {
			t.Fatal(err)
		}
	}
	for _, fault := range []string{"coverage", "run", "end", "snapshot", "inventory", "streams"} {
		t.Run(fault, func(t *testing.T) {
			_, expected, r := reviewFixture(t)
			switch fault {
			case "coverage":
				r.Evidence.Coverage = "invented"
			case "run":
				r.Evidence.Subject.Target.Run++
			case "end":
				r.Evidence.Subject.EndSeq++
			case "snapshot":
				r.Evidence.Checks[0].SnapshotSHA256 = launchFixtureBlob("other-tree", "manifest").SHA256
			case "inventory":
				r.Evidence.Inventory.ThroughSeq = expected.EndSeq - 1
			case "streams":
				expected.Streams = append(expected.Streams, expected.Streams[0])
				r.Evidence.Subject = expected
			}
			requireLaunchInvalid(t, ValidateReviewEvidence(*r.Evidence, expected), "review evidence gate was bypassed")
		})
	}
}

func TestReviewAcceptance(t *testing.T) {
	scope, subject, receipt := reviewFixture(t)
	if err := ValidateReviewAcceptance(scope, receipt, subject, []string{"unit"}); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"self", "check_exit", "required", "tool_gap", "eof", "resolution", "missing"} {
		t.Run(fault, func(t *testing.T) {
			s, expected, r := reviewFixture(t)
			switch fault {
			case "self":
				s.Actor = Actor{Kind: "lane", ID: "self", LifeID: expected.Target.LifeID}
				r.Reviewer = s.Actor
			case "check_exit":
				r.Evidence.Checks[0].ExitCode = 1
			case "required":
				r.Evidence.Checks = nil
				r.Checks = nil
			case "tool_gap":
				r.Evidence.Inventory.ToolCoverage = CoveragePartial
			case "eof":
				r.Evidence.Inventory.Streams[0].EOF = false
			case "resolution":
				r.Evidence.Resolutions = nil
				r.RefusalResolution = nil
			case "missing":
				r.Evidence = nil
			}
			requireLaunchInvalid(t, ValidateReviewAcceptance(s, r, expected, []string{"unit"}), "review acceptance gate was bypassed")
		})
	}
}

func TestCheckNaturalStateWrite(t *testing.T) {
	zero, survivors := 0, uint64(0)
	observation := ProcessObservation{Handle: ProcessHandle{ID: "process-one", Target: LifeRef{LifeID: "child", Run: 1}, ContainmentID: "containment", Generation: "kernel-one"},
		State: "exited", ExitCode: &zero, Survivors: &survivors, PromptStatus: "completed", ObservedAt: "2026-01-01T00:00:00Z"}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	tx := Transaction{Scope: Scope{Config: "demo", Actor: Actor{Kind: "lane", ID: "parent", LifeID: "parent-life", Level: 6}, Request: Request{Method: "lane.check"}},
		Reply: &RPCReply{Result: raw}, Writes: StateWrites{Lanes: []Lane{{LifeID: "child", Run: 1, Generation: 2, State: "verifying"}}},
		Events: []Event{{Kind: "lane.ended"}, {Kind: "lane.state"}}, Compare: []Compare{{Kind: CompareLane, ID: "child", Generation: 1}},
		Guards: []TransactionGuard{{Cancellation: &CancellationCheck{LifeID: "child", Epoch: 1}}}}
	if err := ValidateTransactionShape(tx); err != nil {
		t.Fatalf("natural completion state transition was refused: %v", err)
	}
}
