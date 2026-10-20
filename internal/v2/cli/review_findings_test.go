package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// The service reply is a component input. Findings come from the production
// generator; this tests the real file-input, response and diagnostic paths.
func TestReviewFindingCLIOutput(t *testing.T) {
	for _, test := range []struct{ name, path, kind, coverage, nullField string }{
		{"fake-complete", "internal/cache_test.go", "fake_only_diff", api.CoverageComplete, ""},
		{"fake-partial", "internal/cache_test.go", "fake_only_diff", api.CoveragePartial, ""},
		{"empty-complete", "", "empty_diff", api.CoverageComplete, ""},
		{"empty-partial", "", "empty_diff", api.CoveragePartial, ""},
		{"trusted", "internal/cache.go", "", api.CoverageComplete, ""},
		{"null-subject-streams", "internal/cache_test.go", "fake_only_diff", api.CoverageComplete, "evidence.subject.streams"},
		{"null-refusal-ids", "internal/cache_test.go", "fake_only_diff", api.CoverageComplete, "evidence.subject.refusal_ids"},
		{"null-checks", "internal/cache_test.go", "fake_only_diff", api.CoverageComplete, "evidence.checks"},
		{"null-inventory-streams", "internal/cache_test.go", "fake_only_diff", api.CoverageComplete, "evidence.inventory.streams"},
		{"null-gap-ids", "internal/cache_test.go", "fake_only_diff", api.CoverageComplete, "evidence.inventory.streams[].gap_ids"},
		{"null-resolutions", "internal/cache_test.go", "fake_only_diff", api.CoverageComplete, "evidence.resolutions"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ref := api.BlobRef{ID: "candidate-diff", Class: "diff", Bytes: 1, SHA256: api.Digest(strings.Repeat("a", 64))}
			check, inventory := ref, ref
			check.ID, check.Class = "unit-check", "check"
			inventory.ID, inventory.Class = "inventory", "manifest"
			request := api.ReviewRequest{Target: api.LifeRef{LifeID: "reviewed-life", Run: 1}, Diff: ref,
				Checks: []api.BlobRef{check}, RecordInventory: inventory, RefusalResolution: []api.ID{}}
			diff := reviewjob.Diff{Changes: []reviewjob.Change{}}
			if test.path != "" {
				diff.Changes = append(diff.Changes, reviewjob.Change{Path: test.path})
			}
			snapshot, tools := inventory, inventory
			snapshot.ID, tools.ID = "review-snapshot", "tool-records"
			subject := api.ReviewSubject{Target: request.Target, LaunchID: "reviewed-launch", Generation: 2,
				EndEventID: "run-ended", EndSeq: 10, Snapshot: snapshot, SessionID: "reviewed-session", InventorySeq: 12,
				CaptureBindingID: "reviewed-capture", RefusalIDs: []api.ID{},
				Streams: []api.CaptureStreamBinding{{ID: "review-stdout", Stream: "stdout", PipeID: "stdout-pipe"},
					{ID: "review-stderr", Stream: "stderr", PipeID: "stderr-pipe"}}}
			checks := []api.ReviewCheckFact{{Name: "unit", Receipt: check, Target: subject.Target, EndSeq: subject.EndSeq,
				SnapshotSHA256: snapshot.SHA256, ExitCode: 0, WorkerLeaseID: "unit-worker", OperationID: "unit-operation"}}
			findings := reviewjob.DiffFindings(diff, checks)
			evidence := &api.ReviewEvidence{Schema: "laneboss.review.v2", Subject: subject, VerifierLeaseID: "review-worker",
				Diff: ref, Checks: checks, Resolutions: []api.ReviewResolution{}, Coverage: test.coverage,
				Findings: findings, Untrusted: len(findings) != 0,
				Inventory: api.ReviewInventory{Manifest: inventory, ThroughSeq: subject.InventorySeq,
					ToolRecords: tools, ToolCoverage: test.coverage, Streams: []api.ReviewStreamFact{}}}
			for _, stream := range subject.Streams {
				evidence.Inventory.Streams = append(evidence.Inventory.Streams, api.ReviewStreamFact{
					BindingID: subject.CaptureBindingID, StreamID: stream.ID, EOF: true, GapIDs: []api.ID{}})
			}
			receipt := api.ReviewReceipt{ID: "review-receipt", Reviewer: api.Actor{Kind: "human", ID: "reviewer"},
				Coverage: test.coverage, Diff: ref, Checks: request.Checks, RecordInventory: inventory,
				RefusalResolution: []api.ID{}, Evidence: evidence}
			// Required collections must be arrays on the wire, including when
			// empty. Validate the component input before any negative mutation;
			// the command still crosses its real typed-result integrity gate.
			if err := api.ValidateReviewEvidence(*evidence, subject); err != nil {
				t.Fatal("review fixture has invalid evidence", err)
			}
			if test.coverage == api.CoverageComplete {
				if err := api.ValidateReviewAcceptance(api.Scope{Actor: receipt.Reviewer}, receipt, subject, []string{"unit"}); err != nil {
					t.Fatal("complete review fixture is not production-shaped", err)
				}
			}
			valid, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			var decoded api.ReviewReceipt
			if err := api.DecodeObject(valid, &decoded); err != nil {
				t.Fatal("review fixture violates the strict result shape", err)
			}
			switch test.nullField {
			case "":
			case "evidence.subject.streams":
				evidence.Subject.Streams = nil
			case "evidence.subject.refusal_ids":
				evidence.Subject.RefusalIDs = nil
			case "evidence.checks":
				evidence.Checks = nil
			case "evidence.inventory.streams":
				evidence.Inventory.Streams = nil
			case "evidence.inventory.streams[].gap_ids":
				evidence.Inventory.Streams[0].GapIDs = nil
			case "evidence.resolutions":
				evidence.Resolutions = nil
			default:
				t.Fatal("unknown null-array control")
			}
			transport := &integrateFixtureClient{handle: func(frame api.Request) (any, error) {
				if frame.Method != "lane.review" {
					return nil, errors.New("review CLI changed the selected method")
				}
				var actual api.ReviewRequest
				if err := api.DecodeObject(frame.Params, &actual); err != nil {
					return nil, err
				}
				if actual.Target != request.Target || actual.Diff != request.Diff {
					return nil, errors.New("review CLI changed the file input")
				}
				return receipt, nil
			}}
			var output, diagnostic bytes.Buffer
			call := Invocation{Config: "demo", Method: "lane.review", Stdout: &output, Stderr: &diagnostic,
				IdempotencyKey:  api.ID(strings.Repeat("r", 32)),
				integrateSocket: &integrateSocket{options: client.Options{Config: "demo"}, connection: transport}}
			path := integrateFixtureFile(t, t.TempDir(), "review-request.json", request)
			err = call.invokeFile(context.Background(), path)
			if test.nullField != "" {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "service result does not match the typed method" ||
					output.Len() != 0 || diagnostic.Len() != 0 || len(transport.requests) != 1 {
					t.Fatalf("CLI accepted a null required collection or bypassed its result gate: field=%s err=%v", test.nullField, err)
				}
				return
			}
			if err != nil {
				t.Fatal("real review CLI response failed", err)
			}
			want, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bytes.TrimSpace(output.Bytes()), want) || len(transport.requests) != 1 {
				t.Fatal("review diagnostic changed the reusable JSON receipt or repeated the operation")
			}
			if test.kind == "" {
				if diagnostic.Len() != 0 {
					t.Fatalf("trusted review printed an advisory: %s", diagnostic.String())
				}
				return
			}
			if !strings.Contains(diagnostic.String(), test.kind) || !strings.Contains(diagnostic.String(), test.coverage) ||
				!strings.Contains(diagnostic.String(), "untrusted") {
				t.Fatalf("CLI review coverage omitted its finding kind: %q", diagnostic.String())
			}
		})
	}
}
