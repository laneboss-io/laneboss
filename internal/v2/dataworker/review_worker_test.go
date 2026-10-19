package dataworker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// Bootstrap, native identity and prior test/capture facts are explicit
// component inputs. This executes the real verifier over actual object bytes;
// it makes no claim to a helper launch, kernel containment or installed pass.
func reviewWorkerFixture(t *testing.T, mode string) (ReviewJob, *archivePorts) {
	t.Helper()
	baseJob, ports := archiveFixture(t, "valid")
	p := baseJob.Principal
	put := func(id api.ID, class string, value any) api.BlobRef {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		ports.objects[id] = raw
		return api.BlobRef{ID: id, Class: class, Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}
	}
	content := make([]byte, 43)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}
	oldBytes, newBytes := append([]byte("before:"), content...), append([]byte("after:"), content...)
	old := api.BlobRef{ID: "base-content", Class: "artifact", Bytes: int64(len(oldBytes)), SHA256: manifest.Hash(oldBytes)}
	changed := api.BlobRef{ID: "changed-content", Class: "artifact", Bytes: int64(len(newBytes)), SHA256: manifest.Hash(newBytes)}
	ports.objects[old.ID], ports.objects[changed.ID] = oldBytes, newBytes
	before := api.ObjectEntry{Path: "file.txt", Kind: "file", Mode: 0600, Content: &old}
	after := api.ObjectEntry{Path: "file.txt", Kind: "file", Mode: 0600, Content: &changed}
	base := put("base-tree", "manifest", api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{before}})
	frozen := after
	frozen.Path = "work/file.txt"
	current := put("current-tree", "manifest", api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{frozen}})
	subject := api.ReviewSubject{Target: p.Lease.Target, LaunchID: "subject-launch", Generation: 5, EndEventID: "subject-end", EndSeq: 9,
		Snapshot: current, SessionID: "subject-session", InventorySeq: 12, CaptureBindingID: "subject-capture",
		Streams: []api.CaptureStreamBinding{{ID: "stdout", PipeID: "out-pipe", Stream: "stdout"}, {ID: "stderr", PipeID: "err-pipe", Stream: "stderr"}}, RefusalIDs: []api.ID{}}
	diffValue := reviewjob.Diff{Schema: "laneboss.review-diff.v2", Base: base.SHA256, Current: current.SHA256,
		Changes: []reviewjob.Change{{Path: before.Path, Before: &before, After: &after}}}
	if mode == "diff" {
		diffValue.Changes = []reviewjob.Change{}
	}
	diff := put("candidate-diff", "diff", diffValue)
	checkRecord := reviewjob.CheckRecord{Schema: "laneboss.check.v2", Name: "unit", Target: subject.Target, EndSeq: subject.EndSeq,
		SnapshotSHA256: current.SHA256, ExitCode: 0, WorkerLeaseID: "test-worker", OperationID: "test-operation"}
	if mode == "failed-check" {
		checkRecord.ExitCode = 7
	}
	check := put("candidate-check", "check", checkRecord)
	checkFact := api.ReviewCheckFact{Name: checkRecord.Name, Receipt: check, Target: checkRecord.Target, EndSeq: checkRecord.EndSeq,
		SnapshotSHA256: checkRecord.SnapshotSHA256, ExitCode: checkRecord.ExitCode, WorkerLeaseID: checkRecord.WorkerLeaseID, OperationID: checkRecord.OperationID}
	if mode == "check-bytes" {
		checkRecord.ExitCode = 3
		check = put(check.ID, "check", checkRecord)
		checkFact.Receipt = check
	}
	tools := put("tool-records", "manifest", api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}})
	inventory := api.ReviewInventory{ThroughSeq: subject.InventorySeq, ToolRecords: tools, ToolCoverage: api.CoverageComplete,
		Streams: []api.ReviewStreamFact{{BindingID: subject.CaptureBindingID, StreamID: "stdout", EndOffset: int64(len(newBytes)), EOF: true, GapIDs: []api.ID{}},
			{BindingID: subject.CaptureBindingID, StreamID: "stderr", EOF: true, GapIDs: []api.ID{}}}}
	if mode == "partial" {
		inventory.ToolCoverage = api.CoveragePartial
	}
	if mode == "gap" {
		inventory.Streams[0].GapIDs = []api.ID{"gap"}
	}
	if mode == "eof" {
		inventory.Streams[0].EOF = false
	}
	record := reviewjob.InventoryRecord{Schema: "laneboss.review-inventory.v2", ThroughSeq: inventory.ThroughSeq, Streams: inventory.Streams,
		ToolRecords: inventory.ToolRecords, ToolCoverage: inventory.ToolCoverage}
	if mode == "inventory" {
		record.ThroughSeq++
	}
	inventory.Manifest = put("candidate-inventory", "manifest", record)
	request := api.ReviewRequest{Target: subject.Target, Diff: diff, Checks: []api.BlobRef{check}, RecordInventory: inventory.Manifest, RefusalResolution: []api.ID{}}
	input := reviewjob.Input{Schema: "laneboss.review-input.v2", Subject: subject, Request: request, Required: []string{"unit"}, Base: base,
		Checks: []api.ReviewCheckFact{checkFact}, Inventory: inventory, Resolutions: []api.ReviewResolution{}}
	if mode == "required" {
		input.Required = append(input.Required, "integration")
	}
	ref := put("review-input", "manifest", input)
	p.Lease.Kind, p.Lease.Input = "export", ref
	p.Claim.Record.Effect.Worker.Kind, p.Claim.Record.Effect.Worker.Input = "export", ref
	ports.input = api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: p.StageID, LeaseID: p.Lease.ID, Kind: p.Lease.Kind,
		OperationID: p.Lease.OperationID, EffectID: p.Lease.EffectID, Input: ref, Bytes: ports.objects[ref.ID]}
	if mode == "artifact" {
		ports.objects[changed.ID][0] ^= 1
	}
	job := ReviewJob{Principal: p, Scope: baseJob.Scope, Bootstrap: ports, Read: ports.read, Clock: baseJob.Clock}
	if mode == "identity" {
		job.Scope.Actor = p.Claim.Record.Effect.Context.RequestedBy
	}
	if mode == "expired" {
		job.Clock = workerClock{baseJob.Clock.Now().Add(2 * time.Minute)}
	}
	return job, ports
}

func TestReviewWorker(t *testing.T) {
	for _, mode := range []string{"valid", "partial", "gap", "eof", "failed-check", "required", "diff", "check-bytes", "inventory", "artifact", "identity", "expired"} {
		t.Run(mode, func(t *testing.T) {
			job, ports := reviewWorkerFixture(t, mode)
			ack, err := RunInternalJob(context.Background(), job.Scope.Config,
				[]string{"--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Principal.Lease.ID)}, job)
			partial := mode == "partial" || mode == "gap" || mode == "eof" || mode == "failed-check" || mode == "required"
			if mode != "valid" && !partial {
				if err == nil || ports.submissions != 0 {
					t.Fatalf("invalid review input submitted a result: %s: %v", mode, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("fixed review entry did not execute the verifier: %s: %v", mode, err)
			}
			var evidence api.ReviewEvidence
			if api.DecodeObject(ports.result, &evidence) != nil || ports.submissions != 1 || ack.Result.SHA256 != manifest.Hash(ports.result) {
				t.Fatal("review did not retain its exact measured output")
			}
			want := api.CoverageComplete
			if partial {
				want = api.CoveragePartial
			}
			if evidence.Coverage != want || evidence.Subject.Target != job.Principal.Lease.Target || evidence.VerifierLeaseID != job.Principal.Lease.ID {
				t.Fatalf("review changed its subject or promoted incomplete evidence: %s: %s", mode, evidence.Coverage)
			}
		})
	}
}
