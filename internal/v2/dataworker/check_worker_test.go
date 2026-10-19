package dataworker

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// The existing component bootstrap is deliberately post-authentication. Reads
// use actual retained tree bytes; this is not native launch acceptance.
func TestCheckWorker(t *testing.T) {
	for _, fault := range []string{"current", "content", "plan", "subject", "kind"} {
		t.Run(fault, func(t *testing.T) {
			job, ports := reviewWorkerFixture(t, "valid")
			var prior reviewjob.Input
			if err := api.DecodeObject(ports.input.Bytes, &prior); err != nil {
				t.Fatal(err)
			}
			p := &job.Principal
			p.Lease.Kind, p.Claim.Record.Effect.Worker.Kind = "test", "test"
			declared := *p.Claim.Record.Effect.Worker
			declared.Argv = []string{"laneboss", "check", reviewjob.SnapshotIntegrity}
			declared.Input = prior.Base
			input := reviewjob.CheckInput{Schema: "laneboss.check-input.v2", Subject: prior.Subject, Request: api.TestChildRequest{Child: prior.Subject.Target, Candidate: prior.Base, TestPlan: api.BlobRef{ID: "declared-plan", Class: "manifest"}, Budget: declared.Budget},
				Plan: declared, Required: []string{reviewjob.SnapshotIntegrity}, Base: prior.Base}
			switch fault {
			case "content":
				ports.objects["changed-content"][0] ^= 1
			case "plan":
				input.Plan.Argv[2] = "unknown-check"
			case "subject":
				input.Subject.Target.Run++
			case "kind":
				p.Lease.Kind = "export"
			}
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			ref := api.BlobRef{ID: "check-input", Class: "manifest", Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}
			p.Lease.Input, p.Claim.Record.Effect.Worker.Input = ref, ref
			ports.input.Kind, ports.input.Input, ports.input.Bytes = p.Lease.Kind, ref, raw
			ack, err := RunInternalJob(context.Background(), job.Scope.Config, []string{"--binding", "/runtime/laneboss-worker.json", "--lease", string(p.Lease.ID)}, job)
			if fault != "current" {
				if err == nil || ports.submissions != 0 {
					t.Fatal("invalid native check submitted a result", fault, err)
				}
				return
			}
			if err != nil {
				t.Fatal("fixed test job did not execute its actual snapshot check", err)
			}
			var output reviewjob.CheckResult
			if api.DecodeObject(ports.result, &output) != nil || len(output.Checks) != 1 || output.Checks[0].Name != reviewjob.SnapshotIntegrity || output.Checks[0].WorkerLeaseID != p.Lease.ID || output.Checks[0].SnapshotSHA256 != prior.Subject.Snapshot.SHA256 ||
				len(output.Diff.Changes) != 1 || output.Diff.Changes[0].Path != "file.txt" || ack.Result.SHA256 != manifest.Hash(ports.result) || ports.submissions != 1 {
				t.Fatal("native check did not retain its actual subject, diff and measured receipt")
			}
		})
	}
}
