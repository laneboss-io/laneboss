package dataworker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/testjob"
)

// Native identity/bootstrap are explicit component doubles. The candidate,
// executable, command exit and captured output are actual files/processes.
func nativeTestFixture(t *testing.T, mode string) (TestJob, *archivePorts, string) {
	t.Helper()
	base, ports := archiveFixture(t, "valid")
	executable, err := os.Open("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := executable.Close(); err != nil {
			t.Error(err)
		}
	})
	pin, err := hashOpenTestFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	put := func(id api.ID, class string, raw []byte) api.BlobRef {
		ports.objects[id] = raw
		return api.BlobRef{ID: id, Class: class, Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}
	}
	expected := filepath.Base(t.TempDir()) + "-" + mode
	script := []byte("#!/bin/sh\nset -eu\nIFS= read -r measured < input.txt\nprintf '%s' \"$measured\"\nprintf 'actual-stderr' >&2\ntest \"$measured\" = \"$1\"\n")
	input := put("candidate-content", "artifact", []byte(expected+"\n"))
	command := put("candidate-script", "artifact", script)
	raw, err := json.Marshal(api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "input.txt", Kind: "file", Mode: 0600, Content: &input}, {Path: "task.sh", Kind: "file", Mode: 0700, Content: &command}}})
	if err != nil {
		t.Fatal(err)
	}
	candidate := put("candidate-tree", "manifest", raw)
	p := base.Principal
	budget := p.Claim.Record.Effect.Worker.Budget
	budget.WallMS, budget.MemoryBytes, budget.DiskBytes = 1000, 32<<20, 1<<20
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", Input: candidate, Budget: budget, GrantSetID: "actual-child-grants",
		Executable: api.Executable{ID: "enrolled-shell", SHA256: pin, Version: "component"}, Argv: []string{"sh", "task.sh", expected}}
	if mode == "failed" {
		plan.Argv[2] += "changed"
	}
	if mode == "executable" {
		plan.Executable.SHA256 = manifest.Hash([]byte("other executable"))
	}
	sealed := testjob.Input{Schema: "laneboss.test-input.v2", Request: api.TestChildRequest{Child: p.Lease.Target, Candidate: candidate, Budget: budget}, Plan: plan,
		Subject: api.ReviewSubject{Target: p.Lease.Target, EndSeq: 7, Snapshot: candidate, Streams: []api.CaptureStreamBinding{}, RefusalIDs: []api.ID{}}, Name: "actual-check"}
	if mode == "subject" {
		sealed.Subject.Target.Run++
	}
	if mode == "budget" {
		sealed.Plan.Budget.Processes++
	}
	if mode == "argv" {
		sealed.Plan.Argv = nil
	}
	raw, err = json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	ref := put("sealed-test", "manifest", raw)
	p.Lease.Kind, p.Lease.Input = "test", ref
	p.Claim.Record.Effect.Worker.Kind, p.Claim.Record.Effect.Worker.Input, p.Claim.Record.Effect.Worker.Budget = "test", ref, budget
	ports.input = api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: p.StageID, LeaseID: p.Lease.ID, Kind: "test",
		OperationID: p.Lease.OperationID, EffectID: p.Lease.EffectID, Input: ref, Bytes: raw}
	if mode == "candidate" {
		ports.objects[input.ID][0] ^= 1
	}
	job := TestJob{Principal: p, Scope: base.Scope, Bootstrap: ports, Read: ports.read, Clock: base.Clock, Workspace: root, Directory: directory, Executable: executable}
	if mode == "identity" {
		job.Scope.Actor.Kind = "lane"
	}
	return job, ports, expected
}

func TestNativeChildWorker(t *testing.T) {
	for _, mode := range []string{"valid", "failed", "executable", "subject", "budget", "argv", "candidate", "identity"} {
		t.Run(mode, func(t *testing.T) {
			job, ports, expected := nativeTestFixture(t, mode)
			ack, err := RunInternalJob(context.Background(), job.Scope.Config,
				[]string{"--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Principal.Lease.ID)}, job)
			if mode != "valid" && mode != "failed" {
				if err == nil || ports.submissions != 0 {
					t.Fatalf("invalid TestChild submitted a result: %s: %v", mode, err)
				}
				return
			}
			if err != nil {
				t.Fatal("native TestChild did not execute actual candidate", err)
			}
			var result testjob.Result
			if api.DecodeObject(ports.result, &result) != nil || ack.Result.SHA256 != manifest.Hash(ports.result) || ports.submissions != 1 ||
				string(result.Stdout) != expected || string(result.Stderr) != "actual-stderr" || result.Check.WorkerLeaseID != job.Principal.Lease.ID ||
				result.StdoutPipeID == "" || result.StderrPipeID == "" || result.StdoutPipeID == result.StderrPipeID {
				t.Fatal("TestChild did not retain its actual output, worker or acknowledgement")
			}
			want := 0
			if mode == "failed" {
				want = 1
			}
			if result.Check.ExitCode != want {
				t.Fatal("TestChild replaced its actual command exit")
			}
		})
	}
}
