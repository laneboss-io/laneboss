package store

import (
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/reviewjob"
	"laneboss.io/laneboss/internal/v2/testjob"
)

func TestNativeChildResultPins(t *testing.T) {
	for _, mode := range []string{"valid", "worker", "snapshot", "target", "exit", "name", "pipe"} {
		t.Run(mode, func(t *testing.T) {
			subject := api.ReviewSubject{Target: api.LifeRef{LifeID: "actual-child", Run: 3}, EndSeq: 19, Snapshot: api.BlobRef{SHA256: api.Digest(hash([]byte(t.Name())))}}
			r := reviewRecord{Test: &testjob.Input{Subject: subject, Name: "measured-check"}}
			r.Job.Lease.ID, r.Job.Intent.OperationID = "actual-worker", "actual-operation"
			result := testjob.Result{Schema: "laneboss.test-result.v2", Stdout: []byte(t.Name()), Stderr: []byte{}, StdoutPipeID: "component-out-pipe", StderrPipeID: "component-err-pipe", Check: reviewjob.CheckRecord{
				Schema: "laneboss.check.v2", Name: r.Test.Name, Target: subject.Target, EndSeq: subject.EndSeq, SnapshotSHA256: subject.Snapshot.SHA256,
				WorkerLeaseID: r.Job.Lease.ID, OperationID: r.Job.Intent.OperationID}}
			switch mode {
			case "worker":
				result.Check.WorkerLeaseID = "another-worker"
			case "snapshot":
				result.Check.SnapshotSHA256 = api.Digest(hash([]byte("another snapshot")))
			case "target":
				result.Check.Target.Run++
			case "exit":
				result.Check.ExitCode = 256
			case "name":
				result.Check.Name = "another-check"
			case "pipe":
				result.StderrPipeID = result.StdoutPipeID
			}
			raw, err := json.Marshal(result)
			if err == nil {
				raw, err = api.CanonicalJSON(raw)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = validateTestOutput(r, raw)
			if mode == "valid" && err != nil {
				t.Fatal("measured TestChild result was rejected", err)
			}
			if mode != "valid" && err == nil {
				t.Fatalf("TestChild accepted changed result pins: %s", mode)
			}
		})
	}
}
