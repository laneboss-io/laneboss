//go:build linux

package dashboardcase

import "testing"

func TestDashboardNativeChildControls(t *testing.T) {
	root := "../../../.."
	var records [][]byte
	for _, row := range []struct{ pkg, test, file, before, after, diagnostic string }{
		{"dataworker", "TestNativeChildWorker/valid", "dataworker/test_worker.go", "Stdout: append([]byte{}, stdout.Bytes()...)", "Stdout: []byte{}", "TestChild did not retain its actual output"},
		{"dataworker", "TestNativeChildWorker/failed", "dataworker/test_worker.go", "code = exited.ExitCode()", "code = 0", "TestChild replaced its actual command exit"},
		{"dataworker", "TestNativeChildWorker/executable", "dataworker/test_worker.go", "digest != plan.Executable.SHA256", "digest != plan.Executable.SHA256 && false", "invalid TestChild submitted a result: executable"},
		{"dataworker", "TestNativeChildWorker/subject", "dataworker/test_worker.go", "input.Subject.Target != p.Lease.Target", "false", "invalid TestChild submitted a result: subject"},
		{"dataworker", "TestNativeChildWorker/budget", "dataworker/test_worker.go", "plan.Budget != p.Claim.Record.Effect.Worker.Budget", "false", "invalid TestChild submitted a result: budget"},
		{"dataworker", "TestNativeChildWorker/identity", "dataworker/test_worker.go", "job.Scope.Actor != p.Record.Actor", "false", "invalid TestChild submitted a result: identity"},
		{"dataworker", "TestNativeChildDispatch", "dataworker/service.go", "return control.SubmitChildTest(ctx, call, request, grants)", "return control.SubmitChildTest(ctx, call, request, api.GrantSet{})", "TestChild did not hand the exact scoped request and child grants"},
		{"service", "TestNativeChildSubmit", "service/test_child.go", "Guards: call.Guards", "Guards: nil", "TestChild detached its proof, native request or worker effect"},
		{"service", "TestNativeChildMissingGuard", "service/test_child.go", "call.Scope.Actor.Kind == \"human\" &&", "call.Scope.Actor.Kind == \"worker\" &&", "TestChild accepted a missing atomic human guard"},
		{"service", "TestNativeChildFrame", "service/test_child.go", "!reflect.DeepEqual(framed, caller.Request)", "false", "TestChild accepted a different native frame"},
		{"service", "TestNativeChildActor", "service/test_child.go", "current.Actor != caller.Actor", "false", "TestChild accepted a replaced native actor"},
		{"service", "TestNativeChildCaptureWait", "service/test_child.go", "position.StreamID == stream.ID && position.EOF", "position.StreamID == stream.ID", "TestChild froze before every primary EOF was observed"},
		{"grants", "TestHumanWorkerGuard", "grants/service.go", "call.Guards = []api.TransactionGuard{guard}", "_ = guard; call.Guards = nil", "human job lost its exact native frame or atomic proof guard"},
		{"store", "TestNativeChildWriter", "store/test_result.go", "return appendEvent(\"worker.completed\", api.WorkerEvent{WorkerID: r.Job.Lease.ID, Kind: \"test\", Input: r.Test.Request.TestPlan, Output: &r.Ack.Receipt.Result, Status: \"succeeded\"})", "return nil", "TestChild omitted its measured check, actual capture, worker or release"},
		{"store", "TestNativeChildResultPins/worker", "store/test_result.go", "c.WorkerLeaseID != r.Job.Lease.ID", "false", "TestChild accepted changed result pins: worker"},
		{"store", "TestNativeChildResultPins/snapshot", "store/test_result.go", "c.SnapshotSHA256 != input.Subject.Snapshot.SHA256", "false", "TestChild accepted changed result pins: snapshot"},
		{"store", "TestNativeChildResultPins/target", "store/test_result.go", "c.Target != input.Subject.Target", "false", "TestChild accepted changed result pins: target"},
		{"store", "TestNativeChildResultPins/exit", "store/test_result.go", "c.ExitCode > 255", "false", "TestChild accepted changed result pins: exit"},
		{"store", "TestNativeChildResultPins/name", "store/test_result.go", "c.Name != input.Name", "false", "TestChild accepted changed result pins: name"},
		{"store", "TestNativeChildResultPins/pipe", "store/test_result.go", "result.StdoutPipeID == result.StderrPipeID", "false", "TestChild accepted changed result pins: pipe"},
		{"store", "TestNativeChildResultPins/valid", "store/test_result.go", "result.Schema != \"laneboss.test-result.v2\"", "result.Schema != \"laneboss.test-result-invalid.v2\"", "measured TestChild result was rejected"},
	} {
		t.Run(row.test, func(t *testing.T) {
			records = append(records, dashboardGoControl(t, root, "./internal/v2/"+row.pkg, row.test, "internal/v2/"+row.file, row.before, row.after, row.diagnostic))
		})
	}
	if !t.Failed() {
		dashboardRetainControls(t, records)
	}
}
