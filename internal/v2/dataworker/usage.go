package dataworker

import (
	"context"
	"encoding/json"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets"
)

// UsageJob carries the native worker's own authenticated bootstrap and held
// helper projections. It never takes an executable or home path from a lane.
type UsageJob struct {
	Principal  api.WorkerPrincipal
	Scope      api.Scope
	Bootstrap  api.WorkerBootstrap
	Executable *os.File
	Home       *os.File
	Clock      api.Clock
}

func RunUsage(ctx context.Context, job UsageJob) (api.WorkerResultReceipt, error) {
	var zero api.WorkerResultReceipt
	if ctx == nil || missing(job.Bootstrap) || missing(job.Clock) || job.Executable == nil || job.Home == nil {
		return zero, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-grants", Message: "usage worker requires its native bootstrap, clock and held projections",
			Instead: "Install the original native usage worker projections and bootstrap."}
	}
	if err := checkContext(ctx); err != nil {
		return zero, err
	}
	p := job.Principal
	if p.Lease.Kind != "usage" || job.Scope.Config != p.Endpoint.Config || job.Scope.Actor != p.Record.Actor || job.Scope.LaunchID != p.Record.ID || job.Scope.EndpointGeneration != p.Endpoint.EndpointGeneration || job.Scope.Request.Method != "" {
		return zero, &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-grants", Message: "usage worker cannot borrow its requester identity",
			Instead: "Run the fixed usage job on its own authenticated worker connection."}
	}
	input, err := job.Bootstrap.WorkerInput(ctx, job.Scope, api.WorkerInputRequest{LeaseID: p.Lease.ID})
	if err != nil {
		return zero, err
	}
	output, err := secrets.RunUsageCommand(ctx, p, input, job.Executable, job.Home, job.Clock)
	if err != nil {
		return zero, err
	}
	raw, err := json.Marshal(output)
	if err == nil {
		raw, err = api.CanonicalJSON(raw)
	}
	if err != nil {
		return zero, err
	}
	submission := api.WorkerResultSubmission{LeaseID: p.Lease.ID, ExpectedGeneration: p.Lease.Generation, InputSHA256: p.Lease.Input.SHA256, Result: raw}
	receipt, err := job.Bootstrap.WorkerResult(ctx, job.Scope, submission)
	if err != nil {
		return zero, err
	}
	if err := api.ValidateWorkerResult(p, submission, receipt, job.Clock.Now()); err != nil {
		return zero, err
	}
	return receipt, nil
}
