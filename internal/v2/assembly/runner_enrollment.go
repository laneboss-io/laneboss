package assembly

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// enrolledRunner keeps the service graph constructible while making vendor
// enrollment a per-run decision. It never turns the installation reference
// into executable paths or credentials; the runner still validates its own
// pinned adapter and the helper owns the final native gate.
type enrolledRunner struct {
	api.Runner
	driver     api.Driver
	enrollment *api.BlobRef
	config     string
	runtime    api.BlobRef
	deps       runnerDependencies
}

func guardRunnerEnrollment(runner api.Runner, installed Installation, driver api.Driver, ports runnerDependencies) api.Runner {
	if runner == nil {
		return runner
	}
	r := &enrolledRunner{Runner: runner, driver: driver, config: installed.Config, runtime: installed.RuntimeManifest, deps: ports}
	if installed.LaunchEnrollment != nil {
		ref := *installed.LaunchEnrollment
		r.enrollment = &ref
	}
	return r
}

func (r *enrolledRunner) guard(ctx context.Context, request api.RunnerRequest, retained bool) error {
	if ctx == nil {
		return &api.Error{Code: api.CodeInvalid, Owner: "lb-v2-integrate", Message: "runner context is required", Instead: "Supply the live service operation context."}
	}
	if err := ctx.Err(); err != nil {
		code := api.CodeCancelled
		if err == context.DeadlineExceeded {
			code = api.CodeDeadline
		}
		return &api.Error{Code: code, Owner: "lb-v2-integrate", Message: "runner enrollment check was cancelled", Instead: "Inspect the retained run before retrying."}
	}
	ref := r.enrollment
	if err := checkRunnerSpend(ctx, r.deps.Store, request.Slot); err != nil {
		return err
	}
	if ref == nil || ref.ID == "" || ref.Class != "manifest" || ref.Bytes <= 0 || !isDigest(ref.SHA256) {
		return &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-integrate", Message: "runner requires its protected per-run enrollment", Instead: "Install and read back the administrator-owned launch enrollment before selecting a vendor."}
	}
	if request.Target.LifeID == "" || request.Target.Run == 0 || request.Session.Driver != r.driver {
		return &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-integrate", Message: "runner request is foreign to its enrolled driver or life", Instead: "Use the exact current life and driver selection."}
	}
	if request.Executable.ID == "" || !isDigest(request.Executable.SHA256) || request.Executable.Version == "" || retained && request.Session.VendorVersion == "" ||
		request.Home.ID == "" || request.Home.WorkspaceID == "" || request.Home.HistoryID == "" || request.Session.HomeID != request.Home.ID ||
		request.Session.HistoryID != request.Home.HistoryID || request.Slot.ID == "" || request.Slot.LeaseID == "" ||
		request.Slot.ProfileGrantID == "" || request.Slot.ProfileID == "" {
		return &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-integrate", Message: "runner request lacks its complete enrolled life, home or credential pins", Instead: "Retain the original run selection and repair the missing pin."}
	}
	if err := api.RequireDependencies("lb-v2-integrate", r.Runner, r.deps.Store, r.deps.Clock, r.deps.Sources, r.deps.Storage, r.deps.Credentials); err != nil {
		return err
	}
	if expiry, err := time.Parse(time.RFC3339Nano, string(request.Slot.ExpiresAt)); err != nil || !expiry.After(r.deps.Clock.Now()) {
		return &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-integrate", Message: "runner credential enrollment is expired", Instead: "Select a current delegated profile through the service."}
	}
	return nil
}

func (r *enrolledRunner) Start(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	if err := r.guard(ctx, request, false); err != nil {
		return api.RunnerPlan{}, err
	}
	if err := r.verifyRun(ctx, request, "start"); err != nil {
		return api.RunnerPlan{}, err
	}
	return r.Runner.Start(ctx, request)
}

func (r *enrolledRunner) Resume(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	if err := r.guard(ctx, request, true); err != nil {
		return api.RunnerPlan{}, err
	}
	if err := r.verifyRun(ctx, request, "resume"); err != nil {
		return api.RunnerPlan{}, err
	}
	return r.Runner.Resume(ctx, request)
}

func (r *enrolledRunner) Turn(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	if err := r.guard(ctx, request, true); err != nil {
		return api.RunnerPlan{}, err
	}
	if err := r.verifyRun(ctx, request, "turn"); err != nil {
		return api.RunnerPlan{}, err
	}
	return r.Runner.Turn(ctx, request)
}
