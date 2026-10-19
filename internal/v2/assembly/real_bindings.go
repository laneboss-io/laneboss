package assembly

import (
	"context"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

type realRunner struct {
	api.Runner
	records *claudock.Records
	capture *realCapture
}

func (r *realRunner) SessionFromCapture(ctx context.Context, record api.CaptureRecord) (api.Session, error) {
	if r.capture == nil {
		return r.Runner.SessionFromCapture(ctx, record)
	}
	reader, err := r.capture.bind(ctx, record.Target)
	if err != nil {
		return api.Session{}, err
	}
	return reader.SessionFromCapture(ctx, record)
}

func (r *realRunner) LimitFromCapture(ctx context.Context, record api.CaptureRecord, exit api.ProcessObservation) (*api.LimitSignal, error) {
	if r.capture == nil {
		return r.Runner.LimitFromCapture(ctx, record, exit)
	}
	reader, err := r.capture.bind(ctx, record.Target)
	if err != nil {
		return nil, err
	}
	return reader.LimitFromCapture(ctx, record, exit)
}

func (r *realRunner) Close() error {
	if r.records == nil {
		return nil
	}
	return r.records.Close()
}

func realBindings(installed Installation, ports runnerDependencies, deps claudock.Dependencies) (claudock.Dependencies, error) {
	if installed.RuntimeManifest.ID == "" {
		return deps, nil
	}
	runtime, err := loadRealRuntime(installed)
	if err != nil || runtime == nil {
		return deps, err
	}
	deps.Executable, deps.ExecutablePath = runtime.Wrapper, runtime.WrapperPath
	deps.Claude, deps.ClaudePath = runtime.Claude, runtime.ClaudePath
	deps.RuntimePath = "/runtime/claudock"
	reader := &enrolledRunner{config: installed.Config, deps: ports}
	deps.Run = func(ctx context.Context, target api.LifeRef) (api.RunnerRequest, error) {
		_, request, _, err := reader.realRun(ctx, target)
		return request, err
	}
	deps.SelectLaunch = func(ctx context.Context, target api.LifeRef) (claudock.LaunchSelector, error) {
		selector, _, _, err := reader.realRun(ctx, target)
		return selector, err
	}
	// Home operations execute in the existing root helper credential worker.
	// A host path or protected record handle never enters the event service.
	deps.HomePath = nil
	deps.PlanHome = reader.planClaudockHome
	deps.Profile = func(ctx context.Context, slot api.CredentialSlot) (api.ProfileGrant, error) {
		lease, ok := api.EffectLeaseFromContext(ctx)
		if !ok || lease.Record.Effect.Context == nil {
			return api.ProfileGrant{}, runError(api.CodeForbidden, "real profile requires its planning claim")
		}
		selector, request, _, err := reader.realRun(ctx, lease.Record.Effect.Context.Target)
		if err != nil {
			return api.ProfileGrant{}, err
		}
		if request.Slot != slot {
			return api.ProfileGrant{}, runError(api.CodeForbidden, "real profile slot differs")
		}
		record, err := ports.Store.LaunchPlan(ctx, selector.Scope, selector.ReservationID)
		if err != nil {
			return api.ProfileGrant{}, err
		}
		for _, profile := range record.Inputs.Grants.Profiles {
			if profile.ID == slot.ProfileGrantID && profile.ProfileID == slot.ProfileID {
				return profile, nil
			}
		}
		return api.ProfileGrant{}, runError(api.CodeForbidden, "real profile is outside retained grants")
	}
	// Vendor selection is measured from the installed CLI, independently of
	// enrollment labels and the helper's bootstrap/private-home measurements.
	compatibility := &realCompatibility{installed: installed, runtime: *runtime}
	deps.VerifyMode = compatibility.verify
	deps.VerifySlot = reader.verifyClaudockBootstrap
	if deps.Capture == nil {
		deps.Capture = func(context.Context, api.ID) (api.CaptureRecord, []byte, error) {
			return api.CaptureRecord{}, nil, api.NotImplemented("lb-v2-store", "CaptureFrame")
		}
	}
	deps.Observation = func(context.Context, api.LifeRef) (api.ProcessObservation, error) {
		return api.ProcessObservation{}, api.NotImplemented("lb-v2-admin", "real runner terminal observation")
	}
	deps.ReportHome = func(context.Context, api.PrivateHome, []claudock.Finding) error {
		return api.NotImplemented("lb-v2-admin", "credential worker home findings")
	}
	deps.LimitGuard = func(context.Context, api.RunnerRequest, api.CaptureRecord, api.ProcessObservation) error {
		return api.NotImplemented("lb-v2-lifecycle", "whole-run refusal coverage")
	}
	directory := filepath.Join(installed.StateDirectory, "claudock")
	if err := privateDirectory(installed.StateDirectory, installed.ServiceUID); err != nil {
		return deps, err
	}
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return deps, installError("real runner records cannot be created")
	}
	deps.Records, err = claudock.NewRecords(directory)
	return deps, err
}

func currentRun(ctx context.Context) api.RunNumber {
	if lease, ok := api.EffectLeaseFromContext(ctx); ok && lease.Record.Effect.Context != nil {
		return lease.Record.Effect.Context.Target.Run
	}
	return 0
}
