// Package dataworker owns confined data/Git/test/render/archive jobs.
// No method executes untrusted content in the service's process or authority.
package dataworker

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/testjob"
)

type Dependencies struct {
	// Required by launch materialization; legacy job ports remain constructible
	// while assembly is ported to the installed configuration binding.
	Config   string
	Controls api.MaterializationControl
	Store    api.StateStore
	Helper   api.HelperControl
	Launcher api.Launcher
	Clock    api.Clock
	// Optional installed administrator capability; cleanup also discovers it
	// on Helper when that owner implements the private collection port.
	Workspace api.WorkspaceCollector
}

type Service struct{ deps Dependencies }

func New(deps Dependencies) (*Service, error) {
	if deps.Config != "" && !manifest.Config(deps.Config) || missing(deps.Store) || missing(deps.Helper) || missing(deps.Launcher) || missing(deps.Clock) {
		return nil, &api.Error{Code: api.CodePrerequisite, Message: "data worker requires a state store, helper, confinement launcher and clock",
			Instead: "Wire the installed state store, helper control, verified launcher and service clock.", Owner: "lb-v2-grants"}
	}
	return &Service{deps: deps}, nil
}

func missing(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	return (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil()
}

var _ api.DataWorker = (*Service)(nil)

func checkContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		code := api.CodeCancelled
		if err == context.DeadlineExceeded {
			code = api.CodeDeadline
		}
		return &api.Error{Code: code, Message: "data worker operation context ended",
			Instead: "Inspect the original operation before retrying.", Owner: "lb-v2-grants"}
	}
	return nil
}

func (s *Service) confinement(ctx context.Context) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	capabilities, err := s.deps.Launcher.Probe(ctx)
	if err != nil {
		return err
	}
	if !capabilities.Available || (capabilities.Backend != "linux-bwrap-landlock" && capabilities.Backend != "darwin-seatbelt") {
		return &api.Error{Code: api.CodePrerequisite, Message: "confined data worker backend is unavailable",
			Instead: "Repair the platform confinement prerequisites; no host execution fallback is permitted.", Owner: "lb-v2-grants"}
	}
	return nil
}

func (s *Service) Materialize(ctx context.Context, grants api.GrantSet) (api.Materialization, error) {
	var zero api.Materialization
	if err := checkContext(ctx); err != nil {
		return zero, err
	}
	if err := manifest.Set(grants, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	for _, grant := range grants.Data {
		if grant.Delivery == "mount" {
			return zero, &api.Error{Code: api.CodeUnsupported, Message: "mount delivery requires a verified registered export lease",
				Instead: "Use an independent snapshot copy until pinned export and writer-handoff support is installed.", Owner: "lb-v2-grants"}
		}
	}
	if err := s.confinement(ctx); err != nil {
		return zero, err
	}
	// Launcher alone cannot read committed sources, allocate/commit a worker
	// lease/permit, deliver opened source handles, or recover output manifests.
	// Creating a temporary directory here would run the deputy as the service.
	return zero, api.NotImplemented("lb-v2-grants", "dataworker.Materialize authenticated job lease, source handles and output collection")
}

func (s *Service) TestChild(ctx context.Context, request api.TestChildRequest, grants api.GrantSet) (api.Operation, error) {
	var zero api.Operation
	if err := checkContext(ctx); err != nil {
		return zero, err
	}
	if err := manifest.Set(grants, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	if request.Child.LifeID != grants.LifeID || request.Child.Run == 0 {
		return zero, manifest.Invalid("test worker must name its exact child life and run")
	}
	if err := manifest.Budget(request.Budget); err != nil {
		return zero, err
	}
	if err := manifest.Blob(request.Candidate); err != nil {
		return zero, err
	}
	if err := manifest.Blob(request.TestPlan); err != nil {
		return zero, err
	}
	if err := s.confinement(ctx); err != nil {
		return zero, err
	}
	call, ok := testjob.FromContext(ctx)
	control, installed := s.deps.Controls.(testjob.Control)
	if !ok || !installed || missing(control) {
		return zero, api.NotImplemented("lb-v2-grants", "TestChild installed scoped native execution coordinator")
	}
	return control.SubmitChildTest(ctx, call, request, grants)
}

func (s *Service) Archive(ctx context.Context, request api.ArchiveRequest) (api.ArchiveReceipt, error) {
	var zero api.ArchiveReceipt
	if err := checkContext(ctx); err != nil {
		return zero, err
	}
	if !manifest.ValidID(request.Target.LifeID) || request.Target.Run == 0 || request.ExpectedGeneration == 0 {
		return zero, manifest.Invalid("archive requires an exact life, run and generation")
	}
	if err := s.confinement(ctx); err != nil {
		return zero, err
	}
	return zero, api.NotImplemented("lb-v2-grants", "dataworker.Archive protected source inventory, destination lease and independent read-back")
}
