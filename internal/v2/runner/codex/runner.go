// Package codex builds pinned Codex plans. It never starts a process or reads
// ambient credentials. Only the isolation launcher's committed gate may execute
// a returned plan, particularly when the vendor's inner sandbox is disabled.
package codex

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strconv"

	"laneboss.io/laneboss/internal/v2/api"
)

const AdapterVersion = "codex-exec-v4"

// Runtime is installed service configuration, never lane-supplied configuration.
// Both paths must name retained immutable vendor bytes at the same paths in the
// launch namespace. SelfHelper may be the executable itself. Evidence references
// must come from reviewed compatibility receipts in the installed manifest.
type Runtime struct {
	Executable         api.Executable
	ExecutablePath     string
	SelfHelper         api.Executable
	SelfHelperPath     string
	FileLoginEvidence  api.BlobRef
	LimitEvidence      api.BlobRef
	SupervisorEvidence map[int]api.BlobRef
}

type Dependencies struct {
	Store api.StateStore
	Clock api.Clock
	// ReadScope is borrowed from the trusted service operation, including its
	// pinned ReadView. Its owner keeps that view alive through the adapter call
	// and closes it afterward; the runner never authenticates a connection.
	ReadScope api.Scope
	Runtime   Runtime
	// Planning and AllocationEffectID are operation-owned selectors. Every call
	// reloads their current records; these copies never authorize an effect.
	Planning           api.LaunchPlanRequest
	AllocationEffectID api.ID
	Sources            api.LaunchSourceResolver
	Storage            api.LaunchStorageResolver
	Materialization    api.MaterializationControl
	ResolveSession     func(context.Context, api.LifeRef) (api.Session, error)
	// UsageWindows supplies normalized outside usage, never lane capture text.
	// Native facts and vendor profile spelling come from protected installation
	// and enrollment reads; Store.WorkerBinding independently resolves the worker.
	UsageWindows api.UsageWindowSource
	UsageWorker  func(context.Context, api.Scope, api.ID) (api.InstalledBinding, api.PeerFacts, error)
	UsageProfile func(context.Context, api.ProfileGrant) (string, error)

	// ResolveHome reads service-owned life/workspace/history metadata. It must
	// never adopt a binding from inside the vendor home. Its data worker audits
	// the private physical tree before the namespace is prepared.
	ResolveHome func(context.Context, api.LifeRef) (api.PrivateHome, error)

	// The data worker checks the actual materialized project configuration;
	// a lane-writable project config must not override the file-login contract.
	CheckProject func(context.Context, api.LifeRef, api.Session) error

	// VerifySlot is the credential worker's live lease/projection verification.
	// It binds the canonical-login lease AND native auth projection to this run,
	// home and slot. The lease remains held through quiescence and validated
	// refresh persistence. The frozen broker has no read/verify method; missing
	// wiring returns a typed error, never an inferred successful lease.
	VerifySlot func(context.Context, api.LifeRef, api.PrivateHome, api.CredentialSlot) error
}

type Service struct {
	deps      Dependencies
	installed bool
}

func New(deps Dependencies) (*Service, error) {
	if deps.Store == nil || deps.Clock == nil || !id(api.ID(deps.ReadScope.Config)) {
		return nil, problem(api.CodePrerequisite, "Codex needs a scoped store and clock")
	}
	if !executable(deps.Runtime.Executable) || !absolute(deps.Runtime.ExecutablePath) ||
		!executable(deps.Runtime.SelfHelper) || !absolute(deps.Runtime.SelfHelperPath) {
		return nil, problem(api.CodePrerequisite, "Codex needs pinned vendor and self-helper artifacts")
	}
	deps.Runtime.SupervisorEvidence = maps.Clone(deps.Runtime.SupervisorEvidence)
	return &Service{deps: deps}, nil
}

// NewInstalled constructs the real adapter's stable service graph. Runtime
// pins and the operation's protected read/planning context are checked only
// when a run or capture is requested, never replaced by synthetic enrollment.
func NewInstalled(deps Dependencies) (*Service, error) {
	if !id(api.ID(deps.ReadScope.Config)) {
		return nil, problem(api.CodePrerequisite, "installed Codex requires its configuration")
	}
	if err := api.RequireDependencies("lb-v2-codex", deps.Store, deps.Clock,
		deps.Sources, deps.Storage, deps.Materialization, deps.UsageWindows); err != nil {
		return nil, err
	}
	deps.Runtime.SupervisorEvidence = maps.Clone(deps.Runtime.SupervisorEvidence)
	return &Service{deps: deps, installed: true}, nil
}

func (s *Service) installedRuntime() error {
	if s != nil && s.installed {
		if !executable(s.deps.Runtime.Executable) || !absolute(s.deps.Runtime.ExecutablePath) ||
			!executable(s.deps.Runtime.SelfHelper) || !absolute(s.deps.Runtime.SelfHelperPath) {
			return api.NotImplemented("lb-v2-codex", "installed vendor runtime enrollment")
		}
		if _, err := New(s.deps); err != nil {
			return err
		}
	}
	return nil
}

var _ api.Runner = (*Service)(nil)

func (s *Service) Start(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return s.plan(ctx, request, "start")
}

func (s *Service) Resume(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return s.plan(ctx, request, "resume")
}

func (s *Service) Turn(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return s.plan(ctx, request, "turn")
}

func (s *Service) plan(ctx context.Context, request api.RunnerRequest, mode string) (api.RunnerPlan, error) {
	var empty api.RunnerPlan
	continuing := mode != "start"
	if err := cancelled(ctx); err != nil {
		return empty, err
	}
	if err := s.installedRuntime(); err != nil {
		return empty, err
	}
	if s == nil || s.deps.Store == nil || s.deps.Clock == nil {
		return empty, problem(api.CodePrerequisite, "Codex runner is not configured")
	}
	if err := validateRequest(request); err != nil {
		return empty, err
	}
	if request.Executable != s.deps.Runtime.Executable ||
		request.Session.VendorVersion != request.Executable.Version {
		return empty, problem(api.CodeVersion, "Codex artifact differs from the pinned runtime")
	}
	if request.Prompt.Class != "prompt" && request.Prompt.Class != "task" {
		return empty, problem(api.CodeIntegrity, "Codex input is not a committed prompt or task")
	}
	if err := s.blobMetadata(ctx, request.Prompt); err != nil {
		return empty, err
	}
	switch request.Slot.Mode {
	case "codex-file":
	case "codex-api", "codex-local":
		return empty, api.NotImplemented("lb-v2-codex", "Codex API/local credential mode")
	case "claudock-headless", "claudock-helper", "claudock-api":
		return empty, problem(api.CodeForbidden, "Codex cannot consume another driver's credential slot")
	default:
		return empty, problem(api.CodeInvalid, "Codex credential mode is unknown")
	}
	proof, err := s.loadCompatibility(ctx, s.deps.Runtime.FileLoginEvidence, "file-login")
	if err != nil {
		return empty, err
	}
	if !slices.Contains(proof.Efforts, request.Effort) {
		return empty, problem(api.CodeUnsupported, "Codex effort is not supported by the pinned compatibility receipt")
	}
	if err := verifyArtifact(s.deps.Runtime.ExecutablePath, request.Executable); err != nil {
		return empty, err
	}
	if err := verifyArtifact(s.deps.Runtime.SelfHelperPath, s.deps.Runtime.SelfHelper); err != nil {
		return empty, err
	}
	input, err := s.launchInput(ctx, request, mode)
	if err != nil {
		return empty, err
	}
	home, err := s.boundHome(ctx, request.Target)
	if err != nil {
		return empty, err
	}
	if home != request.Home {
		return empty, problem(api.CodeIntegrity, "Codex home or history differs from its life binding")
	}
	if input.level >= 4 {
		if err := s.compatibility(ctx, s.deps.Runtime.SupervisorEvidence[input.level], "supervisor-"+strconv.Itoa(input.level)); err != nil {
			return empty, err
		}
	}
	if continuing {
		if request.Target.Run == 1 {
			return empty, api.NotImplemented("lb-v2-codex", "imported Codex adoption provenance")
		}
		if !uuid(request.Session.VendorID) {
			return empty, problem(api.CodeIntegrity, "Codex continuation needs the captured vendor session")
		}
		if err := s.continuation(ctx, request); err != nil {
			return empty, err
		}
	} else {
		if request.Session.VendorID != "" {
			return empty, problem(api.CodeConflict, "Codex start cannot supply or replace a vendor session")
		}
		if request.Target.Run > 1 {
			if err := s.startupRetry(ctx, request); err != nil {
				return empty, err
			}
		}
	}
	if err := s.profile(ctx, input.record.Reservation, request.Slot); err != nil {
		return empty, err
	}
	if s.deps.CheckProject == nil {
		return empty, api.NotImplemented("lb-v2-integrate", "Codex materialized project configuration check")
	}
	if err := s.deps.CheckProject(ctx, request.Target, request.Session); err != nil {
		return empty, dependencyError(err)
	}
	expires, err := timestamp(request.Slot.ExpiresAt)
	if err != nil || !s.deps.Clock.Now().Before(expires) {
		return empty, problem(api.CodeForbidden, "Codex credential slot is expired")
	}
	if s.deps.VerifySlot == nil {
		return empty, api.NotImplemented("lb-v2-secrets", "Codex live slot verification")
	}
	if err := s.deps.VerifySlot(ctx, request.Target, home, request.Slot); err != nil {
		return empty, dependencyError(err)
	}
	if err := cancelled(ctx); err != nil {
		return empty, err
	}
	effort, err := json.Marshal(request.Effort)
	if err != nil {
		return empty, problem(api.CodeInvalid, "Codex effort cannot be encoded")
	}
	argv := []string{s.deps.Runtime.ExecutablePath,
		"-c", `cli_auth_credentials_store="file"`,
		"-c", `sandbox_mode="danger-full-access"`,
		"-c", `approval_policy="never"`,
		"-c", "model_reasoning_effort=" + string(effort), "exec"}
	if continuing {
		argv = append(argv, "resume")
	}
	argv = append(argv, "--json", "--model", request.Model)
	if continuing {
		argv = append(argv, request.Session.VendorID)
	}
	argv = append(argv, "-")
	plan := api.RunnerPlan{
		Driver: api.DriverCodex, Executable: request.Executable, Argv: argv,
		CWD: request.Session.LogicalCWD, EnvironmentNames: environmentNames(),
		Prompt: request.Prompt, Home: home, Slot: request.Slot, Session: request.Session,
		InnerSandbox: "disabled", AdapterVersion: AdapterVersion,
	}
	if input.record.Plan != nil && !reflect.DeepEqual(input.record.Plan.Runner, plan) {
		return empty, problem(api.CodeIntegrity, "Codex replay changed the retained runner plan")
	}
	return plan, nil
}

func (s *Service) boundHome(ctx context.Context, target api.LifeRef) (api.PrivateHome, error) {
	if s.deps.ResolveHome == nil {
		return api.PrivateHome{}, api.NotImplemented("lb-v2-integrate", "Codex authoritative home resolution")
	}
	home, err := s.deps.ResolveHome(ctx, target)
	if err != nil {
		return api.PrivateHome{}, dependencyError(err)
	}
	if !privateHome(home) {
		return api.PrivateHome{}, problem(api.CodeIntegrity, "Codex authoritative home descriptor is invalid")
	}
	return home, nil
}

func (s *Service) boundLane(ctx context.Context, target api.LifeRef) (api.Lane, error) {
	lane, err := s.deps.Store.Lane(ctx, s.deps.ReadScope, target)
	if err != nil {
		return api.Lane{}, dependencyError(err)
	}
	if lane.LifeID != target.LifeID || lane.Run != target.Run {
		return api.Lane{}, problem(api.CodeIntegrity, "Codex store returned a different life or run")
	}
	return lane, nil
}

func (s *Service) profile(ctx context.Context, reservation api.LaunchReservation, slot api.CredentialSlot) error {
	grants, err := s.deps.Store.Grants(ctx, reservation.GrantSetID)
	if err != nil {
		return dependencyError(err)
	}
	expires, err := timestamp(grants.ExpiresAt)
	if err != nil || !s.deps.Clock.Now().Before(expires) || grants.Revoked ||
		grants.ID != reservation.GrantSetID || grants.LifeID != reservation.Target.LifeID ||
		grants.PolicyGeneration != reservation.PolicyGeneration {
		return problem(api.CodeForbidden, "Codex profile grants are stale or revoked")
	}
	for _, grant := range grants.Profiles {
		if grant.ID != slot.ProfileGrantID {
			continue
		}
		until, err := timestamp(grant.ExpiresAt)
		if err != nil || !s.deps.Clock.Now().Before(until) || grant.ProfileID != slot.ProfileID || grant.Driver != api.DriverCodex {
			return problem(api.CodeForbidden, "Codex selected profile is not delegated to this life")
		}
		return nil
	}
	return problem(api.CodeForbidden, "Codex selected profile is not delegated to this life")
}

func (s *Service) continuation(ctx context.Context, request api.RunnerRequest) error {
	events, err := s.events(ctx, api.LifeRef{LifeID: request.Target.LifeID})
	if err != nil {
		return err
	}
	var mapped, ended bool
	for _, event := range events {
		if event.Run >= request.Target.Run {
			continue
		}
		if event.Kind == "runner.session" {
			var session api.Session
			if decode(event.Payload, &session) != nil || session != request.Session {
				return problem(api.CodeIntegrity, "Codex persisted session mapping differs from continuation")
			}
			mapped = true
		}
		if event.Kind == "lane.ended" && event.Run == request.Target.Run-1 {
			var end api.RunEndEvent
			if decode(event.Payload, &end) != nil || !quiescent(end.Observation, api.LifeRef{LifeID: request.Target.LifeID, Run: event.Run}) {
				return problem(api.CodeContainmentUnknown, "Codex preceding run is not proved quiescent")
			}
			ended = true
		}
	}
	if !mapped {
		return problem(api.CodeIntegrity, "Codex continuation has no outside-captured session mapping")
	}
	if !ended {
		return problem(api.CodeContainmentUnknown, "Codex continuation has no quiescent preceding run")
	}
	return nil
}

func (s *Service) startupRetry(ctx context.Context, request api.RunnerRequest) error {
	events, err := s.events(ctx, api.LifeRef{LifeID: request.Target.LifeID})
	if err != nil {
		return err
	}
	ended := false
	for _, event := range events {
		if event.Kind == "runner.session" {
			return problem(api.CodeConflict, "Codex startup retry cannot replace an outside-captured session")
		}
		if event.Kind == "lane.ended" && event.Run == request.Target.Run-1 {
			var end api.RunEndEvent
			if decode(event.Payload, &end) != nil || !quiescent(end.Observation, api.LifeRef{LifeID: request.Target.LifeID, Run: event.Run}) {
				return problem(api.CodeContainmentUnknown, "Codex startup retry has no quiescent preceding run")
			}
			ended = true
		}
	}
	if !ended {
		return problem(api.CodeContainmentUnknown, "Codex startup retry has no quiescent preceding run")
	}
	return nil
}

func environmentNames() []string {
	return []string{"CODEX_HOME", "HOME", "PATH", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"}
}

// dependencyError preserves a typed refusal (including its exact recovery route)
// and prevents filesystem/parser errors from printing private paths or values.
func dependencyError(err error) error {
	var typed *api.Error
	if errors.As(err, &typed) {
		return typed
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return contextError(err)
	}
	return problem(api.CodeUnavailable, "Codex dependency could not complete its operation")
}

func cancelled(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return contextError(err)
	}
	return nil
}

func contextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return problem(api.CodeDeadline, "Codex operation deadline expired")
	}
	return problem(api.CodeCancelled, "Codex operation was cancelled")
}

func problem(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Message: message, Owner: "lb-v2-codex",
		Instead: "Preserve the evidence and repair the named dependency before launch."}
}

// Own all returned slices. No subsequent caller can mutate service state by
// changing a previous plan or the generated environment-name declaration.
func sameNames(names []string) bool { return slices.Equal(names, environmentNames()) }
