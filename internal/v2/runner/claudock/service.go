// Package claudock prepares the claudock-cli runner; it never starts a process.
package claudock

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

const (
	AdapterVersion                = "claudock-cli/v2.0-draft.4-fix12"
	VendorDirectory               = "/home/lane/.claude"
	PrivateVendorDirectory        = ".claude"
	RequiredUmask          uint32 = 0077
	ClaudockVersion               = "0.1.0"
	ClaudeVersion                 = "2.1.296"
)

// Dependencies are installed by the trusted composition root, never an RPC.
// All callbacks must read protected service records, not lane-authored files.
// Paths name retained immutable executables, mounted at the same absolute path
// inside isolation. The launcher must pin the child Claude binary too: pinning
// only the wrapper leaves its PATH lookup unverified.
type Dependencies struct {
	Config      string
	State       api.StateStore
	Sources     api.LaunchSourceResolver
	Storage     api.LaunchStorageResolver
	Grants      api.GrantResolver
	Credentials api.CredentialBroker
	// UsageWindows returns the outside worker's retained normalized evidence.
	UsageWindows api.UsageWindowSource
	// UsageWorker reads actual installed endpoint/native peer facts for the
	// selected outside lease; State.WorkerBinding independently authenticates it.
	UsageWorker func(context.Context, api.Scope, api.ID) (api.InstalledBinding, api.PeerFacts, error)
	// UsageProfile reads the vendor spelling from protected profile enrollment,
	// never from a row chosen by the lane or the evidence envelope.
	UsageProfile   func(context.Context, api.ProfileGrant) (string, error)
	CaptureControl api.CaptureControl
	// SelectLaunch supplies selectors from the current protected planning/capture
	// job. It supplies no path, executable, plan, home or authorization result.
	SelectLaunch   func(context.Context, api.LifeRef) (LaunchSelector, error)
	Executable     api.Executable
	ExecutablePath string
	// RuntimePath is the helper's fixed read-only namespace projection. Empty
	// retains the same-path embedding contract used by non-installed callers.
	RuntimePath string
	Claude      api.Executable
	ClaudePath  string
	Clock       api.Clock
	Records     *Records
	// Run resolves the exact durable request, including the session/home/history
	// mapping, for this life AND run. It must survive service reconstruction.
	Run func(context.Context, api.LifeRef) (api.RunnerRequest, error)
	// HomePath resolves the private physical home outside every checkout. The
	// lane sees VendorDirectory; host paths are never inferred from its strings.
	HomePath func(context.Context, api.PrivateHomeBinding) (string, error)
	// PlanHome runs the same private home transaction in the helper's credential
	// worker. It returns no host path or record-store handle to the service/lane.
	PlanHome func(context.Context, HomePlanRequest) error
	// Profile resolves an already delegated profile and its provider affinity.
	Profile func(context.Context, api.CredentialSlot) (api.ProfileGrant, error)
	// VerifyMode requires independent live compatibility evidence for BOTH
	// pinned binaries and this credential mode. Fixtures cannot enable a mode.
	// Absent proof must return a typed not_implemented/unsupported error.
	VerifyMode func(context.Context, api.Executable, api.Executable, string) error
	// VerifySlot checks the actual run lease, one-profile runtime projection,
	// selected token injection, single refresh owner, pinned read-only overlays
	// and environment bindings, including helper-established umask 077 before
	// vendor exec. Missing measured/pinned bootstrap proof must refuse. This
	// library never changes the event service's own process umask.
	VerifySlot func(context.Context, api.RunnerRequest, uint32) error
	// Capture resolves the immutable primary spool by ID, including its canonical
	// metadata. A caller setting Primary=true is not sufficient provenance.
	Capture func(context.Context, api.ID) (api.CaptureRecord, []byte, error)
	// Observation returns the outside supervisor's retained observation for the
	// exact run. Lane claims and an exit code alone cannot authorize rotation.
	Observation func(context.Context, api.LifeRef) (api.ProcessObservation, error)
	// LimitGuard corroborates the completed run across ALL captured streams and
	// service refusal/auth/provider-affinity receipts. A single CaptureRecord
	// cannot establish the absence of a refusal in another stream. Missing
	// whole-run coverage is a typed not_implemented result, never a swap signal.
	// Outside exhaustion is separately validated through UsageWindows and its
	// actual producer/source. This guard supplies whole-run refusal coverage.
	LimitGuard func(context.Context, api.RunnerRequest, api.CaptureRecord, api.ProcessObservation) error
	// ReportHome retains nonfatal findings about ordinary tool state. It must
	// screen relative names before exposing them beyond protected evidence.
	ReportHome func(context.Context, api.PrivateHome, []Finding) error
}

type Service struct {
	deps Dependencies
	// Installed graph construction precedes per-run vendor enrollment. Every
	// operation must still pass the original strict constructor's validation.
	installed bool
	// Private barrier for deterministic in-package concurrency regression tests.
	beforeStartCommit func()
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func New(deps Dependencies) (*Service, error) {
	if !label(deps.Config) || deps.State == nil || deps.Sources == nil || deps.Storage == nil || deps.Grants == nil || deps.Credentials == nil || deps.CaptureControl == nil || deps.SelectLaunch == nil {
		return nil, api.NotImplemented("lb-v2-claudock", "launch-plan bindings")
	}
	if deps.Run == nil || deps.HomePath == nil && deps.PlanHome == nil || deps.Profile == nil ||
		deps.VerifyMode == nil || deps.VerifySlot == nil || deps.Capture == nil ||
		deps.Observation == nil || deps.ReportHome == nil || deps.Records == nil || deps.LimitGuard == nil ||
		deps.ExecutablePath == "" || deps.ClaudePath == "" {
		return nil, api.NotImplemented("lb-v2-claudock", "trusted runner bindings")
	}
	if !executable(deps.Executable) || !executable(deps.Claude) {
		return nil, failure(api.CodeInvalid, "both pinned executable identities are required")
	}
	if deps.Executable.Version != ClaudockVersion || deps.Claude.Version != ClaudeVersion {
		return nil, api.NotImplemented("lb-v2-claudock", "pinned vendor version adapter")
	}
	if deps.RuntimePath != "" && (deps.RuntimePath != "/runtime/claudock" || deps.Executable.ID != "claudock" || deps.Claude.ID != "claude") {
		return nil, failure(api.CodeIntegrity, "runtime executable projection differs from pinned identities")
	}
	if err := deps.verifyExecutables(); err != nil {
		return nil, err
	}
	if deps.Clock == nil {
		deps.Clock = wallClock{}
	}
	return &Service{deps: deps}, nil
}

// NewInstalled binds the real service dependencies at host startup. It does not
// enroll vendor artifacts, compatibility receipts or private per-run callbacks.
// Missing operation capabilities are refused by ready before any plan/capture.
func NewInstalled(deps Dependencies) (*Service, error) {
	if !label(deps.Config) {
		return nil, failure(api.CodePrerequisite, "installed runner requires its configuration")
	}
	if err := api.RequireDependencies("lb-v2-claudock", deps.State, deps.Clock,
		deps.Sources, deps.Storage, deps.Grants, deps.Credentials, deps.UsageWindows, deps.CaptureControl); err != nil {
		return nil, err
	}
	return &Service{deps: deps, installed: true}, nil
}

var _ api.Runner = (*Service)(nil)

func (s *Service) Start(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return s.plan(ctx, request, true, "start")
}

func (s *Service) Resume(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return s.plan(ctx, request, false, "resume")
}

func (s *Service) Turn(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return s.plan(ctx, request, false, "turn")
}

func (s *Service) plan(ctx context.Context, request api.RunnerRequest, start bool, method string) (api.RunnerPlan, error) {
	var empty api.RunnerPlan
	if err := s.ready(ctx); err != nil {
		return empty, err
	}
	if runtime.GOOS != "linux" {
		return empty, api.NotImplemented("lb-v2-claudock", "native credential adapter")
	}
	if err := validateRequest(request); err != nil {
		return empty, err
	}
	environmentName := api.ClaudeSlotEnvironment(request.Slot.Mode)
	if environmentName == "" {
		return empty, api.NotImplemented("lb-v2-claudock", "helper/API credential adapter")
	}
	deadline, _ := timestamp(request.Slot.ExpiresAt)
	if !deadline.After(s.deps.Clock.Now()) {
		return empty, failure(api.CodeForbidden, "credential slot has expired")
	}
	bound, err := s.boundRun(ctx, request.Target)
	if err != nil {
		return empty, err
	}
	if !reflect.DeepEqual(bound, request) {
		return empty, failure(api.CodeIntegrity, "runner request differs from its protected run binding")
	}
	launch, err := s.planning(ctx, request, method)
	if err != nil {
		return empty, err
	}
	if err := s.mode(ctx, request); err != nil {
		return empty, err
	}
	if err := s.deps.verifyExecutables(); err != nil {
		return empty, err
	}
	profile, err := s.profile(ctx, request.Slot, true)
	if err != nil {
		return empty, err
	}
	if profile.Paid && request.Budget.SpendMicros == 0 {
		return empty, failure(api.CodeBudget, "paid profile has no authorized spend budget")
	}
	if err := dependency(s.deps.VerifySlot(ctx, request, RequiredUmask)); err != nil {
		return empty, err
	}
	selector := "--resume"
	if start {
		selector = "--session-id"
	}
	executablePath := s.deps.ExecutablePath
	if s.deps.RuntimePath != "" {
		executablePath = s.deps.RuntimePath
	}
	profileName := "claude"
	if request.Slot.Mode == "claude-api-key" {
		profileName = KeyProfile
	}
	argv := []string{executablePath, "run", profileName, "--", "-p", "--permission-mode", "bypassPermissions", "--setting-sources", "",
		"--settings", VendorDirectory + "/settings.json", selector, request.Session.VendorID,
		"--model", request.Model, "--effort", request.Effort,
		"--output-format", "stream-json", "--verbose"}
	plan := api.RunnerPlan{
		Driver: api.DriverClaudock, Executable: request.Executable, Argv: argv,
		CWD: request.Session.LogicalCWD, Prompt: request.Prompt, Home: request.Home,
		Slot: request.Slot, Session: request.Session, InnerSandbox: "off",
		AdapterVersion: AdapterVersion, EnvironmentNames: []string{environmentName},
	}
	if s.deps.PlanHome != nil {
		if launch.record.Plan != nil && (launch.record.Plan.Budget != request.Budget || !reflect.DeepEqual(launch.record.Plan.Runner, plan)) {
			return empty, failure(api.CodeIntegrity, "runner replay differs from its retained plan")
		}
		if err := s.deps.PlanHome(ctx, HomePlanRequest{Request: request, Home: launch.storage.Home,
			ReservationID: launch.record.Reservation.ID, InputsSHA256: launch.digest, Start: start,
			Claude: s.deps.Claude, ClaudePath: s.claudeRuntimePath()}); err != nil {
			return empty, dependency(err)
		}
	} else if err := s.localHomePlan(ctx, request, launch, start, plan); err != nil {
		return empty, err
	}
	return plan, nil
}

func (s *Service) localHomePlan(ctx context.Context, request api.RunnerRequest, launch launchInputs, start bool, plan api.RunnerPlan) error {
	path, err := s.deps.HomePath(ctx, launch.storage.Home)
	if err != nil {
		return dependency(err)
	}
	return PlanPrivateHome(path, s.deps.Records, HomePlanRequest{Request: request, Home: launch.storage.Home,
		ReservationID: launch.record.Reservation.ID, InputsSHA256: launch.digest, Start: start,
		Claude: s.deps.Claude, ClaudePath: s.claudeRuntimePath()},
		func(findings []Finding) error { return s.deps.ReportHome(ctx, request.Home, findings) }, func() error {
			if launch.record.Plan != nil && (launch.record.Plan.Budget != request.Budget || !reflect.DeepEqual(launch.record.Plan.Runner, plan)) {
				return failure(api.CodeIntegrity, "runner replay differs from its retained plan")
			}
			if start && s.beforeStartCommit != nil {
				s.beforeStartCommit()
			}
			return nil
		})
}

func (s *Service) claudeRuntimePath() string {
	if s.deps.RuntimePath != "" {
		return "/runtime/claude"
	}
	return s.deps.ClaudePath
}

// HomePlanRequest is a private composition message. Its caller has already
// validated the exact retained request, current authority and launch seal.
type HomePlanRequest struct {
	Request       api.RunnerRequest
	Home          api.PrivateHomeBinding
	ReservationID api.ID
	InputsSHA256  api.Digest
	Start         bool
	Claude        api.Executable
	ClaudePath    string
}

func PlanPrivateHome(path string, records *Records, input HomePlanRequest, report func([]Finding) error, beforeCommit func() error) error {
	request, start := input.Request, input.Start
	if err := validateRequest(request); err != nil {
		return err
	}
	if input.Home.Home != request.Home || input.Home.LifeID != request.Target.LifeID ||
		!identifier(input.ReservationID) || !digest(input.InputsSHA256) || report == nil ||
		!executable(input.Claude) || input.Claude.Version != request.Session.VendorVersion || !absolute(input.ClaudePath) {
		return failure(api.CodeIntegrity, "private home plan lacks its exact retained binding")
	}
	home, err := OpenHome(path, records)
	if err != nil {
		return err
	}
	if err := home.pinMode(request.Slot.Mode); err != nil {
		return err
	}
	if err := home.checkProjection(request.Slot.Mode); err != nil {
		return err
	}
	findings, err := home.Inspect()
	if err != nil {
		return err
	}
	if err := dependency(report(findings)); err != nil {
		return err
	}
	replayed, err := home.checkLaunch(input.ReservationID, input.InputsSHA256)
	if err != nil {
		return err
	}
	if !start {
		if err := home.bind(request, false); err != nil {
			return err
		}
	}
	found, err := home.conversation(request.Session)
	if err != nil {
		return err
	}
	if start && found && !replayed {
		return failure(api.CodeConflict, "start cannot replace an existing conversation")
	}
	if !start && !found {
		return failure(api.CodeNotFound, "the private conversation is missing; continuation cannot start a replacement")
	}
	if err := home.pinClaude(input.Claude, input.ClaudePath); err != nil {
		return err
	}
	if beforeCommit != nil {
		if err := beforeCommit(); err != nil {
			return err
		}
	}
	if start {
		if err := home.bindAndSeal(request, input.ReservationID, input.InputsSHA256); err != nil {
			return err
		}
	} else {
		if err := home.retainLaunch(input.ReservationID, input.InputsSHA256); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) ready(ctx context.Context) error {
	if ctx == nil {
		return failure(api.CodeInvalid, "runner context is required")
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return failure(api.CodeDeadline, "runner deadline exceeded")
		}
		return failure(api.CodeCancelled, "runner operation cancelled")
	}
	if s != nil && s.installed {
		if _, err := New(s.deps); err != nil {
			return err
		}
	}
	if s == nil || s.deps.Run == nil || s.deps.Capture == nil {
		return api.NotImplemented("lb-v2-claudock", "trusted runner bindings")
	}
	return nil
}

func (s *Service) boundRun(ctx context.Context, target api.LifeRef) (api.RunnerRequest, error) {
	request, err := s.deps.Run(ctx, target)
	if err != nil {
		return api.RunnerRequest{}, dependency(err)
	}
	if err := validateRequest(request); err != nil {
		return api.RunnerRequest{}, err
	}
	if request.Target != target || request.Executable != s.deps.Executable ||
		request.Session.VendorVersion != s.deps.Claude.Version {
		return api.RunnerRequest{}, failure(api.CodeIntegrity, "run and pinned vendor identities differ")
	}
	return request, nil
}

func (s *Service) mode(ctx context.Context, request api.RunnerRequest) error {
	return dependency(s.deps.VerifyMode(ctx, s.deps.Executable, s.deps.Claude, request.Slot.Mode))
}

func (s *Service) profile(ctx context.Context, slot api.CredentialSlot, active bool) (api.ProfileGrant, error) {
	grant, err := s.deps.Profile(ctx, slot)
	if err != nil {
		return api.ProfileGrant{}, dependency(err)
	}
	expires, valid := timestamp(grant.ExpiresAt)
	if grant.ID != slot.ProfileGrantID || grant.ProfileID != slot.ProfileID ||
		grant.Driver != api.DriverClaudock || !label(grant.Provider) || !valid ||
		(active && !expires.After(s.deps.Clock.Now())) {
		return api.ProfileGrant{}, failure(api.CodeForbidden, "credential slot is not bound to an eligible delegated profile")
	}
	return grant, nil
}

func failure(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Message: message, Owner: "lb-v2-claudock",
		Instead: "Retain the evidence and repair the named runtime dependency before retrying."}
}

// Preserve a dependency's typed refusal/Instead exactly; never echo a raw I/O
// error, which may contain a private path, provider response or credential.
func dependency(err error) error {
	if err == nil {
		return nil
	}
	if typed, ok := err.(*api.Error); ok && typed != nil && typed.Code == api.CodeInvalid && typed.Owner == "" {
		owned := *typed
		owned.Owner = "lb-v2-claudock"
		return &owned
	}
	var typed *api.Error
	if errors.As(err, &typed) {
		return err
	}
	if errors.Is(err, context.Canceled) {
		return failure(api.CodeCancelled, "runner dependency cancelled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return failure(api.CodeDeadline, "runner dependency deadline exceeded")
	}
	return failure(api.CodeUnavailable, "runner dependency failed; consult protected evidence")
}
