package admin

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) ResolveLaunchSources(ctx context.Context, request api.LaunchSourceRequest) (_ api.LaunchSources, resultErr error) {
	defer helperContextCheck(ctx, &resultErr, "launch_sources")
	if !validID(request.GrantSetID) {
		return api.LaunchSources{}, failure(api.CodeInvalid, "launch source requires the issued grant set")
	}
	authority, err := s.launchAuthority(ctx, request.ReservationID, request.GrantSetID, nil, request.Claim)
	if err != nil {
		return api.LaunchSources{}, err
	}
	return s.runtimeLaunchSources(ctx, authority)
}

// The caller has already reloaded and fenced its actual planning or helper
// registration authority. Both routes retain every protected-source check.
func (s *Service) runtimeLaunchSources(ctx context.Context, authority launchAuthority) (api.LaunchSources, error) {
	if s.deps.LaunchEnrollment == nil {
		return api.LaunchSources{}, failure(api.CodePrerequisite, "protected launch enrollment is not installed")
	}
	enrollment, manifest, err := s.loadLaunchEnrollment(ctx)
	if err != nil {
		return api.LaunchSources{}, err
	}
	// A class label in the object store is not enrollment. The exact bytes
	// must also match the protected administrator-installed object above.
	data, err := s.readLaunchObject(ctx, authority.Scope, *s.deps.LaunchEnrollment, "", "", true)
	if err != nil {
		return api.LaunchSources{}, err
	}
	var committed api.LaunchEnrollment
	if err := api.DecodeObject(data, &committed); err != nil {
		return api.LaunchSources{}, err
	}
	if !reflect.DeepEqual(committed, enrollment) {
		return api.LaunchSources{}, failure(api.CodeIntegrity, "committed enrollment differs from protected bytes")
	}
	return s.resolveLaunchSourceInputs(ctx, authority, enrollment, manifest)
}

// Both the installed file reader and the committed-object reader below use
// this complete source-selection path, including all retained replay fences.
func (s *Service) resolveLaunchSourceInputs(ctx context.Context, authority launchAuthority, enrollment api.LaunchEnrollment, manifest api.RuntimeManifest) (api.LaunchSources, error) {
	project, driver, level, role, profile, err := s.launchSelection(ctx, authority)
	if err != nil {
		return api.LaunchSources{}, err
	}
	selected, err := selectLaunchSources(authority, enrollment, manifest, project, driver, level, role, profile)
	if err != nil {
		return api.LaunchSources{}, err
	}
	if authority.Record.Inputs != nil && (!reflect.DeepEqual(authority.Record.Inputs.Sources, selected) ||
		!reflect.DeepEqual(authority.Record.Inputs.Grants, authority.Grants)) {
		return api.LaunchSources{}, failure(api.CodeConflict, "retained launch sources or grants changed")
	}
	if authority.Record.Reservation.PreviousLaunchID != "" {
		previous, err := s.deps.Store.LaunchBinding(ctx, authority.Record.Reservation.PreviousLaunchID)
		if err != nil {
			return api.LaunchSources{}, err
		}
		if previous.Recovery == nil {
			return api.LaunchSources{}, failure(api.CodeIntegrity, "retained launch recovery is missing")
		}
		prior, err := s.deps.Store.LaunchPlan(ctx, authority.Scope, previous.Recovery.PlanID)
		if err != nil {
			return api.LaunchSources{}, err
		}
		if prior.Plan == nil || prior.Inputs == nil || !reflect.DeepEqual(prior.Inputs.Sources.Project, selected.Project) ||
			!reflect.DeepEqual(prior.Inputs.Sources.Runtime, selected.Runtime) {
			return api.LaunchSources{}, failure(api.CodeConflict, "retained project or runtime enrollment changed")
		}
	}
	if _, err := s.readLaunchObject(ctx, authority.Scope, selected.Project.Object, "", "", false); err != nil {
		return api.LaunchSources{}, err
	}
	if err := s.fenceLaunch(ctx, authority); err != nil {
		return api.LaunchSources{}, err
	}
	return selected, nil
}

func (s *Service) launchSelection(ctx context.Context, authority launchAuthority) (api.ID, api.Driver, int, string, api.ID, error) {
	r := authority.Record.Reservation
	switch r.Mode {
	case "start":
		input, err := decodeLaunchRequest[api.StartRequest](authority.Request, "lane.start")
		if err == nil && input.ExpectedPolicyGeneration != r.PolicyGeneration {
			allowAndLog("launch_policy_generation")
		}
		if err != nil {
			return "", "", 0, "", "", err
		}
		profile, err := api.IssuedLaunchProfile(r, authority.Request, authority.Grants)
		return input.ProjectID, input.Driver, input.Level, input.Role, profile.ID, err
	case "adopt":
		input, err := decodeLaunchRequest[api.AdoptRequest](authority.Request, "lane.adopt")
		if err != nil {
			return "", "", 0, "", "", err
		}
		if input.ExpectedPolicyGeneration != r.PolicyGeneration {
			allowAndLog("adopt_policy_generation")
		}
		data, err := s.readLaunchObject(ctx, authority.Scope, input.ImportManifest, "", "", false)
		if err != nil {
			return "", "", 0, "", "", err
		}
		var adopted api.AdoptionManifest
		if err := api.DecodeObject(data, &adopted); err != nil {
			return "", "", 0, "", "", err
		}
		profile, err := api.IssuedLaunchProfile(r, authority.Request, authority.Grants)
		return adopted.Workspace.ProjectID, input.Driver, input.Level, input.Role, profile.ID, err
	case "resume", "turn", "continue":
		selected, err := s.retainedLaunchInput(ctx, authority)
		if err != nil {
			return "", "", 0, "", "", err
		}
		previous, retained, lane := selected.Binding, selected.Plan, selected.Lane
		// This does not infer quiescence from a Lane label. The original
		// helper-owned run is independently observed before reusing its data.
		reconciliation, err := s.ReconcileGate(ctx, api.HelperReconcileRequest{LeaseID: retained.Plan.Lease.ID, LaunchID: previous.Record.ID,
			PreparedID: previous.Prepared.ID, OperationID: retained.Reservation.OperationID})
		if err != nil {
			return "", "", 0, "", "", err
		}
		observation := reconciliation.Observation
		if observation.State != "exited" || observation.Survivors == nil || *observation.Survivors != 0 {
			return "", "", 0, "", "", failure(api.CodeContainmentUnknown, "prior run is not independently quiescent")
		}
		return retained.Plan.Inputs.Sources.Project.ProjectID, retained.Plan.Runner.Driver, lane.Level, lane.Role, selected.ProfileID, nil
	default:
		return "", "", 0, "", "", failure(api.CodeInvalid, "unknown launch source mode")
	}
}

type retainedLaunchInput struct {
	Binding   api.LaunchBindingRequest
	Plan      api.LaunchPlanRecord
	Lane      api.Lane
	ProfileID api.ID
}

// Resolve protected input pins separately from the following native
// quiescence observation. This read does not authorize opening a gate.
func (s *Service) retainedLaunchInput(ctx context.Context, authority launchAuthority) (retainedLaunchInput, error) {
	var result retainedLaunchInput
	r := authority.Record.Reservation
	previous, err := s.deps.Store.LaunchBinding(ctx, r.PreviousLaunchID)
	if err != nil {
		return result, err
	}
	if previous.Recovery == nil {
		return result, failure(api.CodeIntegrity, "retained launch has no recovery binding")
	}
	retained, err := s.deps.Store.LaunchPlan(ctx, authority.Scope, previous.Recovery.PlanID)
	if err != nil {
		return result, err
	}
	if retained.Plan == nil || retained.Phase != "opened" || previous.Record.ID != r.PreviousLaunchID ||
		previous.Record.Target.LifeID != r.Target.LifeID || previous.Record.Target.Run+1 != r.Target.Run {
		return result, failure(api.CodeConflict, "previous launch is not the retained life and run")
	}
	if err := api.ValidateLaunchBindingPlan(previous, *retained.Plan); err != nil {
		return result, err
	}
	lane, err := s.deps.Store.Lane(ctx, authority.Scope, previous.Record.Target)
	if err != nil {
		return result, err
	}
	if lane.Cleaned || lane.LaunchID != previous.Record.ID || lane.Generation != r.BaseGeneration ||
		lane.State != "ended" && lane.State != "idle" && lane.State != "verifying" && !(r.Mode == "continue" && lane.State == "profile_wait") || lane.Workspace != retained.Plan.Data.Workspace ||
		lane.Session.HomeID != retained.Plan.Data.Home.Home.ID || lane.Session.HistoryID != retained.Plan.Data.Home.Home.HistoryID {
		return result, failure(api.CodeConflict, "retained private session or workspace differs")
	}
	if loop := r.Loop; loop != nil {
		home := previous.Recovery.Home
		if lane.Session != loop.PreviousSession || lane.BudgetRemaining != loop.BudgetRemaining || lane.LogicalTurnID != loop.PreviousLogicalTurnID ||
			home.RootID != loop.PreviousHome.RootID || home.Home != loop.PreviousHome.Home || home.Generation < loop.PreviousHome.Generation {
			return result, failure(api.CodeConflict, "loop helper input changed its retained history or budget")
		}
	}
	profile := lane.ProfileGrantID
	if r.Mode == "continue" {
		raw, err := s.readLaunchObject(ctx, authority.Scope, r.OriginalRequest, r.OperationID, r.Target.LifeID, true)
		if err != nil {
			return result, err
		}
		input, err := s.contInput(ctx, authority.Scope, authority.Record, authority.Cause, raw)
		if err != nil {
			return result, err
		}
		profile = input.Swap.ProfileGrantID
	}
	return retainedLaunchInput{Binding: previous, Plan: retained, Lane: lane, ProfileID: profile}, nil
}

func selectLaunchSources(authority launchAuthority, enrollment api.LaunchEnrollment, manifest api.RuntimeManifest,
	project api.ID, driver api.Driver, level int, role string, profile api.ID) (api.LaunchSources, error) {
	r := authority.Record.Reservation
	if level != r.Level || role != r.Role || driver != r.Driver {
		return api.LaunchSources{}, failure(api.CodeForbidden, "launch selection differs from reserved role, level or driver")
	}
	if !validID(project) || level < 3 || level > 6 || role == "" || authority.Policy.Generation != authority.Record.Reservation.PolicyGeneration {
		return api.LaunchSources{}, failure(api.CodeForbidden, "launch role or level differs from approved policy")
	}
	if err := api.ValidateLaunchEnrollment(enrollment, authority.Record.Reservation.Config, authority.RuntimeManifest); err != nil {
		return api.LaunchSources{}, err
	}
	var selected api.LaunchSources
	selected.ReservationID = authority.Record.Reservation.ID
	for _, candidate := range enrollment.Projects {
		if candidate.ProjectID == project {
			selected.Project = api.ProjectLaunchSource{EnrollmentID: candidate.ID, Generation: candidate.Generation, ProjectID: project,
				Object: candidate.Object, Base: candidate.Base, HistoryScope: candidate.HistoryScope}
		}
	}
	for _, candidate := range enrollment.Runtimes {
		if candidate.Driver == driver {
			selected.Runtime = candidate
		}
	}
	if selected.Project.EnrollmentID == "" || selected.Runtime.EnrollmentID == "" {
		return api.LaunchSources{}, failure(api.CodeForbidden, "project or driver is not enrolled")
	}
	if err := enrolledExecutable(manifest, selected.Runtime.Executable); err != nil {
		return api.LaunchSources{}, err
	}
	main, profiles := 0, 0
	for _, grant := range authority.Grants.Data {
		if grant.Destination != "/work/main" {
			continue
		}
		deadline, err := time.Parse(time.RFC3339Nano, string(grant.ExpiresAt))
		if err != nil || !deadline.After(time.Now()) || grant.SourceObjectID != selected.Project.Object.ID ||
			grant.SourceSHA256 != selected.Project.Object.SHA256 || grant.HistoryScope != selected.Project.HistoryScope || grant.RelativePath != "." {
			return api.LaunchSources{}, failure(api.CodeForbidden, "main workspace grant differs from enrolled project")
		}
		selected.Project.GrantID = grant.ID
		main++
	}
	for _, grant := range authority.Grants.Profiles {
		if grant.ID == profile && grant.Driver == driver {
			deadline, err := time.Parse(time.RFC3339Nano, string(grant.ExpiresAt))
			if err != nil || !deadline.After(time.Now()) {
				return api.LaunchSources{}, failure(api.CodeForbidden, "selected profile grant expired")
			}
			profiles++
			for _, excluded := range authority.Policy.ProfileExclusions {
				if excluded == grant.ProfileID {
					return api.LaunchSources{}, failure(api.CodeForbidden, "selected profile is excluded by policy")
				}
			}
		}
	}
	if main != 1 || profiles != 1 {
		return api.LaunchSources{}, failure(api.CodeForbidden, "launch requires a unique main data grant and approved driver profile")
	}
	if authority.Record.Reservation.PreviousLaunchID != "" && authority.Record.Inputs != nil &&
		!reflect.DeepEqual(selected, authority.Record.Inputs.Sources) {
		return api.LaunchSources{}, failure(api.CodeConflict, "retained life cannot select a different runtime or project")
	}
	return selected, nil
}

func enrolledExecutable(manifest api.RuntimeManifest, executable api.Executable) error {
	for _, object := range manifest.Objects {
		if object.ID == executable.ID && object.Mode == 0555 && object.Content.SHA256 == executable.SHA256 && executable.Version != "" {
			return nil
		}
	}
	return failure(api.CodeForbidden, "selected executable is not pinned by the installed runtime")
}
