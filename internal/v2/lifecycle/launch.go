package lifecycle

import (
	"context"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func validBudget(budget api.Budget) bool {
	return budget.WallMS > 0 && uint64(budget.WallMS) <= maxInteger &&
		budget.CPUSeconds > 0 && budget.CPUSeconds <= maxInteger &&
		budget.MemoryBytes > 0 && budget.MemoryBytes <= maxInteger &&
		budget.Processes > 0 && budget.DiskBytes > 0 && budget.DiskBytes <= maxInteger &&
		budget.SpendMicros >= 0 && uint64(budget.SpendMicros) <= maxInteger &&
		len(budget.Currency) == 3 && strings.Trim(budget.Currency, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == ""
}

func driverAllowed(driver api.Driver) bool {
	return driver == api.DriverClaudock || driver == api.DriverCodex
}

func (s *Service) runner(driver api.Driver) (api.Runner, error) {
	switch driver {
	case api.DriverClaudock:
		if !absent(s.deps.Claudock) {
			return s.deps.Claudock, nil
		}
		return nil, api.NotImplemented("lb-v2-claudock", "Runner")
	case api.DriverCodex:
		if !absent(s.deps.Codex) {
			return s.deps.Codex, nil
		}
		return nil, api.NotImplemented("lb-v2-codex", "Runner")
	default:
		return nil, invalid("unsupported production driver")
	}
}

func (s *Service) spawnPreflight(ctx context.Context, scope api.Scope,
	request api.StartRequest, projectRequired bool) error {
	if err := startInputs(request, projectRequired); err != nil {
		return err
	}
	if scope.PolicyGeneration != request.ExpectedPolicyGeneration {
		return problem(api.CodeConflict, "launch policy differs from the authenticated scope",
			"Read current policy and retain its exact launch generation.")
	}
	if request.RootTicketID != "" && !humanTicketEndpoint(scope) {
		return problem(api.CodeForbidden, "root tickets require the installed human endpoint",
			"Use the authenticated human connection; a ticket ID cannot change a lane or worker binding.")
	}
	if scope.Actor.Kind == "human" {
		if !validID(request.RootTicketID) {
			return problem(api.CodeForbidden, "root launch requires a ticket",
				"Obtain an operation-bound root ticket through human confirmation.")
		}
		policy, err := s.deps.Store.Policy(ctx, scope)
		if err != nil {
			return failure(err)
		}
		generation, err := api.PolicyGenerationFor(api.PolicyNewLaunch, policy.Generation, 0)
		if err != nil {
			return failure(err)
		}
		if scope.PolicyGeneration != generation {
			return problem(api.CodeConflict, "root launch policy context is stale",
				"Reload current authorization before reserving the root ticket.")
		}
		ticket, err := s.deps.Store.Ticket(ctx, scope, request.RootTicketID)
		if err != nil {
			return failure(err)
		}
		expires, parseErr := time.Parse(time.RFC3339Nano, string(ticket.ExpiresAt))
		if ticket.ID != request.RootTicketID || ticket.Level != request.Level || ticket.Role != request.Role ||
			ticket.PrincipalID != scope.Actor.ID || ticket.Config != scope.Config ||
			ticket.EndpointGeneration != scope.EndpointGeneration ||
			!validID(ticket.GrantSetID) || ticket.Redeemed || parseErr != nil ||
			!s.deps.Clock.Now().Before(expires) {
			return problem(api.CodeForbidden, "root ticket does not authorize this launch",
				"Use a current unused ticket issued for the exact level, role and root grants.")
		}
		// Draft.3 supplies atomic TicketUse. Do not consume the ticket until
		// the complete launch intent can be committed with that guard.
		return s.launchAvailability(ctx, scope, request)
	}
	if scope.Actor.Kind != "lane" || !validID(scope.LaunchID) || !validGeneration(scope.EndpointGeneration) {
		return problem(api.CodeForbidden, "launch requires an authentic starter",
			"Use a live recorded starter or the confirmed human root path.")
	}
	if request.RootTicketID != "" || request.Level >= scope.Actor.Level {
		return problem(api.CodeForbidden, "child level must be strictly lower",
			"Choose a child level from 3 through the authentic starter level minus one.")
	}
	parent, err := s.currentStarter(ctx, scope, scope.LaunchID, scope.Actor, scope.EndpointGeneration)
	if err != nil {
		return err
	}
	parent, err = s.refreshLaunchPolicy(ctx, scope, parent)
	if err != nil {
		return err
	}
	policy, err := s.policyForLane(ctx, scope, parent)
	if err != nil {
		return failure(err)
	}
	if policy.Generation != request.ExpectedPolicyGeneration {
		allowAndLog("launch_policy_generation")
	}
	return s.launchAvailability(ctx, scope, request)
}

func humanTicketEndpoint(scope api.Scope) bool {
	if scope.Actor.Kind != "human" || absent(scope.Connection) {
		return false
	}
	binding := scope.Connection.Binding()
	return binding.Class == api.EndpointHuman && binding.Config == scope.Config &&
		binding.EndpointGeneration != 0 && binding.EndpointGeneration == scope.EndpointGeneration
}

func (s *Service) probe(ctx context.Context) error {
	if absent(s.deps.Launcher) {
		return api.NotImplemented("lb-v2-linux", "Launcher.Probe")
	}
	capabilities, err := s.deps.Launcher.Probe(ctx)
	if err != nil {
		return failure(err)
	}
	if !capabilities.Available || len(capabilities.Checks) == 0 || capabilities.Backend == "" {
		return problem(api.CodePrerequisite, "isolation launch prerequisites are unavailable",
			"Repair the installed backend before starting an agent.")
	}
	for _, check := range capabilities.Checks {
		if !check.Available {
			return problem(api.CodePrerequisite, "an isolation launch check failed",
				"Repair every failed backend capability; no agent was released.")
		}
	}
	return nil
}

func (s *Service) LaneStart(ctx context.Context, scope api.Scope,
	request api.StartRequest) (api.Operation, error) {
	if err := s.authorize(ctx, scope, "lane.start", request); err != nil {
		return api.Operation{}, err
	}
	if result, found, err := s.launchReplay(ctx, scope); found || err != nil {
		return result, err
	}
	if err := s.spawnPreflight(ctx, scope, request, true); err != nil {
		return api.Operation{}, err
	}
	return s.reservePublicLaunch(ctx, scope, "start", api.Lane{})
}

func (s *Service) LaneAdopt(ctx context.Context, scope api.Scope,
	request api.AdoptRequest) (api.Operation, error) {
	if err := s.authorize(ctx, scope, "lane.adopt", request); err != nil {
		return api.Operation{}, err
	}
	if result, found, err := s.launchReplay(ctx, scope); found || err != nil {
		return result, err
	}
	start := api.StartRequest{Lane: request.Lane,
		Level: request.Level, Role: request.Role, Task: request.Task, Grants: request.Grants,
		Driver: request.Driver, ProfileGrantID: request.ProfileGrantID,
		Model: request.Model, Effort: request.Effort, Budget: request.Budget,
		RootTicketID:             request.RootTicketID,
		ExpectedPolicyGeneration: request.ExpectedPolicyGeneration}
	// D9 is checked before reading or importing any legacy workspace.
	if err := s.spawnPreflight(ctx, scope, start, false); err != nil {
		return api.Operation{}, err
	}
	if !validBlob(request.ImportManifest) || request.ImportManifest.Class != "manifest" {
		return api.Operation{}, invalid("adoption requires an immutable manifest")
	}
	data, err := s.readBlob(ctx, scope, request.ImportManifest)
	if err != nil {
		return api.Operation{}, err
	}
	var manifest api.AdoptionManifest
	if err := decode(data, &manifest); err != nil {
		return api.Operation{}, err
	}
	if manifest.Schema != "laneboss.adoption.v2" ||
		manifest.Session.Driver != request.Driver || !validSession(manifest.Session) ||
		!validBlob(manifest.Quiescence) || !validBlob(manifest.PrivateHistory) {
		return api.Operation{}, invalid("invalid adoption session or provenance")
	}
	return s.reservePublicLaunch(ctx, scope, "adopt", api.Lane{})
}

func validSession(session api.Session) bool {
	return validID(session.ID) && driverAllowed(session.Driver) && session.VendorID != "" &&
		session.VendorVersion != "" && validID(session.HomeID) && validID(session.HistoryID) && session.LogicalCWD != ""
}

func (s *Service) resumeReady(ctx context.Context, scope api.Scope, lane api.Lane,
	target api.LifeRef, budget api.Budget) error {
	if lane.Cleaned || lane.Run != target.Run ||
		(lane.State != "verifying" && lane.State != "idle" && lane.State != "accepted" &&
			lane.State != "profile_wait") {
		return problem(api.CodeConflict, "life is not eligible for continuation",
			"Use an ended, uncleaned life with its current session and generation.")
	}
	if !validSession(lane.Session) || !validID(lane.Workspace.ID) ||
		lane.Workspace.LogicalCWD != lane.Session.LogicalCWD {
		return problem(api.CodePrerequisite, "life has no verified retained session",
			"Reconcile the vendor mapping and private workspace before resuming.")
	}
	if !validBudget(budget) {
		return invalid("continuation requires an explicit valid budget")
	}
	remaining := lane.BudgetRemaining
	if budget.Currency != remaining.Currency || budget.WallMS > remaining.WallMS ||
		budget.CPUSeconds > remaining.CPUSeconds || budget.MemoryBytes > remaining.MemoryBytes ||
		budget.Processes > remaining.Processes || budget.DiskBytes > remaining.DiskBytes ||
		budget.SpendMicros > remaining.SpendMicros {
		return problem(api.CodeBudget, "continuation exceeds the remaining budget",
			"Retain the remaining task budget; obtain a separate authorized change if needed.")
	}
	observed, facts, err := s.observe(ctx, scope, lane, target)
	if err != nil {
		return err
	}
	if err := requireQuiescence(observed); err != nil {
		return err
	}
	if facts.end == nil || facts.end.Reason == "service_lost" ||
		requireQuiescence(facts.end.Observation) != nil {
		return problem(api.CodeContainmentUnknown, "run has no committed quiescent end",
			"Reconcile capture and containment before creating another run.")
	}
	if _, err := s.revalidate(ctx, scope, lane); err != nil {
		return err
	}
	if _, err := s.runner(lane.Session.Driver); err != nil {
		return err
	}
	return s.probe(ctx)
}

func (s *Service) revalidate(ctx context.Context, scope api.Scope,
	lane api.Lane) (api.GrantSet, error) {
	// This is current capability revalidation of historical issuance. A fresh
	// launch resolves a distinct reserved grant snapshot in sourceInputs, whose
	// policy must equal the new reservation/current policy before any release.
	// Rewriting this retained set's generation would corrupt its old binding.
	if absent(s.deps.Grants) {
		return api.GrantSet{}, api.NotImplemented("lb-v2-grants", "GrantResolver.Revalidate")
	}
	grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return api.GrantSet{}, failure(err)
	}
	if grants.ID != lane.GrantSetID || grants.LifeID != lane.LifeID || grants.Revoked ||
		grants.ParentLifeID != lane.ParentLifeID {
		return api.GrantSet{}, problem(api.CodeForbidden, "retained grants are invalid or revoked",
			"Obtain valid delegated grants through the authentic starter.")
	}
	current, err := s.deps.Grants.Revalidate(ctx, grants)
	if err != nil {
		return api.GrantSet{}, failure(err)
	}
	if current.ID != grants.ID || current.LifeID != lane.LifeID || current.Revoked ||
		current.ParentLifeID != grants.ParentLifeID || !validDigest(current.SHA256) {
		return api.GrantSet{}, integrity("grant revalidation changed the retained life")
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return api.GrantSet{}, failure(err)
	}
	if scope.PolicyGeneration == 0 || uint64(scope.PolicyGeneration) > maxInteger ||
		scope.PolicyGeneration != policy.Generation || !validGeneration(current.PolicyGeneration) || current.PolicyGeneration > policy.Generation {
		return api.GrantSet{}, problem(api.CodeConflict, "current policy and grants differ",
			"Revalidate the complete grant set under current policy before release.")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(current.ExpiresAt))
	if err != nil || !s.deps.Clock.Now().Before(expires) {
		return api.GrantSet{}, problem(api.CodeForbidden, "retained grants have expired",
			"Obtain a current delegated grant set before continuing.")
	}
	return current, nil
}

func (s *Service) policyForLane(ctx context.Context, scope api.Scope, lane api.Lane) (api.EffectivePolicy, error) {
	if (scope.Actor.Kind == "lane" || scope.Actor.Kind == "worker") && scope.Actor.LifeID != lane.LifeID {
		// Draft.4 makes BriefingInputRequest an own-life claim. A parent
		// cannot use that port as a selector for its child's policy, and its
		// authenticated actor must not be relabelled to make the read pass.
		return api.EffectivePolicy{}, api.NotImplemented(owner, "trusted target policy outside own-life briefing")
	}
	input, err := s.deps.Store.BriefingInput(ctx, scope, api.BriefingInputRequest{
		LifeID: lane.LifeID, GrantSetID: lane.GrantSetID,
		Context: api.RoleContext{Level: lane.Level, Role: lane.Role}})
	if err != nil {
		return api.EffectivePolicy{}, failure(err)
	}
	if input.Lane == nil || input.Lane.LifeID != lane.LifeID || input.Lane.Run != lane.Run ||
		input.Lane.Generation != lane.Generation || input.Lane.GrantSetID != lane.GrantSetID ||
		input.Lane.Level != lane.Level || input.Lane.Role != lane.Role ||
		input.Policy.Context.Level != lane.Level || input.Policy.Context.Role != lane.Role ||
		input.Policy.Generation == 0 || input.Policy.Generation != lane.PolicyGeneration {
		return api.EffectivePolicy{}, integrity("resolved policy does not match the authentic target role")
	}
	return input.Policy, nil
}

func (s *Service) LaneResume(ctx context.Context, scope api.Scope,
	request api.ResumeRequest) (api.Operation, error) {
	if err := s.authorize(ctx, scope, "lane.resume", request); err != nil {
		return api.Operation{}, err
	}
	unlock, err := s.lockLife(ctx, request.Target.LifeID)
	if err != nil {
		return api.Operation{}, err
	}
	defer unlock()
	lane, err := s.lane(ctx, scope, request.Target, false)
	if err != nil {
		return api.Operation{}, err
	}
	if operation, done, err := s.launchReplay(ctx, scope); done || err != nil {
		return operation, err
	}
	lane, err = s.refreshLaunchPolicy(ctx, scope, lane)
	if err != nil {
		return api.Operation{}, err
	}
	if lane.Generation != request.ExpectedGeneration {
		return api.Operation{}, problem(api.CodeConflict, "life generation changed",
			"Read the current generation before reserving another run.")
	}
	if err := s.resumeReady(ctx, scope, lane, request.Target, request.Budget); err != nil {
		return api.Operation{}, err
	}
	if !validBlob(request.Message) || request.Message.Class != "task" || request.Message.Bytes == 0 {
		return api.Operation{}, invalid("resume requires an immutable message")
	}
	if _, err := s.readBlob(ctx, scope, request.Message); err != nil {
		return api.Operation{}, err
	}
	return s.reservePublicLaunch(ctx, scope, "resume", lane)
}

func (s *Service) LaneTurn(ctx context.Context, scope api.Scope,
	request api.TurnRequest) (api.Operation, error) {
	if err := s.authorize(ctx, scope, "lane.turn", request); err != nil {
		return api.Operation{}, err
	}
	unlock, err := s.lockLife(ctx, request.Target.LifeID)
	if err != nil {
		return api.Operation{}, err
	}
	defer unlock()
	lane, err := s.lane(ctx, scope, request.Target, false)
	if err != nil {
		return api.Operation{}, err
	}
	if operation, done, err := s.launchReplay(ctx, scope); done || err != nil {
		return operation, err
	}
	lane, err = s.refreshLaunchPolicy(ctx, scope, lane)
	if err != nil {
		return api.Operation{}, err
	}
	if lane.Generation != request.ExpectedGeneration {
		return api.Operation{}, problem(api.CodeConflict, "life generation changed",
			"Read the current generation before reserving another run.")
	}
	if err := s.resumeReady(ctx, scope, lane, request.Target, request.Budget); err != nil {
		return api.Operation{}, err
	}
	trigger, err := turnTrigger(request)
	if err != nil {
		return api.Operation{}, err
	}
	if request.IdleMessage != nil {
		if _, err := s.readBlob(ctx, scope, *request.IdleMessage); err != nil {
			return api.Operation{}, err
		}
	}
	// The reservation retains the authentic requester and ordered trigger;
	// planning/delivery consume those exact inputs under their durable claims.
	_ = trigger
	return s.reservePublicLaunch(ctx, scope, "turn", lane)
}
