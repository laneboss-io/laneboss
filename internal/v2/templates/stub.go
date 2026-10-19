// Package templates renders retained task and approved role bytes without
// executing an agent or granting authority through prompt text.
package templates

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Publisher api.OrgPublisher
	Clock     api.Clock
	Store     api.StateStore
	Policy    api.PolicyAPI
	Human     api.HumanVerifier
	// Bootstrap pins are protected installation inputs, never request fields.
	BootstrapRenderer  api.Executable
	BootstrapOwnership api.BlobRef
}

type Service struct {
	deps Dependencies
}

func New(deps Dependencies) (*Service, error) {
	if deps.Store == nil || deps.Policy == nil {
		return nil, problem(api.CodePrerequisite, "templates requires the service store and policy component",
			"Wire the frozen store and policy interfaces before registering templates.")
	}
	return &Service{deps: deps}, nil
}

var _ api.TemplatesAPI = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if registry == nil || s == nil {
		return invalid("templates requires a registrar and initialized service")
	}
	entries := []struct {
		method  api.Method
		handler api.Handler
	}{
		{"brief.render", templateHandler(s.BriefRender)},
		{"brief.start", templateHandler(s.BriefStart)},
		{"org.validate", templateHandler(s.OrgValidate)},
		{"org.bootstrap", templateHandler(s.OrgBootstrap)},
	}
	for _, entry := range entries {
		if err := registry.Register(entry.method, entry.handler); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) BriefRender(ctx context.Context, scope api.Scope, request api.TemplateRequest) (api.Briefing, error) {
	if err := checkScope(scope); err != nil {
		return api.Briefing{}, err
	}
	if err := checkContext(request.Context); err != nil {
		return api.Briefing{}, err
	}
	if err := selfContext(scope, request.Context); err != nil {
		return api.Briefing{}, err
	}
	if !safeID.MatchString(string(request.GrantSetID)) {
		return api.Briefing{}, invalid("a committed grant-set identifier is required")
	}
	if err := checkTaskRef(request.Task); err != nil {
		return api.Briefing{}, err
	}
	preparation, err := s.renderPreflight(ctx, scope, request)
	if err != nil {
		return api.Briefing{}, err
	}
	current, err := s.selfLane(ctx, scope, request.Context, request.GrantSetID, "")
	if err != nil {
		return api.Briefing{}, err
	}
	inputRequest := api.BriefingInputRequest{GrantSetID: request.GrantSetID, Context: request.Context}
	if current != nil {
		inputRequest.LifeID, inputRequest.GrantSetID = current.LifeID, current.GrantSetID
	} else if preparation != nil {
		inputRequest.LifeID = preparation.reservation.Target.LifeID
	}
	input, err := s.deps.Store.BriefingInput(ctx, scope, inputRequest)
	if err != nil {
		return api.Briefing{}, err
	}
	if input.Mode != "lane" || input.Lane == nil || input.GrantSet == nil || input.Task == nil {
		return api.Briefing{}, integrity("briefing input omits the authentic life, task or grants")
	}
	grants, lane, policy := *input.GrantSet, *input.Lane, input.Policy
	if grants.ID != request.GrantSetID || !safeID.MatchString(string(grants.LifeID)) || grants.Revoked {
		return api.Briefing{}, integrity("grant projection does not match the render request")
	}
	if lifeBound(scope) && grants.LifeID != scope.Actor.LifeID {
		return api.Briefing{}, problem(api.CodeForbidden, "brief.render is scoped to the authenticated lane",
			"Render your own scope; let the lifecycle service render a child launch.")
	}
	if current != nil && (lane.LifeID != current.LifeID || lane.GrantSetID != current.GrantSetID ||
		lane.Generation != current.Generation || lane.Run != current.Run || lane.Task != current.Task) {
		return api.Briefing{}, integrity("briefing input differs from the authenticated current life")
	}
	if lane.LifeID != grants.LifeID || lane.GrantSetID != grants.ID ||
		lane.Level != request.Context.Level || lane.Role != request.Context.Role {
		return api.Briefing{}, integrity("render role and grants differ from the authentic lane")
	}
	if err := checkLineage(lane); err != nil {
		return api.Briefing{}, err
	}
	if *input.Task != request.Task {
		return api.Briefing{}, problem(api.CodeConflict, "render task differs from the life’s retained task",
			"Use the task retained by the current or reserved life; task visibility is not task assignment.")
	}
	if policy.Context != request.Context || (scope.PolicyGeneration != 0 && scope.PolicyGeneration != policy.Generation) {
		return api.Briefing{}, problem(api.CodeConflict, "render policy is stale or belongs to another role",
			"Resolve the authenticated lane's current policy and grants before rendering.")
	}
	if err := checkPolicyGeneration(lane, grants, policy, scope.Request.Method == "lane.start" || scope.Request.Method == "lane.adopt"); err != nil {
		return api.Briefing{}, err
	}
	if preparation != nil {
		if err := preparation.checkInput(input); err != nil {
			return api.Briefing{}, err
		}
	}
	return s.renderBriefing(ctx, scope, request.Context, input, preparation)
}

func (s *Service) BriefStart(ctx context.Context, scope api.Scope, request api.BriefingRequest) (api.Briefing, error) {
	if err := checkScope(scope); err != nil {
		return api.Briefing{}, err
	}
	role := api.RoleContext{Level: request.Level, Role: request.Role}
	if err := checkContext(role); err != nil {
		return api.Briefing{}, err
	}
	if err := selfContext(scope, role); err != nil {
		return api.Briefing{}, err
	}
	if lifeBound(scope) {
		if request.LifeID != "" && request.LifeID != scope.Actor.LifeID {
			return api.Briefing{}, problem(api.CodeForbidden, "brief.start cannot impersonate another lane life",
				"Use the authenticated life or omit --life-id.")
		}
		request.LifeID = scope.Actor.LifeID
	}
	current, err := s.selfLane(ctx, scope, role, "", request.LifeID)
	if err != nil {
		return api.Briefing{}, err
	}
	if current != nil {
		request.LifeID = current.LifeID
	}
	if request.LifeID != "" {
		if !safeID.MatchString(string(request.LifeID)) {
			return api.Briefing{}, invalid("invalid briefing life identifier")
		}
	}
	// No launch, registration, worker, transaction or ambient-shell binding is
	// performed by this read operation. Only the immutable prompt is retained.
	input, err := s.deps.Store.BriefingInput(ctx, scope, api.BriefingInputRequest{LifeID: request.LifeID, Context: role})
	if err != nil {
		return api.Briefing{}, err
	}
	if request.LifeID != "" {
		if input.Mode != "lane" || input.Lane == nil || input.Lane.LifeID != request.LifeID ||
			input.Lane.Level != request.Level || input.Lane.Role != request.Role || input.Task == nil || input.Lane.Task != *input.Task {
			return api.Briefing{}, integrity("briefing role differs from its authentic lane")
		}
		if current != nil && (input.Lane.Generation != current.Generation || input.Lane.Run != current.Run ||
			input.Lane.GrantSetID != current.GrantSetID || input.Lane.Task != current.Task) {
			return api.Briefing{}, integrity("briefing input differs from the authenticated current life")
		}
	} else if scope.Actor.Kind != "human" || input.Mode != "overview" || input.Lane != nil || input.Task != nil || input.GrantSet != nil {
		return api.Briefing{}, problem(api.CodeForbidden, "a life-free briefing requires a human read-only overview",
			"Use the authenticated life; only a human endpoint may request an overview without one.")
	}
	return s.renderBriefing(ctx, scope, role, input, nil)
}

func (s *Service) OrgValidate(ctx context.Context, scope api.Scope, request api.OrgValidateRequest) (api.OrgValidation, error) {
	if err := checkScope(scope); err != nil {
		return api.OrgValidation{}, err
	}
	if request.Generation == 0 || request.Generation > maxGeneration {
		return api.OrgValidation{}, invalid("an org generation is required")
	}
	snapshot, err := s.deps.Store.OrgSnapshot(ctx, scope, api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: request.Generation})
	if err != nil {
		return api.OrgValidation{}, err
	}
	if snapshot.Config != scope.Config || snapshot.Ref.OrgID != api.ID(scope.Config) ||
		snapshot.Ref.Generation == 0 || snapshot.Ref.Generation > maxGeneration {
		return api.OrgValidation{}, integrity("org validation snapshot differs from its configuration")
	}
	if snapshot.Ref.Generation != request.Generation {
		return api.OrgValidation{}, problem(api.CodeConflict, "org validation snapshot differs from its exact publication",
			"Validate the configuration's exact committed org generation.")
	}
	validation, err := s.deps.Policy.ConfigValidate(ctx, scope, api.Empty{})
	if err != nil {
		return api.OrgValidation{}, err
	}
	if !validation.Valid {
		if len(validation.Problems) == 0 {
			return api.OrgValidation{}, integrity("failed policy validation omitted its problems")
		}
		return validation, nil
	}
	if len(validation.Problems) != 0 {
		return api.OrgValidation{}, integrity("successful policy validation contains problems")
	}
	if err := s.validateOrg(ctx, scope, snapshot); err != nil {
		return api.OrgValidation{}, err
	}
	return api.OrgValidation{Valid: true, Problems: []string{}}, nil
}

func (s *Service) OrgBootstrap(ctx context.Context, scope api.Scope, request api.BootstrapRequest) (api.Operation, error) {
	return s.bootstrap(ctx, scope, request)
}

func templateHandler[Request, Result any](run func(context.Context, api.Scope, Request) (Result, error)) api.Handler {
	return func(ctx context.Context, scope api.Scope, data json.RawMessage) (json.RawMessage, error) {
		var request Request
		if err := DecodeJSON(data, &request); err != nil {
			return nil, err
		}
		result, err := run(ctx, scope, request)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, integrity("template result could not be encoded")
		}
		return encoded, nil
	}
}
