package store

import (
	"context"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/templates"
)

// BriefingInput is the public current-life/verified-human reader. Preparing
// launches continue to use LaunchBriefingInput and its separate live effect.
// All request IDs are checked claims after resolving the authentic life.
func (s *Service) BriefingInput(ctx context.Context, scope api.Scope, request api.BriefingInputRequest) (result api.BriefingInput, resultErr error) {
	if scope.Actor.Kind != "lane" && scope.Actor.Kind != "human" {
		return result, fault(api.CodeForbidden, "public briefing requires a current lane or verified human")
	}
	if scope.Actor.Kind == "lane" && request.LifeID != "" && request.LifeID != scope.Actor.LifeID {
		return result, fault(api.CodeForbidden, "briefing life claim differs from the authenticated life")
	}
	bound, owned, err := s.sourceView(ctx, scope)
	if err != nil {
		return result, err
	}
	if owned != nil {
		defer func() { resultErr = errors.Join(resultErr, owned.Close()) }()
	}
	scope = bound
	life := request.LifeID
	if scope.Actor.Kind == "lane" {
		life = scope.Actor.LifeID
	}
	role := request.Context
	var lane api.Lane
	if life != "" {
		lane, err = s.Lane(ctx, scope, api.LifeRef{LifeID: life})
		if err != nil {
			return result, err
		}
		if scope.Actor.Kind == "lane" && (lane.Level != scope.Actor.Level || lane.Role != scope.Actor.Role) {
			return result, fault(api.CodeForbidden, "briefing role differs from its authenticated life")
		}
		if role != (api.RoleContext{}) && (role.Level != lane.Level || role.Role != lane.Role) || request.GrantSetID != "" && request.GrantSetID != lane.GrantSetID {
			return result, fault(api.CodeForbidden, "briefing role or grant claim differs from the authentic life")
		}
		if scope.Actor.Kind == "lane" && role.InstanceID != "" && role.InstanceID != scope.Actor.ID {
			return result, fault(api.CodeForbidden, "briefing instance claim differs from the native binding")
		}
	} else if request.GrantSetID != "" {
		return result, fault(api.CodeForbidden, "human overview cannot select another life's grants")
	}
	selectedRole := role
	if life != "" {
		selectedRole = api.RoleContext{Level: lane.Level, Role: lane.Role, InstanceID: role.InstanceID}
	}
	policy, err := s.policyForRole(ctx, scope, selectedRole)
	if err != nil {
		return result, err
	}
	if policy.Generation == 0 || policy.Generation != scope.PolicyGeneration {
		return result, fault(api.CodeConflict, "public briefing policy generation changed")
	}
	if life != "" {
		actual := api.RoleContext{Level: lane.Level, Role: lane.Role, InstanceID: policy.Context.InstanceID}
		if role != (api.RoleContext{}) && role != actual {
			return result, fault(api.CodeForbidden, "briefing instance claim differs from the authentic life")
		}
		if lane.Cleaned || lane.PolicyGeneration == 0 || lane.PolicyGeneration > policy.Generation {
			return result, fault(api.CodeConflict, "public briefing life is stale or collected")
		}
		grants, err := scopedProjection[api.GrantSet](ctx, s, scope, "grants", lane.GrantSetID)
		if err != nil {
			return result, err
		}
		expiry, err := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt))
		if err != nil || grants.Revoked || grants.LifeID != lane.LifeID || grants.ID != lane.GrantSetID || grants.PolicyGeneration == 0 || grants.PolicyGeneration > policy.Generation || !s.deps.Clock.Now().Before(expiry) {
			return result, fault(api.CodeForbidden, "briefing grants are absent, stale or revoked")
		}
		if policy.Context != actual {
			return result, fault(api.CodeConflict, "approved briefing policy belongs to a different role")
		}
		metadata, err := s.ObjectMetadata(ctx, scope, lane.Task.ID)
		if err != nil {
			return result, err
		}
		if metadata.Ref != lane.Task || lane.Task.Class != "task" {
			return api.BriefingInput{}, fault(api.CodeIntegrity, "briefing task differs from its actual committed object")
		}
		role = actual
		result.Mode, result.Lane, result.Task, result.GrantSet = "lane", &lane, &lane.Task, &grants
	} else {
		if role == (api.RoleContext{}) {
			role = policy.Context
		}
		if role != policy.Context {
			return result, fault(api.CodeConflict, "overview role differs from its approved policy projection")
		}
		result.Mode = "overview"
	}
	if err := templates.ValidateTemplateContext(role); err != nil {
		return api.BriefingInput{}, err
	}
	var snapshot api.OrgSnapshot
	s.mu.RLock()
	db, readErr := s.reader(scope)
	if readErr == nil {
		readErr = storedProjection(ctx, db, "org", api.ID(scope.Config), &snapshot)
	}
	s.mu.RUnlock()
	if readErr != nil {
		return api.BriefingInput{}, readErr
	}
	sources, err := s.TemplateSources(ctx, scope, api.TemplateSourceRequest{OrgID: snapshot.Ref.OrgID, Generation: snapshot.Ref.Generation, Context: role})
	if err != nil {
		return api.BriefingInput{}, err
	}
	page, err := s.Lanes(ctx, scope, api.ListRequest{Limit: 200})
	if err != nil {
		return api.BriefingInput{}, err
	}
	if page.Cursor != "" {
		return api.BriefingInput{}, fault(api.CodeBudget, "public briefing inventory exceeds its bounded page")
	}
	groups, err := templates.GroupLanes(page.Lanes)
	if err != nil {
		return api.BriefingInput{}, err
	}
	result.Policy, result.Sources, result.Groups = policy, sources, groups
	result.Checks = []api.Capability{{Name: "approved_sources", Available: true}, {Name: "current_policy", Available: policy.Generation == scope.PolicyGeneration}}
	if result.Lane != nil {
		result.Checks = append(result.Checks, api.Capability{Name: "current_life", Available: result.Lane.LifeID == life}, api.Capability{Name: "grants", Available: result.GrantSet.ID == result.Lane.GrantSetID})
	}
	return result, nil
}
