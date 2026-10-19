package admin

import (
	"context"
	"path/filepath"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
)

// ReviewRequirements is administrator-installed policy data. A public review
// request cannot choose this file, its project, generation or required names.
// The installer/operator retains it beside the protected installation binding.
type ReviewRequirements struct {
	Schema           string                `json:"schema"`
	Config           string                `json:"config"`
	PolicyGeneration api.Generation        `json:"policy_generation"`
	Projects         []ReviewProjectChecks `json:"projects"`
}

type ReviewProjectChecks struct {
	ProjectID api.ID   `json:"project_id"`
	Checks    []string `json:"checks"`
}

func (s *Service) RequiredReviewChecks(ctx context.Context, scope api.Scope, target api.LifeRef) ([]string, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if s.deps.Store == nil || scope.Config != s.deps.Config || scope.Actor.Kind != "service" || scope.Connection != nil || scope.Frame != nil || !validID(target.LifeID) || target.Run == 0 {
		return nil, failure(api.CodeForbidden, "review requirements need the installed service and exact target")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, target)
	if err != nil {
		return nil, err
	}
	current, ok := s.deps.Store.(interface {
		CurrentApprovedPolicy(context.Context, api.Scope) (api.EffectivePolicy, error)
	})
	if !ok {
		return nil, failure(api.CodePrerequisite, "review requirements need current approved policy")
	}
	policy, err := current.CurrentApprovedPolicy(ctx, scope)
	if err != nil {
		return nil, err
	}
	return readReviewRequirements(filepath.Join("/etc/laneboss-v2/review", s.deps.Config+".json"), s.deps.Config, lane.Workspace.ProjectID, policy.Generation)
}

func readReviewRequirements(path, config string, project api.ID, generation api.Generation) ([]string, error) {
	raw, err := readReviewProtected(path, api.MaxFrameBytes)
	if err != nil {
		return nil, err
	}
	var document ReviewRequirements
	if decodeStrict(raw, &document) != nil || document.Schema != "laneboss.review-requirements.v2" || document.Config != config ||
		document.PolicyGeneration != generation || generation == 0 || !validID(project) || len(document.Projects) == 0 || len(document.Projects) > 200 {
		return nil, failure(api.CodePrerequisite, "protected review requirements do not match current project policy")
	}
	seen := map[api.ID]bool{}
	var result []string
	for _, row := range document.Projects {
		if !validID(row.ProjectID) || seen[row.ProjectID] || len(row.Checks) == 0 || len(row.Checks) > 200 {
			return nil, failure(api.CodeIntegrity, "protected review requirements contain invalid projects")
		}
		seen[row.ProjectID] = true
		names := map[string]bool{}
		for _, name := range row.Checks {
			if !validID(api.ID(name)) || names[name] {
				return nil, failure(api.CodeIntegrity, "protected review requirements contain invalid check names")
			}
			names[name] = true
		}
		if row.ProjectID == project {
			result = slices.Clone(row.Checks)
		}
	}
	if len(result) == 0 {
		return nil, failure(api.CodePrerequisite, "current project has no protected review requirements")
	}
	return result, nil
}
