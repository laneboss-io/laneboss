package templates

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

var roleSourcePath = regexp.MustCompile(`^\.laneboss/L([3-6])/roles/([^/]+)\.(md|toml)$`)
var roleSourceRoot = regexp.MustCompile(`^\.laneboss/L[^/]+/roles/`)

func isRoleSource(name string) bool { return roleSourceRoot.MatchString(name) }

func isTemplateSource(name string) bool {
	return name == OrgTemplatePath || name == OrgDriversPath || name == WorkflowPath || isRoleSource(name)
}

func templateSourceKind(name string) string {
	switch name {
	case OrgTemplatePath:
		return "prompt"
	case OrgDriversPath:
		return "drivers"
	case WorkflowPath:
		return "policy"
	}
	if match := roleSourcePath.FindStringSubmatch(name); match != nil {
		if match[3] == "md" {
			return "prompt"
		}
		return "drivers"
	}
	return ""
}

// ValidateCatalog validates every discovered role pair, including roles
// other than the requested one. It does not insert seeds into an existing org.
func ValidateCatalog(files map[string][]byte) error {
	workflow, present := files[WorkflowPath]
	if !present {
		return invalid("org workflow source is required")
	}
	if _, err := parseSeed(workflow); err != nil {
		return err
	}
	body, bodyOK := files[OrgTemplatePath]
	driverBytes, driversOK := files[OrgDriversPath]
	if !bodyOK || !driversOK {
		return invalid("org template source and driver source must be a complete pair")
	}
	if err := checkBody(body); err != nil {
		return err
	}
	drivers, err := parseDrivers(driverBytes)
	if err != nil {
		return err
	}
	bases := map[string]bool{}
	for name := range files {
		match := roleSourcePath.FindStringSubmatch(name)
		if match == nil {
			if isRoleSource(name) {
				return invalid("role source path must select exactly L3 through L6 and a role pair")
			}
			continue
		}
		level, err := strconv.Atoi(match[1])
		if err != nil {
			return invalid("role source has an invalid level")
		}
		if err := checkContext(api.RoleContext{Level: level, Role: match[2]}); err != nil {
			return err
		}
		bases[strings.TrimSuffix(name, "."+match[3])] = true
	}
	ordered := make([]string, 0, len(bases))
	for base := range bases {
		ordered = append(ordered, base)
	}
	slices.Sort(ordered)
	for _, base := range ordered {
		local, bodyOK := files[base+".md"]
		localBytes, driversOK := files[base+".toml"]
		if !bodyOK || !driversOK {
			return invalid("local role source and driver source must be a complete pair")
		}
		if err := checkBody(local); err != nil {
			return err
		}
		localDrivers, err := parseDrivers(localBytes)
		if err != nil {
			return err
		}
		for _, driver := range localDrivers {
			if !slices.Contains(drivers, driver) {
				return problem(api.CodeForbidden, "local primary drivers exceed the org catalog",
					"Propose an exact org change through L6 and direct human approval.")
			}
		}
	}
	return nil
}

func (s *Service) validateOrg(ctx context.Context, scope api.Scope, snapshot api.OrgSnapshot) error {
	if err := checkSnapshot(scope, snapshot); err != nil {
		return err
	}
	if _, err := s.readBlob(ctx, scope, snapshot.OwnershipManifest); err != nil {
		return err
	}
	files := map[string][]byte{}
	for _, file := range snapshot.Sources {
		if isTemplateSource(file.Source.Path) && file.Kind != templateSourceKind(file.Source.Path) {
			return invalid("template source kind differs from its prompt, drivers or workflow path")
		}
		retained, err := s.deps.Store.Source(ctx, scope, file.Source)
		if err != nil {
			return err
		}
		if retained.Source != file.Source || retained.Content != file.Content {
			return integrity("approved source identity differs from its committed content")
		}
		if isTemplateSource(file.Source.Path) && file.Content.Bytes > MaxSourceBytes {
			return invalid("template source must be nonempty UTF-8 within 2 MiB")
		}
		data, err := s.readBlob(ctx, scope, file.Content)
		if err != nil {
			return err
		}
		if isTemplateSource(file.Source.Path) {
			if err := checkSource(Source{Ref: file.Source, Bytes: data}, file.Source.Path, snapshot.Ref.Generation); err != nil {
				return err
			}
			files[file.Source.Path] = data
		}
	}
	for _, file := range snapshot.Derived {
		if _, err := s.readBlob(ctx, scope, file.Content); err != nil {
			return err
		}
	}
	return ValidateCatalog(files)
}

// ValidateSources is the complete source-only callback for Policy.ConfigValidate.
// It never calls ConfigValidate or OrgValidate, so assembly can wire this gate
// without recursing through public org validation.
func (s *Service) ValidateSources(ctx context.Context, scope api.Scope, request api.OrgValidateRequest) (api.OrgValidation, error) {
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
		return api.OrgValidation{}, integrity("source validation snapshot differs from its configuration")
	}
	if snapshot.Ref.Generation != request.Generation {
		return api.OrgValidation{}, problem(api.CodeConflict, "source validation snapshot differs from its exact publication",
			"Validate the configuration's exact committed org generation.")
	}
	if err := s.validateOrg(ctx, scope, snapshot); err != nil {
		return api.OrgValidation{}, err
	}
	return api.OrgValidation{Valid: true, Problems: []string{}}, nil
}
