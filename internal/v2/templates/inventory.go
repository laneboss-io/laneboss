package templates

import (
	"fmt"
	"path"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

// ValidateSourceRef checks a lookup claim before any store view is opened.
// It supplies no authority to resolve a well-formed but unretained reference.
func ValidateSourceRef(ref api.SourceRef) error {
	if !safeID.MatchString(string(ref.ID)) || !safeDigest.MatchString(string(ref.SHA256)) ||
		ref.Generation == 0 || ref.Generation > maxGeneration || ref.Path == "" || len(ref.Path) > 4096 ||
		path.IsAbs(ref.Path) || path.Clean(ref.Path) != ref.Path || ref.Path == "." || ref.Path == ".." ||
		strings.HasPrefix(ref.Path, "../") || strings.ContainsAny(ref.Path, "\\\r\n\x00") || !utf8.ValidString(ref.Path) {
		return invalid("source lookup requires a valid identity, relative path, digest and exact generation")
	}
	return nil
}

// ValidateTemplateContext permits store adapters to check the same role claim
// as selection before opening a read view or querying an org snapshot.
func ValidateTemplateContext(role api.RoleContext) error { return checkContext(role) }

// SelectSources projects an already authenticated, committed org inventory.
// The store remains responsible for its read view and each object's visibility.
func SelectSources(scope api.Scope, snapshot api.OrgSnapshot, role api.RoleContext) (api.TemplateSources, error) {
	if err := ValidateTemplateContext(role); err != nil {
		return api.TemplateSources{}, err
	}
	if err := checkSnapshot(scope, snapshot); err != nil {
		return api.TemplateSources{}, err
	}
	byPath := make(map[string]api.ResourceFile, len(snapshot.Sources))
	for _, file := range snapshot.Sources {
		byPath[file.Source.Path] = file
	}
	pair := func(body, drivers string) (api.RoleTemplateSources, bool, error) {
		prompt, hasPrompt := byPath[body]
		catalog, hasDrivers := byPath[drivers]
		if !hasPrompt && !hasDrivers {
			return api.RoleTemplateSources{}, false, nil
		}
		if !hasPrompt || !hasDrivers || prompt.Kind != "prompt" || catalog.Kind != "drivers" {
			return api.RoleTemplateSources{}, false, invalid("template prompt and driver sources must be a complete semantic pair")
		}
		return api.RoleTemplateSources{
			Prompt:  api.TemplateSource{Source: prompt.Source, Content: prompt.Content},
			Drivers: api.TemplateSource{Source: catalog.Source, Content: catalog.Content},
		}, true, nil
	}
	org, present, err := pair(OrgTemplatePath, OrgDriversPath)
	if err != nil {
		return api.TemplateSources{}, err
	}
	if !present {
		return api.TemplateSources{}, invalid("approved org template and driver sources are required")
	}
	result := api.TemplateSources{Snapshot: snapshot.Ref, Context: role, Org: org, LocalStatus: "absent"}
	base := fmt.Sprintf(".laneboss/L%d/roles/%s", role.Level, role.Role)
	local, present, err := pair(base+".md", base+".toml")
	if err != nil {
		return api.TemplateSources{}, err
	}
	if present {
		result.Local, result.LocalStatus = &local, "present"
	}
	return result, nil
}

// SelectSource never interprets a SourceRef ID as an object ID or opens a path.
// Only exact entries in the current committed source inventory may resolve.
func SelectSource(scope api.Scope, snapshot api.OrgSnapshot, ref api.SourceRef) (api.RetainedSource, error) {
	if err := ValidateSourceRef(ref); err != nil {
		return api.RetainedSource{}, err
	}
	if err := checkSnapshot(scope, snapshot); err != nil {
		return api.RetainedSource{}, err
	}
	if ref.Generation != snapshot.Ref.Generation {
		return api.RetainedSource{}, problem(api.CodeConflict, "source generation differs from the current publication",
			"Resolve the exact current committed source reference.")
	}
	for _, file := range snapshot.Sources {
		if file.Source == ref {
			return api.RetainedSource{Source: file.Source, Content: file.Content}, nil
		}
	}
	return api.RetainedSource{}, problem(api.CodeNotFound, "source reference is outside the committed org inventory",
		"Use an exact retained source identity, path, digest and generation.")
}
