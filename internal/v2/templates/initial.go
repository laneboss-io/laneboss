package templates

import (
	"path"
	"regexp"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// ValidateInitialSources is the narrow pre-publication source inventory entry.
// Content is supplied by the protected importer; no source path is opened here.
func ValidateInitialSources(config string, snapshot api.OrgSnapshot, l5 api.RoleContext) error {
	bad := func() error {
		return &api.Error{Code: api.CodeInvalid, Owner: "lb-v2-templates", Message: "invalid initial source inventory", Instead: "Supply a generation-one org source set with explicit L5 prompt and driver files."}
	}
	id := regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	digest := regexp.MustCompile(`^[a-f0-9]{64}$`)
	if snapshot.Config != config || snapshot.Ref.OrgID != api.ID(config) || snapshot.Ref.Generation != 1 || !digest.MatchString(string(snapshot.Ref.ManifestSHA256)) || snapshot.PublishedBy != "" || snapshot.PublishedAt != "" || len(snapshot.Sources) > 512 || l5.Level != 5 || !id.MatchString(l5.Role) || l5.InstanceID != "" {
		return bad()
	}
	if api.ValidateOrgKinds(snapshot) != nil {
		return bad()
	}
	seen := map[api.ID]bool{}
	paths := map[string]bool{}
	prompt, drivers := false, false
	for _, f := range snapshot.Sources {
		s := f.Source
		if !id.MatchString(string(s.ID)) || !digest.MatchString(string(s.SHA256)) || seen[s.ID] || s.Generation != 1 || f.RevisionGeneration != 1 || s.Path == "" || len(s.Path) > 4096 || path.IsAbs(s.Path) || path.Clean(s.Path) != s.Path || s.Path == ".." || strings.HasPrefix(s.Path, "../") || strings.ContainsAny(s.Path, "\\\x00\r\n") || paths[s.Path] || f.Content.SHA256 != s.SHA256 || !id.MatchString(string(f.Content.ID)) || f.Content.Class != "artifact" || f.Content.Bytes <= 0 || f.Content.Bytes > api.MaxObjectBytes || f.Mode != 0444 {
			return bad()
		}
		seen[s.ID], paths[s.Path] = true, true
		switch f.Kind {
		case "prompt":
			prompt = true
		case "drivers":
			drivers = true
		}
	}
	if !prompt || !drivers {
		return bad()
	}
	return nil
}
