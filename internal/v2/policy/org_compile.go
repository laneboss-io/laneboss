package policy

import (
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// OrgDocument is the editable policy source. Source identities and generations
// are assigned from the approved inventory, rather than embedded in the file.
type OrgDocument struct {
	Rules                   []api.Rule       `json:"rules,omitempty"`
	Skip                    []api.SkipEntry  `json:"skip,omitempty"`
	Judge                   *api.JudgeConfig `json:"judge,omitempty"`
	GuidanceHalfLifeSeconds *int64           `json:"guidance_half_life_seconds,omitempty"`
	GuidanceMinRelevance    *float64         `json:"guidance_min_relevance,omitempty"`
	ProfileExclusions       *[]api.ID        `json:"profile_exclusions,omitempty"`
}

func CompileOrgSources(current api.EffectivePolicy, before, after api.OrgSnapshot, read func(api.BlobRef) ([]byte, error)) (api.EffectivePolicy, error) {
	var zero api.EffectivePolicy
	if err := validatePolicy(current); err != nil {
		return zero, err
	}
	digest, err := policyDigest(current)
	if err != nil || digest != current.SHA256 {
		return zero, integrity("approved policy content hash changed")
	}
	if before.Config != after.Config || before.Ref.OrgID != after.Ref.OrgID || after.Ref.Generation != before.Ref.Generation+1 || current.Generation >= 1<<53-1 || before.Renderer != after.Renderer || before.OwnershipManifest != after.OwnershipManifest {
		return zero, integrity("policy compiler inputs changed their approved org binding")
	}
	oldFiles, err := policyOrgFiles(before)
	if err != nil {
		return zero, err
	}
	newFiles, err := policyOrgFiles(after)
	if err != nil {
		return zero, err
	}
	next := copyPolicy(current)
	next.Generation++
	refs := map[api.ID]api.SourceRef{}
	changed := map[api.ID]api.ResourceFile{}
	for i, source := range current.Sources {
		old, oldOK := oldFiles[source.ID]
		file, newOK := newFiles[source.ID]
		if !oldOK || old.Source != source || !newOK || file.Kind != "policy" {
			return zero, integrity("policy compiler source is absent or differs from its approved input")
		}
		refs[source.ID], next.Sources[i] = file.Source, file.Source
		comparison := file
		comparison.Source.Generation = old.Source.Generation
		if comparison != old {
			changed[source.ID] = file
		}
	}
	if len(changed) == 0 {
		return RebindOrgSources(current, before, after)
	}
	next.GuidanceSource = refs[current.GuidanceSource.ID]
	next.Rules, next.Skip = []api.Rule{}, []api.SkipEntry{}
	for _, rule := range current.Rules {
		if _, replaced := changed[rule.Source.ID]; !replaced {
			rule.Source = refs[rule.Source.ID]
			next.Rules = append(next.Rules, rule)
		}
	}
	for _, skip := range current.Skip {
		if _, replaced := changed[skip.Source.ID]; !replaced {
			skip.Source = refs[skip.Source.ID]
			next.Skip = append(next.Skip, skip)
		}
	}
	for _, source := range current.Sources {
		file, updated := changed[source.ID]
		if !updated {
			continue
		}
		raw, err := read(file.Content)
		if err != nil {
			return zero, err
		}
		if digestBytes(raw) != file.Content.SHA256 || int64(len(raw)) != file.Content.Bytes {
			return zero, integrity("policy compiler bytes differ from the approved source")
		}
		oldRules := []api.Rule{}
		oldSkip := []api.SkipEntry{}
		for _, rule := range current.Rules {
			if rule.Source.ID == source.ID {
				oldRules = append(oldRules, rule)
			}
		}
		for _, skip := range current.Skip {
			if skip.Source.ID == source.ID {
				oldSkip = append(oldSkip, skip)
			}
		}
		var document OrgDocument
		text := strings.TrimSpace(string(raw))
		if strings.HasPrefix(text, "{") {
			if err := api.DecodeObject(raw, &document); err != nil {
				return zero, err
			}
		} else if len(oldRules) == 1 {
			document.Rules = append([]api.Rule{}, oldRules...)
			document.Rules[0].Text = text
		} else {
			return zero, invalid("multi-rule policy edits require a JSON policy document")
		}
		if document.Rules == nil {
			document.Rules = oldRules
		}
		if document.Skip == nil {
			document.Skip = oldSkip
		}
		for _, rule := range document.Rules {
			rule.Source, rule.Scope = file.Source, cloneScope(rule.Scope)
			if rule.Thresholds == (api.Thresholds{}) && len(oldRules) != 0 {
				rule.Thresholds = oldRules[0].Thresholds
			}
			next.Rules = append(next.Rules, rule)
		}
		for _, skip := range document.Skip {
			skip.Source = file.Source
			next.Skip = append(next.Skip, skip)
		}
		if document.Judge != nil {
			next.Judge = *document.Judge
		}
		if document.GuidanceHalfLifeSeconds != nil {
			next.GuidanceHalfLifeSeconds = *document.GuidanceHalfLifeSeconds
		}
		if document.GuidanceMinRelevance != nil {
			next.GuidanceMinRelevance = *document.GuidanceMinRelevance
		}
		if document.ProfileExclusions != nil {
			next.ProfileExclusions = append([]api.ID{}, (*document.ProfileExclusions)...)
		}
	}
	if err := validatePolicy(next); err != nil {
		return zero, err
	}
	next.SHA256, err = policyDigest(next)
	return next, err
}
