package policy

import (
	"path"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// RebindOrgSources compiles unchanged approved policy inputs for the next org
// publication. It never interprets changed source bytes or renews an exemption.
// The caller must verify the retained objects and measured canonical inventory.
func RebindOrgSources(current api.EffectivePolicy, before, after api.OrgSnapshot) (api.EffectivePolicy, error) {
	var zero api.EffectivePolicy
	if err := validatePolicy(current); err != nil {
		return zero, err
	}
	digest, err := policyDigest(current)
	if err != nil || digest != current.SHA256 {
		return zero, integrity("approved policy content hash changed")
	}
	if current.AllowCaptureRefusal || current.CaptureRefusalApprovalID != "" || len(current.Skip) != 0 {
		return zero, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-policy", Message: "policy exemptions require exact renewed semantic approval", Instead: "Compile and review the exemption or capture policy under its new defining source generation."}
	}
	if before.Config == "" || before.Config != after.Config || before.Ref.OrgID != api.ID(before.Config) || after.Ref.OrgID != before.Ref.OrgID ||
		before.Ref.Generation == 0 || before.Ref.Generation >= 1<<53-1 || after.Ref.Generation != before.Ref.Generation+1 || current.Generation >= 1<<53-1 ||
		!validDigest(before.Ref.ManifestSHA256) || !validDigest(after.Ref.ManifestSHA256) || before.Renderer != after.Renderer || before.OwnershipManifest != after.OwnershipManifest {
		return zero, integrity("policy compilation changed its org, generation or renderer binding")
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
	for i, source := range current.Sources {
		old, oldOK := oldFiles[source.ID]
		file, newOK := newFiles[source.ID]
		if !oldOK || !newOK || old.Source != source || old.Kind != "policy" || file.Source.Generation != after.Ref.Generation {
			return zero, integrity("policy source is absent, foreign or stale in the approved org")
		}
		ref := file.Source
		file.Source.Generation = old.Source.Generation
		if file != old {
			return zero, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-policy", Message: "changed policy source needs semantic compilation", Instead: "Retain and review the actual compiled policy for the changed source before publication."}
		}
		refs[source.ID], next.Sources[i] = ref, ref
	}
	next.GuidanceSource = refs[current.GuidanceSource.ID]
	for i := range next.Rules {
		next.Rules[i].Source = refs[current.Rules[i].Source.ID]
	}
	if err := validatePolicy(next); err != nil {
		return zero, err
	}
	next.SHA256, err = policyDigest(next)
	return next, err
}

func policyOrgFiles(snapshot api.OrgSnapshot) (map[api.ID]api.ResourceFile, error) {
	if err := api.ValidateOrgKinds(snapshot); err != nil {
		return nil, err
	}
	files, paths := map[api.ID]api.ResourceFile{}, map[string]bool{}
	for _, file := range snapshot.Sources {
		ref := file.Source
		if !validSource(ref) || ref.Generation != snapshot.Ref.Generation || file.RevisionGeneration == 0 || file.RevisionGeneration > snapshot.Ref.Generation ||
			!validID(file.Content.ID) || file.Content.SHA256 != ref.SHA256 || file.Content.Bytes < 0 || file.Content.Bytes > api.MaxObjectBytes || file.Mode & ^uint32(0777) != 0 ||
			path.IsAbs(ref.Path) || path.Clean(ref.Path) != ref.Path || ref.Path == "." || ref.Path == ".." || strings.HasPrefix(ref.Path, "../") || paths[ref.Path] {
			return nil, integrity("policy compilation has invalid org source inventory")
		}
		if _, exists := files[ref.ID]; exists {
			return nil, integrity("policy compilation has duplicate org source identity")
		}
		files[ref.ID], paths[ref.Path] = file, true
	}
	return files, nil
}
