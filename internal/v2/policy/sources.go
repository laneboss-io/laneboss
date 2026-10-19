package policy

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

type sourceSnapshot struct {
	api.OrgSnapshotRef
	Inputs []api.BlobRef
}

// approvedSources checks the effective policy against one approved org
// generation. Org/source generations are independent of policy generations.
// Source paths are discovery metadata, never filesystem inputs to this module.
func (s *Service) approvedSources(ctx context.Context, scope api.Scope, policy api.EffectivePolicy) (sourceSnapshot, error) {
	// SourceRef.Generation pins the current org snapshot, independently of
	// EffectivePolicy.Generation. Use the provenance loaded from real policy
	// state; never turn an absent selector into "current" or generation one.
	if len(policy.Sources) == 0 {
		return sourceSnapshot{}, integrity("approved policy omits its org source generation")
	}
	generation := policy.Sources[0].Generation
	for _, ref := range policy.Sources {
		if ref.Generation != generation {
			return sourceSnapshot{}, integrity("policy sources do not share an approved org generation")
		}
	}
	request := api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: generation}
	if err := api.ValidateOrgSnapshotRequest(scope, request); err != nil {
		return sourceSnapshot{}, err
	}
	snapshot, err := s.deps.Store.OrgSnapshot(ctx, scope, request)
	if err != nil {
		return sourceSnapshot{}, err
	}
	if snapshot.Config != scope.Config || !validID(snapshot.Ref.OrgID) || snapshot.Ref.Generation == 0 ||
		snapshot.Ref.OrgID != request.OrgID || snapshot.Ref.Generation != request.Generation ||
		!validDigest(snapshot.Ref.ManifestSHA256) || snapshot.Sources == nil || snapshot.Derived == nil {
		return sourceSnapshot{}, integrity("approved org snapshot is incomplete")
	}
	result := sourceSnapshot{OrgSnapshotRef: snapshot.Ref, Inputs: []api.BlobRef{}}
	files := make(map[api.ID]api.ResourceFile, len(snapshot.Sources))
	for _, file := range snapshot.Sources {
		if !validSource(file.Source) || file.Source.Generation != snapshot.Ref.Generation ||
			file.RevisionGeneration == 0 || file.RevisionGeneration > snapshot.Ref.Generation ||
			!validID(file.Content.ID) || file.Content.SHA256 != file.Source.SHA256 ||
			file.Content.Bytes < 0 || file.Content.Bytes > api.MaxObjectBytes {
			return sourceSnapshot{}, integrity("approved source inventory is invalid")
		}
		if _, duplicate := files[file.Source.ID]; duplicate {
			return sourceSnapshot{}, integrity("approved source identity is duplicated")
		}
		files[file.Source.ID] = file
		result.Inputs = append(result.Inputs, file.Content)
	}
	for _, source := range policy.Sources {
		file, found := files[source.ID]
		if !found || file.Source != source {
			return sourceSnapshot{}, conflict("policy source differs from approved org snapshot")
		}
		retained, err := s.deps.Store.Source(ctx, scope, source)
		if err != nil {
			return sourceSnapshot{}, err
		}
		if retained.Source != source || retained.Content != file.Content {
			return sourceSnapshot{}, integrity("approved source content reference changed")
		}
	}
	return result, nil
}
