package approval

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// snapshot resolves the exact approved base. Org CAS under Transact establishes
// that it is still current before any write or effect; zero has no invented
// current-generation meaning. The store owns its digest and publication gate.
func (s *Service) snapshot(ctx context.Context, scope api.Scope, org api.ID, base api.Generation) (api.OrgSnapshot, error) {
	snapshot, err := s.deps.Store.OrgSnapshot(ctx, scope, api.OrgSnapshotRequest{OrgID: org, Generation: base})
	if err != nil {
		return api.OrgSnapshot{}, err
	}
	if snapshot.Config != scope.Config || snapshot.Ref.OrgID != org || !validGeneration(snapshot.Ref.Generation) ||
		!validDigest(snapshot.Ref.ManifestSHA256) || !validOwnership(snapshot.OwnershipManifest) ||
		validRenderer(snapshot.Renderer) != nil || snapshot.Sources == nil || snapshot.Derived == nil {
		return api.OrgSnapshot{}, integrity("approved org snapshot lacks exact scope or provenance")
	}
	if snapshot.Ref.Generation != base {
		return api.OrgSnapshot{}, conflict("org generation changed; stage and review a new change")
	}
	paths := []api.ResourceDelta{}
	for _, inventory := range [][]api.ResourceFile{snapshot.Sources, snapshot.Derived} {
		for _, file := range inventory {
			if !validPath(file.Source.Path) || !validID(file.Source.ID) || !validBlob(file.Content) ||
				file.Source.SHA256 != file.Content.SHA256 || file.Source.Generation != snapshot.Ref.Generation ||
				file.RevisionGeneration == 0 || file.RevisionGeneration > snapshot.Ref.Generation || file.Mode > 0777 {
				return api.OrgSnapshot{}, integrity("approved org inventory contains an invalid resource")
			}
			paths = append(paths, api.ResourceDelta{Path: file.Source.Path})
		}
	}
	if err := disjointFiles(paths, nil); err != nil {
		return api.OrgSnapshot{}, integrity("approved org inventory has overlapping paths")
	}
	return snapshot, nil
}

func validateSnapshotBinding(change api.ChangeRequest, snapshot api.OrgSnapshot) error {
	if change.Config != snapshot.Config || change.SourceSnapshot != snapshot.Ref ||
		change.Renderer != snapshot.Renderer || change.OwnershipManifest != snapshot.OwnershipManifest {
		return conflict("approved org provenance changed after staging")
	}
	return validateOwnedDeltas(snapshot, change.Files, change.Derived)
}

// Sources and generated outputs are separate inventories. Neither a file
// extension nor a resource-kind list decides whether a source can be edited.
func validateOwnedDeltas(snapshot api.OrgSnapshot, sources, derived []api.ResourceDelta) error {
	owned := [2]map[string]api.ResourceFile{{}, {}}
	final := make(map[string]bool)
	for group, inventory := range [][]api.ResourceFile{snapshot.Sources, snapshot.Derived} {
		for _, file := range inventory {
			owned[group][file.Source.Path] = file
			final[file.Source.Path] = true
		}
	}
	for group, deltas := range [][]api.ResourceDelta{sources, derived} {
		for _, delta := range deltas {
			if _, foreign := owned[1-group][delta.Path]; foreign {
				return forbidden("resource delta crosses the approved source/generated ownership boundary")
			}
			before, exists := owned[group][delta.Path]
			if delta.Action == "add" {
				if exists {
					return conflict("resource addition targets an existing approved file")
				}
			} else if !exists || delta.BeforeSHA256 != before.Content.SHA256 ||
				delta.Action == "delete" && delta.Mode != before.Mode {
				return conflict("resource preimage or deletion mode differs from the approved inventory")
			}
			if delta.Action == "delete" {
				delete(final, delta.Path)
			} else {
				final[delta.Path] = true
			}
		}
	}
	paths := make([]api.ResourceDelta, 0, len(final))
	for name := range final {
		paths = append(paths, api.ResourceDelta{Path: name})
	}
	if err := disjointFiles(paths, nil); err != nil {
		return conflict("resource deltas create overlapping file and directory paths")
	}
	return nil
}
