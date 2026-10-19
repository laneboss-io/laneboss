package store

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"laneboss.io/laneboss/internal/v2/api"
)

// Optional installed capability of CleanupNative. The administrator resolves
// only exact vendor pins from its protected runtime manifest and streams the
// actual file. No caller path, SQL object or deletion authority is supplied.
type cleanupRuntimeReader interface {
	ReadCleanupRuntime(context.Context, api.BlobRef) (api.CleanupObject, error)
}

func (s *Service) collectionRuntimeObjects(ctx context.Context, objects map[api.ID]graphObject, selected map[api.ID]bool, archiveRefs map[api.ID]api.BlobRef, archive api.ID, references map[api.ID]uint64, inventory *api.CleanupInventory) error {
	missing := map[api.ID]api.BlobRef{}
	for id, from := range objects {
		if !selected[id] {
			continue
		}
		for _, ref := range from.Outbound {
			if !selected[ref.ID] {
				continue
			}
			if _, present := objects[ref.ID]; present {
				continue
			}
			if previous, found := missing[ref.ID]; found && previous != ref {
				return missingCollectionReferences(objects, selected, archiveRefs, archive)
			}
			missing[ref.ID] = ref
		}
	}
	ids := make([]api.ID, 0, len(missing))
	for id := range missing {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		measurement, err := s.measuredRuntime(ctx, s.db, missing[id])
		if err != nil {
			failure := missingCollectionReferences(objects, selected, archiveRefs, archive)
			failure.Message += "; protected runtime verification failed"
			var typed *api.Error
			if errors.As(err, &typed) {
				// This private native port returns fixed diagnostic messages;
				// payloads, file contents and raw OS errors are never appended.
				failure.Message += fmt.Sprintf(" (%s: %s)", typed.Code, typed.Message)
			}
			return failure
		}
		object := measurement.object
		object.References = references[id]
		if inventory != nil {
			for _, previous := range inventory.Objects {
				if previous.Ref == object.Ref && previous.Role == "runtime" && previous.OwnerLifeID == "" && previous.OwnershipGeneration == 0 && previous.RootID != s.storeID {
					// Runtime nodes are immutable provenance and retain-only.
					// Preserve their protected snapshot (including old inventory
					// identities/counts) across native upgrades and new references.
					// Fresh SQL provenance and native state were checked above.
					object = previous
					break
				}
			}
		}
		objects[id] = graphObject{Runtime: &object}
	}
	return nil
}
