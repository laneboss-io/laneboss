package grants

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/objectread"
)

func (s *Service) readObject(ctx context.Context, scope api.Scope, id api.ID, expected api.Digest, size int64) ([]byte, error) {
	return s.readCommitted(ctx, scope, id, expected, size, "manifest")
}

func (s *Service) readCommitted(ctx context.Context, scope api.Scope, id api.ID, expected api.Digest, size int64, class string) (resultBytes []byte, resultErr error) {
	ctx = verificationContext(ctx)
	if !manifest.ValidID(id) || !manifest.ValidDigest(expected) || size > api.MaxObjectBytes {
		return nil, manifest.Invalid("invalid registered source object")
	}
	if err := meterMetadata(ctx); err != nil {
		return nil, err
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	if err := manifest.Blob(metadata.Ref); err != nil {
		return nil, integrity("committed object metadata has an invalid reference")
	}
	if metadata.Ref.ID != id || metadata.Ref.SHA256 != expected || metadata.Ref.Class != class ||
		(size >= 0 && metadata.Ref.Bytes != size) || metadata.ACL.Config != scope.Config {
		return nil, integrity("committed object metadata differs from the reference or configuration")
	}
	// The store authorizes metadata and bytes against the same caller. Checking
	// actual bytes below remains necessary even with committed metadata present.
	data := []byte{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, cancelled(err)
		}
		limit := api.MaxChunkBytes
		expectEOF := size >= 0 && int64(len(data)) == size
		if size >= 0 {
			if expectEOF {
				// Read through the store even for an empty object: a digest of
				// empty bytes does not establish existence or object ownership.
				limit = 1
			} else if remaining := size - int64(len(data)); remaining < int64(limit) {
				limit = int(remaining)
			}
		} else if remaining := api.MaxObjectBytes + 1 - len(data); remaining < limit {
			limit = remaining
		}
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: id, Offset: int64(len(data)), Limit: limit})
		if err != nil {
			return nil, err
		}
		if chunk.ObjectID != id || chunk.Offset != int64(len(data)) || len(chunk.Data) > limit || manifest.Hash(chunk.Data) != chunk.SHA256 {
			return nil, integrity("registered source chunk identity, range or digest changed")
		}
		if len(chunk.Data) == 0 {
			if size >= 0 && !expectEOF {
				return nil, integrity("registered source ended before its declared size")
			}
			break
		}
		if expectEOF {
			return nil, integrity("registered source exceeds its declared reference size")
		}
		if err := meterBytes(ctx, int64(len(chunk.Data))); err != nil {
			return nil, err
		}
		data = append(data, chunk.Data...)
		if len(data) > api.MaxObjectBytes {
			return nil, integrity("registered source exceeds the bounded object size")
		}
	}
	if int64(len(data)) != metadata.Ref.Bytes {
		return nil, integrity("committed object length differs from its actual bytes")
	}
	if manifest.Hash(data) != expected {
		return nil, integrity("registered source digest differs from the grant")
	}
	return data, nil
}

func (s *Service) readRef(ctx context.Context, scope api.Scope, ref api.BlobRef) ([]byte, error) {
	if err := manifest.Blob(ref); err != nil {
		return nil, err
	}
	return s.readCommitted(ctx, scope, ref.ID, ref.SHA256, ref.Bytes, ref.Class)
}

func (s *Service) checkSources(ctx context.Context, scope api.Scope, grants api.GrantSet, diskCeiling ...uint64) error {
	objects := map[api.ID]api.ObjectManifest{}
	digests := map[api.ID]api.Digest{}
	refs := map[api.ID]api.BlobRef{}
	var total uint64
	for _, grant := range grants.Data {
		if grant.Delivery == "mount" {
			return api.NotImplemented("lb-v2-grants", "broker volume pinned identity and export lease")
		}
		object, found := objects[grant.SourceObjectID]
		if !found {
			raw, err := s.readObject(ctx, scope, grant.SourceObjectID, grant.SourceSHA256, -1)
			if err != nil {
				return err
			}
			if err := manifest.Decode(raw, &object); err != nil {
				return err
			}
			if err := manifest.Object(object); err != nil {
				return err
			}
			objects[grant.SourceObjectID], digests[grant.SourceObjectID] = object, grant.SourceSHA256
		} else if digests[grant.SourceObjectID] != grant.SourceSHA256 {
			return integrity("one source identity has conflicting grant digests")
		}
		selected, err := manifest.Select(object, grant.RelativePath)
		if err != nil {
			return err
		}
		if len(diskCeiling) == 1 {
			for _, entry := range selected {
				var size int64
				if entry.Content != nil {
					size = entry.Content.Bytes
				}
				if entry.Assembly != nil {
					size = entry.Assembly.Bytes
				}
				if uint64(size) > diskCeiling[0]-total {
					return verificationLimit()
				}
				total += uint64(size)
			}
		}
		if err := s.checkEntryRefs(ctx, scope, selected, refs); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) validateTestInputs(ctx context.Context, scope api.Scope, request api.TestChildRequest, grants api.GrantSet) error {
	raw, err := s.readRef(ctx, scope, request.Candidate)
	if err != nil {
		return err
	}
	var candidate api.ObjectManifest
	if err := manifest.Decode(raw, &candidate); err != nil {
		return err
	}
	if err := manifest.Object(candidate); err != nil {
		return err
	}
	raw, err = s.readRef(ctx, scope, request.TestPlan)
	if err != nil {
		return err
	}
	var plan api.WorkerPlan
	if err := manifest.Decode(raw, &plan); err != nil {
		return err
	}
	if plan.Schema != "laneboss.worker-plan.v2" || plan.Kind != "test" || plan.GrantSetID != grants.ID ||
		!manifest.ValidID(plan.Executable.ID) || !manifest.ValidDigest(plan.Executable.SHA256) || plan.Executable.Version == "" ||
		len(plan.Argv) == 0 || len(plan.Argv) > 4096 || plan.Input != request.Candidate {
		return refused("child test plan does not bind this candidate, executable and child grant set")
	}
	if err := manifest.Budget(plan.Budget); err != nil {
		return err
	}
	if plan.Budget.WallMS > request.Budget.WallMS || plan.Budget.CPUSeconds > request.Budget.CPUSeconds ||
		plan.Budget.MemoryBytes > request.Budget.MemoryBytes || plan.Budget.Processes > request.Budget.Processes ||
		plan.Budget.DiskBytes > request.Budget.DiskBytes || plan.Budget.SpendMicros > request.Budget.SpendMicros ||
		plan.Budget.Currency != request.Budget.Currency {
		return refused("child test plan exceeds its operation budget")
	}
	// Check the plan's authority before applying the candidate's operation disk
	// ceiling. Service reads have a separate fixed bound in limits.go.
	var total uint64
	for _, entry := range candidate.Entries {
		var size int64
		if entry.Content != nil {
			size = entry.Content.Bytes
		}
		if entry.Assembly != nil {
			size = entry.Assembly.Bytes
		}
		if uint64(size) > request.Budget.DiskBytes-total {
			return verificationLimit()
		}
		total += uint64(size)
	}
	return s.childArtifacts(ctx, scope, request, grants, candidate)
}

// A readable parent/sibling artifact is not automatically a child test input.
// New candidate bytes must have an authentic committed upload by this child;
// existing bytes may come only from the child's selected data view. The test
// plan supplies commands, not an ambient parent/sibling data capability.
func (s *Service) childArtifacts(ctx context.Context, scope api.Scope, request api.TestChildRequest,
	grants api.GrantSet, candidate api.ObjectManifest) error {
	selected := map[api.ID]api.BlobRef{}
	for _, grant := range grants.Data {
		raw, err := s.readObject(ctx, scope, grant.SourceObjectID, grant.SourceSHA256, -1)
		if err != nil {
			return err
		}
		var source api.ObjectManifest
		if err := manifest.Decode(raw, &source); err != nil {
			return err
		}
		entries, err := manifest.Select(source, grant.RelativePath)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			for _, ref := range manifest.ContentRefs(entry) {
				if old, found := selected[ref.ID]; found && old != ref {
					return integrity("child source has conflicting content references")
				}
				selected[ref.ID] = ref
			}
		}
	}
	needed := map[api.ID]api.BlobRef{request.Candidate.ID: request.Candidate}
	for _, entry := range candidate.Entries {
		for _, ref := range manifest.ContentRefs(entry) {
			if old, found := selected[ref.ID]; found && old == ref {
				continue
			}
			if old, found := needed[ref.ID]; found && old != ref {
				return integrity("candidate aliases one object with different bytes")
			}
			needed[ref.ID] = ref
		}
	}
	pageRequest := api.EventTailRequest{LifeID: request.Child.LifeID, Run: request.Child.Run}
	previousCursor := ""
	for len(needed) != 0 {
		if err := ctx.Err(); err != nil {
			return cancelled(err)
		}
		page, err := s.deps.Store.Events(ctx, scope, pageRequest)
		if err != nil {
			return err
		}
		for _, event := range page.Events {
			if event.Kind != "blob.committed" || event.Origin != "service" || event.Schema != api.SchemaVersion ||
				event.Config != scope.Config || event.Actor.Kind != "lane" || event.Actor.LifeID != request.Child.LifeID ||
				event.LifeID != request.Child.LifeID || event.Run != request.Child.Run {
				continue
			}
			var ref api.BlobRef
			if err := manifest.Decode(event.Payload, &ref); err != nil {
				return integrity("authoritative child artifact event is invalid")
			}
			if expected, found := needed[ref.ID]; found && ref == expected {
				metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
				if err != nil {
					return err
				}
				if metadata.Ref != expected || metadata.ACL.Config != scope.Config {
					return integrity("child artifact event differs from committed metadata")
				}
				if metadata.ACL.Owner.Kind != "lane" || metadata.ACL.Owner.LifeID != request.Child.LifeID ||
					metadata.ACL.LifeID != request.Child.LifeID {
					return refused("candidate artifact is not owned by the exact child")
				}
				delete(needed, ref.ID)
			}
		}
		if len(needed) == 0 {
			break
		}
		if page.Complete {
			return refused("candidate includes bytes outside the child grants and committed child artifacts")
		}
		if page.Cursor == "" || page.Cursor == previousCursor {
			return integrity("child artifact event cursor did not advance")
		}
		previousCursor, pageRequest.Cursor = page.Cursor, page.Cursor
	}
	return s.checkEntryRefs(ctx, scope, candidate.Entries, map[api.ID]api.BlobRef{})
}

func (s *Service) checkEntryRefs(ctx context.Context, scope api.Scope, entries []api.ObjectEntry, seen map[api.ID]api.BlobRef) error {
	for _, entry := range entries {
		for _, ref := range manifest.ContentRefs(entry) {
			if prior, exists := seen[ref.ID]; exists {
				if prior != ref {
					return integrity("entry aliases a committed object with different metadata")
				}
				continue
			}
			if len(seen) >= maxVerificationRefs {
				return verificationLimit()
			}
			if err := meterMetadata(ctx); err != nil {
				return err
			}
			metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
			if err != nil {
				return err
			}
			if metadata.Ref != ref || metadata.Ref.Class != "artifact" || metadata.ACL.Config != scope.Config {
				return integrity("source entry differs from committed artifact metadata")
			}
			seen[ref.ID] = ref
		}
	}
	return nil
}
