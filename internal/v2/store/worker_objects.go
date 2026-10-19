package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// WorkerObject is the job-only object.read operation. It traverses only the
// sealed project's and candidate's manifests; same-life object ownership does
// not grant access to task prompts, histories, other jobs or service objects.
func (s *Service) WorkerObject(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.BlobChunk{}, err
	}
	p, err := s.dataWorkerScope(ctx, s.db, scope, api.WorkerObjectRead)
	if err != nil {
		return api.BlobChunk{}, err
	}
	if request.Offset < 0 || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
		return api.BlobChunk{}, wire.Invalid("worker object range exceeds its bound")
	}
	if p.Lease.Kind == "archive" {
		var r archiveRecord
		if err := storedProjection(ctx, s.db, "archive_job", p.Lease.OperationID, &r); err != nil {
			return api.BlobChunk{}, err
		}
		return s.archiveObject(ctx, s.db, r, request)
	}
	if p.Lease.Kind == "channel" {
		return s.channelObject(ctx, s.db, p, request)
	}
	if p.Lease.Kind == "export" || p.Lease.Kind == "test" {
		return s.reviewObject(ctx, s.db, p, request)
	}
	var saved dataStageRecord
	if err := storedProjection(ctx, s.db, "data_stage", p.StageID, &saved); err != nil {
		return api.BlobChunk{}, err
	}
	refs := map[api.ID]api.BlobRef{}
	// This frame may select one of its own manifest roots. Retain verified
	// bytes only in this invocation so that selecting it does not reload it.
	verified := map[api.ID]verifiedObject{}
	load := func(id api.ID) (api.ObjectMetadata, []byte, error) {
		if row, ok := verified[id]; ok {
			return row.metadata, row.data, nil
		}
		metadata, data, err := objectRow(ctx, s.db, id)
		if err == nil {
			verified[id] = verifiedObject{metadata: metadata, data: data}
		}
		return metadata, data, err
	}
	for _, root := range []api.BlobRef{saved.Stage.Inputs.Sources.Project.Object, saved.Output} {
		metadata, raw, err := load(root.ID)
		if err != nil {
			return api.BlobChunk{}, err
		}
		if metadata.Ref != root {
			return api.BlobChunk{}, fault(api.CodeIntegrity, "worker source manifest changed")
		}
		refs[root.ID] = root
		var manifest api.ObjectManifest
		if err := api.DecodeObject(raw, &manifest); err != nil {
			return api.BlobChunk{}, err
		}
		if manifest.Schema != "laneboss.objects.v2" || len(manifest.Entries) > 65536 {
			return api.BlobChunk{}, fault(api.CodeInvalid, "worker object manifest exceeds its sealed tree")
		}
		for _, entry := range manifest.Entries {
			if entry.Content != nil {
				refs[entry.Content.ID] = *entry.Content
			}
			if entry.Assembly != nil {
				for _, ref := range entry.Assembly.Parts {
					refs[ref.ID] = ref
				}
			}
		}
	}
	ref, allowed := refs[request.ObjectID]
	if !allowed {
		return api.BlobChunk{}, fault(api.CodeNotFound, "worker object is outside its sealed job inputs")
	}
	metadata, raw, err := load(request.ObjectID)
	if err != nil {
		return api.BlobChunk{}, err
	}
	if metadata.Ref != ref || request.Offset > int64(len(raw)) {
		return api.BlobChunk{}, fault(api.CodeIntegrity, "worker object differs from its sealed reference or range")
	}
	data := append([]byte{}, raw[request.Offset:min(int64(len(raw)), request.Offset+int64(request.Limit))]...)
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: data, SHA256: api.Digest(hash(data))}, nil
}
