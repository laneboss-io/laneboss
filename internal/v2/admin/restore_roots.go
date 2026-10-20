package admin

import (
	"context"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type restoreRootQuery struct {
	Actor    api.Actor
	LaunchID api.ID
}

type restoreBegin struct {
	Caller  restoreRootQuery
	Request api.RestoreRequest
	Tree    api.ObjectManifest
	Ceiling uint64
}
type restoreSelect struct {
	ID     api.ID
	Caller restoreRootQuery
}
type restoreChunk struct {
	ID, ObjectID api.ID
	Offset       int64
	Data         []byte
}
type nativeRestore struct {
	Input       restoreBegin
	Lease       api.ID
	Root, Stage string
	Refs        map[api.ID]api.BlobRef
	Bodies      map[api.ID][]byte
	Report      api.RestoreReceipt
	Created     time.Time
	Ready       bool
}

// StageRestore transfers only the authenticated immutable inventory, in bounded
// chunks. Publication remains a separate call after the writer's final guards.
func (s *Service) StageRestore(ctx context.Context, scope api.Scope, request api.RestoreRequest, tree api.ObjectManifest, read archivejob.ReadObject, ceiling uint64) (id api.ID, report api.RestoreReceipt, resultErr error) {
	if scope.Config != s.deps.Config || scope.Connection == nil || scope.Request.Method != "lane.restore" {
		return id, report, failure(api.CodeForbidden, "restore_target_scope")
	}
	q := restoreBegin{Caller: restoreRootQuery{Actor: scope.Actor, LaunchID: scope.LaunchID}, Request: request, Tree: tree, Ceiling: ceiling}
	if err := s.call(ctx, "restore_begin", q, &id); err != nil {
		return id, report, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, s.AbortRestore(context.WithoutCancel(ctx), scope, id))
		}
	}()
	seen := map[api.ID]bool{}
	for _, entry := range tree.Entries {
		for _, ref := range manifest.ContentRefs(entry) {
			if seen[ref.ID] {
				continue
			}
			seen[ref.ID] = true
			for offset := int64(0); offset < ref.Bytes; {
				chunk, err := read(ctx, api.BlobReadRequest{ObjectID: ref.ID, Offset: offset, Limit: int(min(int64(api.MaxChunkBytes), ref.Bytes-offset))})
				if err != nil {
					return id, report, err
				}
				if chunk.ObjectID != ref.ID || chunk.Offset != offset || len(chunk.Data) == 0 || int64(len(chunk.Data)) > min(int64(api.MaxChunkBytes), ref.Bytes-offset) || digestBytes(chunk.Data) != chunk.SHA256 {
					return id, report, failure(api.CodeIntegrity, "restore source chunk changed")
				}
				var ack bool
				if err := s.call(ctx, "restore_chunk", restoreChunk{ID: id, ObjectID: ref.ID, Offset: offset, Data: chunk.Data}, &ack); err != nil {
					return id, report, err
				}
				offset += int64(len(chunk.Data))
			}
		}
	}
	resultErr = s.call(ctx, "restore_stage", restoreSelect{ID: id, Caller: q.Caller}, &report)
	return id, report, resultErr
}

func (s *Service) PublishRestore(ctx context.Context, scope api.Scope, id api.ID) error {
	var ack bool
	return s.call(ctx, "restore_publish", restoreSelect{ID: id, Caller: restoreRootQuery{Actor: scope.Actor, LaunchID: scope.LaunchID}}, &ack)
}
func (s *Service) AbortRestore(ctx context.Context, scope api.Scope, id api.ID) error {
	var ack bool
	return s.call(ctx, "restore_abort", restoreSelect{ID: id, Caller: restoreRootQuery{Actor: scope.Actor, LaunchID: scope.LaunchID}}, &ack)
}

// The single writer authenticates the current public caller before invoking
// this private port. Host paths come only from the native allocation journal.
func (s *Service) RestoreRoots(ctx context.Context, scope api.Scope) ([]string, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if scope.Config != s.deps.Config || scope.Connection == nil || scope.Request.Method != "lane.restore" {
		return nil, failure(api.CodeForbidden, "restore_target_scope")
	}
	var roots []string
	err := s.call(ctx, "restore_roots", restoreRootQuery{Actor: scope.Actor, LaunchID: scope.LaunchID}, &roots)
	return roots, err
}
