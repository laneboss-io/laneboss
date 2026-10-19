package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
)

type verifiedObject struct {
	metadata api.ObjectMetadata
	data     []byte
}

// One full maximum-size object may be streamed without re-verification. A
// request that visits many objects keeps only a bounded working set.
const objectCacheBytes = int64(api.MaxObjectBytes)
const objectCacheEntries = 16

// This key is private and used only by counting tests. It observes actual full
// persisted-byte loads immediately before their digest verification.
type objectVerificationKey struct{}

type objectReadBinding struct {
	Config           string
	Actor            api.Actor
	LaunchID         api.ID
	Endpoint, Policy api.Generation
	Connection       api.ID
	RequestID, Key   api.ID
	Digest           api.Digest
}

func bindObjectRead(scope api.Scope) objectReadBinding {
	b := objectReadBinding{Config: scope.Config, Actor: scope.Actor, LaunchID: scope.LaunchID,
		Endpoint: scope.EndpointGeneration, Policy: scope.PolicyGeneration,
		RequestID: scope.Request.RequestID, Key: scope.Request.IdempotencyKey, Digest: scope.Request.RequestSHA256}
	if scope.Connection != nil {
		b.Connection = scope.Connection.ID()
	}
	return b
}

// BeginObjectRead reuses the existing protected snapshot mechanism. Callers
// close it at the end of their complete read; it confers no new authority.
func (s *Service) BeginObjectRead(ctx context.Context, scope api.Scope) (api.ReadView, error) {
	return s.BeginRead(ctx, scope)
}

// Caller holds the store read lock and has rechecked live read authority and
// selected the actual database through reader. Only a store-owned request view
// retains bytes; unbound reads always perform the ordinary full verification.
func (s *Service) readObjectRow(ctx context.Context, scope api.Scope, db queryer, id api.ID) (api.ObjectMetadata, []byte, error) {
	if err := ctx.Err(); err != nil {
		return api.ObjectMetadata{}, nil, err
	}
	if scope.ReadView == nil {
		return objectRow(ctx, db, id)
	}
	view, ok := scope.ReadView.(*readView)
	if !ok || view.store != s || view.closed.Load() || view.objectBinding != bindObjectRead(scope) {
		return api.ObjectMetadata{}, nil, api.WithErrorComponent(fault(api.CodeUnauthenticated, "object read view belongs to another request or caller"), "store_object_view")
	}
	view.objectMu.Lock()
	defer view.objectMu.Unlock()
	if err := view.objectContext.Err(); err != nil {
		return api.ObjectMetadata{}, nil, err
	}
	retained, ok := view.objects[id]
	if !ok {
		// Authorize metadata before loading or retaining the full payload.
		var encoded []byte
		if err := db.QueryRowContext(ctx, "SELECT metadata FROM objects WHERE id=?", string(id)).Scan(&encoded); err != nil {
			if cause := ctx.Err(); cause != nil {
				return api.ObjectMetadata{}, nil, cause
			}
			if errors.Is(err, sql.ErrNoRows) {
				return api.ObjectMetadata{}, nil, missingObject()
			}
			return api.ObjectMetadata{}, nil, err
		}
		var visible api.ObjectMetadata
		if err := decodeStored(encoded, &visible); err != nil {
			return api.ObjectMetadata{}, nil, err
		}
		allowed, err := s.visibleObject(ctx, db, scope, visible)
		if err != nil {
			return api.ObjectMetadata{}, nil, err
		}
		if !allowed {
			return api.ObjectMetadata{}, nil, missingObject()
		}
		metadata, data, err := objectRow(ctx, db, id)
		if err != nil {
			return metadata, nil, err
		}
		allowed, err = s.visibleObject(ctx, db, scope, metadata)
		if err != nil {
			return api.ObjectMetadata{}, nil, err
		}
		if !allowed {
			return api.ObjectMetadata{}, nil, missingObject()
		}
		retained = verifiedObject{metadata: metadata, data: data}
		if int64(len(data)) > objectCacheBytes {
			return metadata, data, nil
		}
		if len(view.objects) >= objectCacheEntries || view.objectBytes+int64(len(data)) > objectCacheBytes {
			view.objects = nil
			view.objectBytes = 0
		}
		if view.objects == nil {
			view.objects = make(map[api.ID]verifiedObject)
		}
		view.objects[id] = retained
		view.objectBytes += int64(len(data))
	}
	// Do not expose the retained ACL's mutable slice to a metadata caller.
	metadata := retained.metadata
	metadata.ACL.Participants = slices.Clone(metadata.ACL.Participants)
	return metadata, retained.data, nil
}

func (v *readView) clearObjects() {
	v.objectMu.Lock()
	defer v.objectMu.Unlock()
	v.objects = nil
	v.objectBytes = 0
}
