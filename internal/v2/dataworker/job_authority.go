package dataworker

import (
	"context"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// These reads are preflight only. They neither claim a job nor authorize a
// gate, credential injection or network action. Those require the fixed-worker
// execution/result handoff described in grants/CONTRACT-GAPS.md.
func (s *Service) jobScope(ctx context.Context, scope api.Scope) (api.Scope, api.ReadView, error) {
	if err := checkContext(ctx); err != nil {
		return api.Scope{}, nil, err
	}
	if !manifest.Config(s.deps.Config) {
		return api.Scope{}, nil, lstate.Error(api.CodePrerequisite, "fixed worker has no installed configuration binding")
	}
	if scope.Config != s.deps.Config || scope.Actor.Kind != "service" || !manifest.ValidID(scope.Actor.ID) ||
		scope.Connection != nil || scope.Frame != nil || scope.Request.Method != "" {
		return api.Scope{}, nil, lstate.Error(api.CodeForbidden, "fixed worker requires its installed service execution scope")
	}
	scope.ReadView = nil
	view, err := s.deps.Store.BeginRead(ctx, scope)
	if err != nil {
		return api.Scope{}, nil, err
	}
	if missing(view) {
		return api.Scope{}, nil, lstate.Error(api.CodeIntegrity, "fixed worker has no pinned read view")
	}
	if snapshot := view.Snapshot(); snapshot.Config != scope.Config || !manifest.ValidID(snapshot.ID) {
		return api.Scope{}, nil, errors.Join(lstate.Error(api.CodeIntegrity, "fixed worker read view belongs to another configuration"), view.Close())
	}
	scope.ReadView = view
	return scope, view, nil
}

func (s *Service) currentJob(ctx context.Context, scope api.Scope, submitted api.WorkerLease, consumer api.ID) (api.EffectRecord, error) {
	var zero api.EffectRecord
	if !manifest.ValidID(submitted.ID) || !manifest.ValidID(submitted.OperationID) || !manifest.ValidID(submitted.EffectID) ||
		!manifest.ValidID(submitted.GrantSetID) || !manifest.ValidID(submitted.Target.LifeID) || submitted.Target.Run == 0 ||
		submitted.Generation == 0 || uint64(submitted.Generation) > manifest.MaxInteger {
		return zero, manifest.Invalid("fixed worker requires an exact retained job lease")
	}
	if err := manifest.Blob(submitted.Input); err != nil {
		return zero, err
	}
	if err := manifest.Blob(submitted.RuntimeManifest); err != nil {
		return zero, err
	}
	if submitted.RuntimeManifest.Class != "manifest" {
		return zero, manifest.Invalid("fixed worker runtime must be an installed manifest")
	}
	lease, err := s.deps.Store.WorkerLease(ctx, scope, submitted.ID)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(lease, submitted) || lease.ConsumedBy != consumer {
		return zero, lstate.Error(api.CodeForbidden, "fixed worker lease changed or belongs to another consumer")
	}
	if _, err := manifest.Expiry(lease.ExpiresAt, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	effect, err := s.deps.Store.Effect(ctx, scope, lease.EffectID)
	if err != nil {
		return zero, err
	}
	if effect.Effect.ID != lease.EffectID || effect.Effect.OperationID != lease.OperationID ||
		!manifest.ValidID(effect.ClaimID) || effect.ClaimantID != scope.Actor.ID ||
		effect.State != "claimed" && effect.State != "running" || effect.Generation == 0 {
		return zero, lstate.Error(api.CodeConflict, "fixed worker has no current effect claim for this executor")
	}
	if _, err := manifest.Expiry(effect.ClaimExpiresAt, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	return effect, nil
}

func (s *Service) jobObject(ctx context.Context, scope api.Scope, lease api.WorkerLease, ref api.BlobRef) ([]byte, error) {
	if err := manifest.Blob(ref); err != nil {
		return nil, err
	}
	if ref.Bytes == 0 || ref.Bytes > api.MaxFrameBytes {
		return nil, manifest.Invalid("fixed worker input exceeds its bounded sealed object size")
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if metadata.Ref != ref || metadata.Origin != "service" || metadata.SourceOperationID != lease.OperationID ||
		metadata.ACL.Config != scope.Config || metadata.ACL.Audience != "private" || metadata.ACL.Generation == 0 ||
		len(metadata.ACL.Participants) != 0 || metadata.ACL.LifeID != "" && metadata.ACL.LifeID != lease.Target.LifeID ||
		metadata.ACL.Owner.Kind != "service" || !manifest.ValidID(metadata.ACL.Owner.ID) {
		return nil, lstate.Error(api.CodeIntegrity, "fixed worker input lacks private service operation provenance")
	}
	data := make([]byte, 0, ref.Bytes)
	for {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		limit := int(min(int64(api.MaxChunkBytes), ref.Bytes-int64(len(data))))
		if limit == 0 {
			limit = 1
		}
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: limit})
		if err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) > limit ||
			manifest.Hash(chunk.Data) != chunk.SHA256 || int64(len(data)+len(chunk.Data)) > ref.Bytes {
			return nil, lstate.Error(api.CodeIntegrity, "fixed worker input chunk differs from its sealed object")
		}
		if len(chunk.Data) == 0 {
			break
		}
		data = append(data, chunk.Data...)
	}
	if int64(len(data)) != ref.Bytes || manifest.Hash(data) != ref.SHA256 {
		return nil, lstate.Error(api.CodeIntegrity, "fixed worker input bytes differ from their retained reference")
	}
	return data, nil
}
