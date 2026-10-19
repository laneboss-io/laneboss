// Package lstate reads service-issued reservations and exact retained
// launch inputs. A selector never supplies a path, executable or authority.
package lstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type State struct {
	Record  api.LaunchPlanRecord
	Request api.Request
	Scope   api.Scope
	store   api.StateStore
	view    api.ReadView
	bytes   int64
	reads   int
}

func Error(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Owner: "lb-v2-grants", Message: message,
		Instead: "Reload the original reservation and current protected launch records; retain the failure for reconciliation."}
}

func Load(ctx context.Context, store api.StateStore, config string, scope api.Scope, id api.ID) (_ *State, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, ContextError(err)
	}
	if !manifest.Config(config) || scope.Config != config || scope.Actor.Kind != "service" ||
		!manifest.ValidID(scope.Actor.ID) || scope.Connection != nil || scope.Frame != nil {
		return nil, Error(api.CodeForbidden, "launch resolution requires its installed service execution scope")
	}
	if !manifest.ValidID(id) {
		return nil, manifest.Invalid("launch reservation needs an opaque service-issued ID")
	}
	scope.ReadView = nil
	view, err := store.BeginRead(ctx, scope)
	if err != nil {
		return nil, err
	}
	if view == nil || reflect.ValueOf(view).Kind() == reflect.Pointer && reflect.ValueOf(view).IsNil() {
		return nil, Error(api.CodeIntegrity, "launch resolution has no pinned store view")
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, view.Close())
		}
	}()
	if snapshot := view.Snapshot(); snapshot.Config != config || !manifest.ValidID(snapshot.ID) {
		return nil, Error(api.CodeIntegrity, "launch read view belongs to another configuration")
	}
	scope.ReadView = view
	state := &State{Scope: scope, store: store, view: view}
	state.Record, err = store.LaunchPlan(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	if err := api.ValidateLaunchPlanRecord(state.Record); err != nil {
		return nil, err
	}
	r := state.Record.Reservation
	if r.ID != id || r.Config != config {
		return nil, Error(api.CodeForbidden, "launch reservation belongs to another selector or configuration")
	}
	if state.Record.Phase == "failed" {
		return nil, state.Record.Error
	}
	operation, err := store.Operation(ctx, scope, r.OperationID)
	if err != nil {
		return nil, err
	}
	if operation.ID != r.OperationID || operation.LifeID != r.Target.LifeID || operation.Run != r.Target.Run {
		return nil, Error(api.CodeIntegrity, "launch reservation has no matching durable operation")
	}
	if operation.Error != nil {
		return nil, operation.Error
	}
	if operation.Status != "pending" && operation.Status != "running" && operation.Status != "succeeded" {
		return nil, Error(api.CodeConflict, "launch operation is no longer eligible for planning")
	}
	if r.Mode == "continue" && operation.Status == "succeeded" && state.Record.Phase != "opened" {
		return nil, Error(api.CodeConflict, "unopened continuation cannot claim operation completion")
	}
	metadata, err := store.ObjectMetadata(ctx, scope, r.OriginalRequest.ID)
	if err != nil {
		return nil, err
	}
	if metadata.Ref != r.OriginalRequest || metadata.Origin != "service" || metadata.SourceOperationID != r.OperationID ||
		metadata.ACL.Config != config || metadata.ACL.Generation == 0 || metadata.ACL.Audience != "owner" ||
		len(metadata.ACL.Participants) != 0 || metadata.ACL.LifeID != "" && metadata.ACL.LifeID != r.Target.LifeID ||
		metadata.ACL.Owner != r.RequestedBy && (metadata.ACL.Owner.Kind != "service" || !manifest.ValidID(metadata.ACL.Owner.ID)) {
		return nil, Error(api.CodeIntegrity, "original launch input lacks private service operation provenance")
	}
	raw, err := state.Read(ctx, r.OriginalRequest)
	if err != nil {
		return nil, err
	}
	if r.Loop != nil {
		var cause api.LoopTurnCause
		if err := api.DecodeObject(raw, &cause); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(cause)
		if err != nil {
			return nil, err
		}
		canonical, err := api.CanonicalJSON(encoded)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(scope.Request, api.Request{}) || !reflect.DeepEqual(cause, *r.Loop) ||
			!bytes.Equal(raw, canonical) || manifest.Hash(raw) != r.RequestSHA256 {
			return nil, Error(api.CodeIntegrity, "loop input differs from its canonical private cause")
		}
		return state, nil
	}
	if err := api.DecodeObject(raw, &state.Request); err != nil {
		return nil, err
	}
	request := state.Request
	digest, err := api.RequestDigest(request)
	spec, known := api.Methods[request.Method]
	if err != nil || !known || !spec.Mutation || request.Protocol != api.Protocol || request.Schema != api.SchemaVersion ||
		request.Config != config || request.RequestID != r.RequestID || !manifest.ValidID(request.IdempotencyKey) ||
		request.RequestSHA256 != r.RequestSHA256 || digest != r.RequestSHA256 ||
		request.Proof != nil && request.Proof.RequestSHA256 != digest {
		return nil, Error(api.CodeIntegrity, "original launch frame differs from its reserved request digest")
	}
	if scope.Request.Method != "" {
		other, err := api.RequestDigest(scope.Request)
		if err != nil || other != digest || scope.Request.RequestID != request.RequestID ||
			scope.Request.IdempotencyKey != request.IdempotencyKey || scope.Request.Config != config {
			return nil, Error(api.CodeForbidden, "launch caller supplied a different operation input")
		}
	}
	if r.Mode != "continue" {
		if r.RequestedBy.Kind == "lane" && request.Proof != nil ||
			r.Authority.Kind == "ticket" && request.Proof != nil ||
			r.Authority.Kind == "proof" && (request.Proof == nil || request.Proof.ID != r.Authority.ID) {
			return nil, Error(api.CodeForbidden, "original launch frame differs from its consumed reservation authority")
		}
	}
	return state, nil
}

func (s *State) Close() error { return s.view.Close() }

// Read has a fixed service ceiling independent of any requested DiskBytes.
// Metadata and every bounded range are read through the same pinned scope.
func (s *State) Read(ctx context.Context, ref api.BlobRef) ([]byte, error) {
	if err := manifest.Blob(ref); err != nil {
		return nil, err
	}
	if s.reads >= 4096 || ref.Bytes > api.MaxObjectBytes-s.bytes {
		return nil, Error(api.CodeBudget, "launch input verification exceeds its fixed service read bound")
	}
	s.reads++
	metadata, err := s.store.ObjectMetadata(ctx, s.Scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if metadata.Ref != ref || metadata.ACL.Config != s.Scope.Config {
		return nil, Error(api.CodeIntegrity, "launch object metadata differs from its committed reference")
	}
	data := make([]byte, 0, min(ref.Bytes, api.MaxChunkBytes))
	for {
		if err := ctx.Err(); err != nil {
			return nil, ContextError(err)
		}
		limit := int(min(int64(api.MaxChunkBytes), ref.Bytes-int64(len(data))))
		if limit == 0 {
			limit = 1 // Check actual EOF even for an empty object.
		}
		chunk, err := s.store.Blob(ctx, s.Scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: limit})
		if err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(data)) || len(chunk.Data) > limit ||
			manifest.Hash(chunk.Data) != chunk.SHA256 || int64(len(data)+len(chunk.Data)) > ref.Bytes {
			return nil, Error(api.CodeIntegrity, "launch object chunk identity, length or digest changed")
		}
		if len(chunk.Data) == 0 {
			break
		}
		s.bytes += int64(len(chunk.Data))
		data = append(data, chunk.Data...)
	}
	if int64(len(data)) != ref.Bytes || manifest.Hash(data) != ref.SHA256 {
		return nil, Error(api.CodeIntegrity, "launch object bytes differ from the retained reference")
	}
	return data, nil
}

func ContextError(err error) *api.Error {
	code := api.CodeCancelled
	if errors.Is(err, context.DeadlineExceeded) {
		code = api.CodeDeadline
	}
	return Error(code, "launch operation context ended")
}
