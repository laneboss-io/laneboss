package service

import (
	"context"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// reviewCaller retains the original native frame and public principal. The
// returned service scope belongs to this installed coordinator, not a copy of
// the requester's labels with Kind changed to service.
func (s *Server) reviewCaller(ctx context.Context, caller api.Scope, target api.LifeRef) (api.Scope, error) {
	if err := ctx.Err(); err != nil {
		return api.Scope{}, contextError(err)
	}
	control, err := s.controlScope()
	if err != nil {
		return api.Scope{}, err
	}
	if caller.Config != s.options.Config || caller.Request.Config != caller.Config ||
		caller.Request.Method != "lane.review" && caller.Request.Method != "lane.mark" ||
		caller.Actor.Kind != "human" && caller.Actor.Kind != "lane" || caller.Connection == nil ||
		caller.Frame == nil || caller.Connection.Peer() == nil || !wire.ValidID(string(target.LifeID)) || target.Run == 0 {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "review requires its actual authenticated dispatcher frame")
	}
	if err := caller.Frame.Verify(ctx, caller.Connection); err != nil {
		return api.Scope{}, err
	}
	var original api.Request
	if api.DecodeObject(caller.Frame.Bytes(), &original) != nil || !reflect.DeepEqual(original, caller.Request) {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "review request differs from its original native frame")
	}
	var selected struct {
		Target api.LifeRef `json:"target"`
	}
	// The full request was decoded by the dispatcher. Only select its target
	// here; unknown fields belong to ReviewRequest or MarkRequest respectively.
	if err := decodeReviewTarget(caller.Request, &selected.Target); err != nil || selected.Target != target {
		return api.Scope{}, serviceError(api.CodeForbidden, "review target differs from its authenticated request")
	}
	current, err := s.authenticateConnection(ctx, caller.Connection)
	if err != nil {
		return api.Scope{}, err
	}
	if current.Actor != caller.Actor || current.Config != caller.Config || current.LaunchID != caller.LaunchID ||
		current.EndpointGeneration != caller.EndpointGeneration || current.PolicyGeneration != caller.PolicyGeneration {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "review caller changed since its original dispatch")
	}
	if caller.Actor.Kind == "lane" && caller.Actor.LifeID == target.LifeID {
		return api.Scope{}, serviceError(api.CodeForbidden, "an executor cannot prepare or verify its own review")
	}
	if err := s.deps.Authenticator.Authorize(ctx, caller, caller.Request); err != nil {
		return api.Scope{}, err
	}
	return control, nil
}

func decodeReviewTarget(request api.Request, target *api.LifeRef) error {
	if request.Method == "lane.review" {
		var value api.ReviewRequest
		if err := api.DecodeObject(request.Params, &value); err != nil {
			return err
		}
		*target = value.Target
		return nil
	}
	var value api.MarkRequest
	if err := api.DecodeObject(request.Params, &value); err != nil {
		return err
	}
	*target = value.Target
	return nil
}

func (s *Server) ResolveReview(ctx context.Context, caller api.Scope, target api.LifeRef) (result api.ReviewSubject, required []string, resultErr error) {
	defer func() {
		if resultErr != nil {
			result, required = api.ReviewSubject{}, nil
		}
	}()
	control, err := s.reviewCaller(ctx, caller, target)
	if err != nil {
		return result, nil, err
	}
	source, ok := s.deps.Store.(reviewjob.Source)
	if !ok {
		return result, nil, serviceError(api.CodePrerequisite, "review requires the single writer's retained native freeze and worker journal")
	}
	s.mu.RLock()
	policy, ok := s.runtime.Helper.(reviewjob.Requirements)
	s.mu.RUnlock()
	if !ok {
		return result, nil, serviceError(api.CodePrerequisite, "review requires current protected project check requirements")
	}
	subject, err := source.ReviewSnapshot(ctx, caller, target)
	if err != nil {
		return result, nil, err
	}
	view, err := s.deps.Store.BeginRead(ctx, control)
	if err != nil {
		return result, nil, err
	}
	if view == nil {
		return result, nil, serviceError(api.CodeIntegrity, "review has no pinned state snapshot")
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	read := control
	read.ReadView = view
	snapshot := view.Snapshot()
	if snapshot.Config != caller.Config || !wire.ValidID(string(snapshot.ID)) {
		return result, nil, serviceError(api.CodeIntegrity, "review read view changed configuration")
	}
	lane, err := s.deps.Store.Lane(ctx, read, target)
	if err != nil {
		return result, nil, err
	}
	if lane.LifeID != target.LifeID || lane.Run != target.Run || lane.Cleaned || lane.State != "verifying" && lane.State != "accepted" {
		return result, nil, serviceError(api.CodeConflict, "review requires the current ended uncleaned run")
	}
	if subject.Target != target || subject.LaunchID != lane.LaunchID || subject.SessionID != lane.Session.ID ||
		subject.Generation == 0 || subject.Generation != lane.Generation && !(lane.State == "accepted" && subject.Generation+1 == lane.Generation) ||
		subject.EndSeq == 0 || subject.InventorySeq < subject.EndSeq || subject.InventorySeq > snapshot.LastSeq ||
		!wire.ValidID(string(subject.EndEventID)) || !wire.ValidID(string(subject.CaptureBindingID)) || subject.RefusalIDs == nil {
		return result, nil, serviceError(api.CodeIntegrity, "review freeze differs from the current ended run")
	}
	var end api.Event
	cursor, cursors := "", make(map[string]bool)
	for {
		page, err := s.deps.Store.Events(ctx, read, api.EventTailRequest{LifeID: target.LifeID, Run: target.Run, Cursor: cursor})
		if err != nil {
			return result, nil, err
		}
		for _, event := range page.Events {
			if event.Config != caller.Config || event.LifeID != target.LifeID || event.Run != target.Run || event.Seq > snapshot.LastSeq {
				return result, nil, serviceError(api.CodeIntegrity, "review event page escaped its pinned run")
			}
			if event.Kind == "lane.ended" && event.Origin == "service" && event.Seq > end.Seq {
				end = event
			}
		}
		if page.Complete {
			break
		}
		if page.Cursor == "" || cursors[page.Cursor] || len(cursors) >= 4096 {
			return result, nil, serviceError(api.CodeIntegrity, "review event cursor did not advance within its bound")
		}
		cursors[page.Cursor], cursor = true, page.Cursor
	}
	var ended api.RunEndEvent
	if end.ID != subject.EndEventID || end.Seq != subject.EndSeq || api.DecodeObject(end.Payload, &ended) != nil ||
		ended.Reason == "service_lost" || ended.Observation.Handle.ID != lane.LaunchID || ended.Observation.Handle.Target != target ||
		ended.Observation.State != "exited" || ended.Observation.Survivors == nil || *ended.Observation.Survivors != 0 ||
		(ended.Observation.ExitCode == nil) == (ended.Observation.Signal == nil) {
		return result, nil, serviceError(api.CodeContainmentUnknown, "review lacks the exact committed known-zero run end")
	}
	capture, err := s.deps.Store.CaptureState(ctx, read, subject.CaptureBindingID)
	if err != nil {
		return result, nil, err
	}
	if capture.Binding.ID != subject.CaptureBindingID || capture.Binding.Config != caller.Config || capture.Binding.Target != target ||
		capture.Binding.LaunchID != lane.LaunchID || capture.Binding.Status != "registered" ||
		!reflect.DeepEqual(capture.Binding.Streams, subject.Streams) || capture.Generation == 0 || capture.LastSeq > subject.InventorySeq ||
		len(subject.Streams) == 0 || len(capture.Positions) != len(subject.Streams) {
		return result, nil, serviceError(api.CodeIntegrity, "review freeze differs from its drained primary capture")
	}
	for _, stream := range subject.Streams {
		matches := 0
		for _, position := range capture.Positions {
			if position.StreamID == stream.ID && position.EOF && position.NextOffset >= 0 {
				matches++
			}
		}
		if matches != 1 {
			return result, nil, serviceError(api.CodeIntegrity, "review capture is missing a unique committed EOF")
		}
	}
	meta, err := s.deps.Store.ObjectMetadata(ctx, control, subject.Snapshot.ID)
	if err != nil {
		return result, nil, err
	}
	if meta.Ref != subject.Snapshot || meta.Ref.Class != "manifest" || meta.ACL.Config != caller.Config || meta.ACL.LifeID != target.LifeID ||
		meta.Origin != "service" && meta.Origin != "worker" || !wire.ValidID(string(meta.SourceOperationID)) {
		return result, nil, serviceError(api.CodeIntegrity, "review snapshot lacks authenticated post-run provenance")
	}
	if _, err := s.reviewObject(ctx, control, subject.Snapshot); err != nil {
		return result, nil, err
	}
	required, err = policy.RequiredReviewChecks(ctx, control, target)
	if err != nil {
		return result, nil, err
	}
	if len(required) == 0 || len(required) > 200 {
		return result, nil, serviceError(api.CodePrerequisite, "protected review requirements are absent or exceed their bound")
	}
	seen := make(map[string]bool)
	for _, name := range required {
		if !wire.ValidID(name) || seen[name] {
			return result, nil, serviceError(api.CodeIntegrity, "protected review requirements contain invalid or repeated names")
		}
		seen[name] = true
	}
	return subject, append([]string{}, required...), nil
}

func (s *Server) pendingReview(ctx context.Context, caller api.Scope, request api.ReviewRequest) (api.MutationReceipt, api.Scope, error) {
	control, err := s.reviewCaller(ctx, caller, request.Target)
	if err != nil {
		return api.MutationReceipt{}, control, err
	}
	var original api.ReviewRequest
	if caller.Request.Method != "lane.review" || api.DecodeObject(caller.Request.Params, &original) != nil || !reflect.DeepEqual(original, request) {
		return api.MutationReceipt{}, control, serviceError(api.CodeForbidden, "review preparation changed the original public request")
	}
	key := api.RequestKey{Method: caller.Request.Method, IdempotencyKey: caller.Request.IdempotencyKey, RequestSHA256: caller.Request.RequestSHA256}
	retained, err := s.deps.Store.LookupReceipt(ctx, caller, key)
	if err != nil {
		return retained, control, err
	}
	owner, ok := s.deps.Store.(interface {
		OwnsMutation(context.Context, api.Scope, api.RequestKey, api.ID) (bool, error)
	})
	if !ok {
		return retained, control, serviceError(api.CodePrerequisite, "review requires actual dispatcher reservation ownership")
	}
	owned, err := owner.OwnsMutation(ctx, caller, key, retained.Operation.ID)
	if err != nil {
		return retained, control, err
	}
	if !owned || retained.Reply != nil || retained.Key != key || retained.Operation.Status != "pending" || !wire.ValidID(string(retained.Operation.ID)) {
		return retained, control, serviceError(api.CodeConflict, "review no longer owns its original pending dispatcher operation")
	}
	return retained, control, nil
}

func (s *Server) PrepareReview(ctx context.Context, caller api.Scope, request api.ReviewRequest, generation api.Generation, endID api.ID, endSeq api.Sequence) (api.ReviewVerifyRequest, error) {
	var zero api.ReviewVerifyRequest
	retained, control, err := s.pendingReview(ctx, caller, request)
	if err != nil {
		return zero, err
	}
	subject, required, err := s.ResolveReview(ctx, caller, request.Target)
	if err != nil {
		return zero, err
	}
	if subject.Generation != generation || subject.EndEventID != endID || subject.EndSeq != endSeq {
		return zero, serviceError(api.CodeConflict, "review preparation changed the selected generation or end")
	}
	source := s.deps.Store.(reviewjob.Source) // ResolveReview validated this installed capability.
	lease, err := source.ReserveReviewWorker(ctx, caller, request, subject, required)
	if err != nil {
		return zero, err
	}
	actual, err := s.deps.Store.WorkerLease(ctx, control, lease.ID)
	if err != nil {
		return zero, err
	}
	expected := lease
	expected.ConsumedBy, expected.Generation = actual.ConsumedBy, actual.Generation
	validAdvance := actual.Generation == lease.Generation && actual.ConsumedBy == "" || actual.ConsumedBy != "" && (actual.Generation == lease.Generation+1 || actual.Generation == lease.Generation+2)
	if !reflect.DeepEqual(expected, actual) || !validAdvance || lease.OperationID != retained.Operation.ID || lease.Target != subject.Target || lease.Kind != "export" ||
		!wire.ValidID(string(lease.EffectID)) || !wire.ValidID(string(lease.ID)) || lease.Input.Class != "manifest" || lease.RuntimeManifest.Class != "manifest" {
		return zero, serviceError(api.CodeIntegrity, "review preparation lost its original retained fixed-worker lease")
	}
	runtimeMeta, err := s.deps.Store.ObjectMetadata(ctx, control, lease.RuntimeManifest.ID)
	if err != nil {
		return zero, err
	}
	if runtimeMeta.Ref != lease.RuntimeManifest || runtimeMeta.Origin != "service" || runtimeMeta.ACL.Config != caller.Config {
		return zero, serviceError(api.CodeIntegrity, "review worker runtime differs from its protected published object")
	}
	runtimeRaw, err := s.reviewObject(ctx, control, lease.RuntimeManifest)
	if err != nil {
		return zero, err
	}
	var runtime api.RuntimeManifest
	if api.DecodeObject(runtimeRaw, &runtime) != nil || runtime.Schema != "laneboss.runtime.v2" || runtime.Generation == 0 ||
		runtime.Artifact.SHA256 != s.deps.Binding.ArtifactSHA256 || !wire.ValidID(string(runtime.Bootstrap.ID)) ||
		!wire.ValidDigest(string(runtime.Bootstrap.SHA256)) || runtime.Bootstrap.Version == "" {
		return zero, serviceError(api.CodeIntegrity, "review worker runtime is not the installed artifact and enrolled bootstrap")
	}
	raw, err := s.reviewObject(ctx, control, lease.Input)
	if err != nil {
		return zero, err
	}
	var input reviewjob.Input
	if api.DecodeObject(raw, &input) != nil || input.Schema != "laneboss.review-input.v2" || !reflect.DeepEqual(input.Subject, subject) ||
		!reflect.DeepEqual(input.Request, request) || !reflect.DeepEqual(input.Required, required) {
		return zero, serviceError(api.CodeIntegrity, "review sealed input differs from its protected frozen context")
	}
	meta, err := s.deps.Store.ObjectMetadata(ctx, control, lease.Input.ID)
	if err != nil {
		return zero, err
	}
	if meta.SourceOperationID != retained.Operation.ID || meta.Origin != "service" || meta.ACL.Config != caller.Config ||
		meta.ACL.Owner.Kind != "service" || meta.ACL.LifeID != subject.Target.LifeID {
		return zero, serviceError(api.CodeIntegrity, "review input is not the original private service operation's object")
	}
	return api.ReviewVerifyRequest{Lease: lease, Request: request, ExpectedGeneration: generation, EndEventID: endID, EndSeq: endSeq}, nil
}

func (s *Server) WithReviewResult(ctx context.Context, caller api.Scope, prepared api.ReviewVerifyRequest, consume func(api.Scope, api.BlobRef) error) error {
	if consume == nil {
		return serviceError(api.CodeInvalid, "review result consumer is absent")
	}
	retained, _, err := s.pendingReview(ctx, caller, prepared.Request)
	if err != nil {
		return err
	}
	if prepared.Lease.OperationID != retained.Operation.ID || prepared.Lease.Target != prepared.Request.Target {
		return serviceError(api.CodeForbidden, "review result selects a foreign worker operation")
	}
	source, ok := s.deps.Store.(reviewjob.Source)
	if !ok {
		return serviceError(api.CodePrerequisite, "review worker journal is absent")
	}
	ref, err := source.AwaitReviewResult(ctx, caller, prepared.Lease)
	if err != nil {
		return err
	}
	_, control, err := s.pendingReview(ctx, caller, prepared.Request)
	if err != nil {
		return err
	}
	return consume(control, ref)
}

func (s *Server) reviewObject(ctx context.Context, scope api.Scope, ref api.BlobRef) ([]byte, error) {
	if !wire.ValidID(string(ref.ID)) || !wire.ValidDigest(string(ref.SHA256)) || ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes {
		return nil, serviceError(api.CodeInvalid, "review object exceeds its bounded reference")
	}
	raw := make([]byte, 0, ref.Bytes)
	for {
		limit := int(min(int64(api.MaxChunkBytes), ref.Bytes-int64(len(raw))))
		if limit == 0 {
			limit = 1
		}
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(raw)), Limit: limit})
		if err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(raw)) || len(chunk.Data) > limit ||
			digestBytes(chunk.Data) != chunk.SHA256 || int64(len(raw)+len(chunk.Data)) > ref.Bytes {
			return nil, serviceError(api.CodeIntegrity, "review object changed its retained range")
		}
		if len(chunk.Data) == 0 {
			break
		}
		raw = append(raw, chunk.Data...)
	}
	if int64(len(raw)) != ref.Bytes || digestBytes(raw) != ref.SHA256 {
		return nil, serviceError(api.CodeIntegrity, "review object bytes changed")
	}
	return raw, nil
}

var _ reviewjob.ResultControl = (*Server)(nil)
