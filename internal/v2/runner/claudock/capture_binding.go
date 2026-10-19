package claudock

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) primaryBinding(ctx context.Context, record api.CaptureRecord) (api.Scope, error) {
	var empty api.Scope
	if !identifier(record.BindingID) {
		return empty, failure(api.CodeIntegrity, "live runner capture lacks its registered binding")
	}
	selected, plan, err := s.retainedLaunch(ctx, record.Target)
	if err != nil {
		return empty, err
	}
	if plan.Plan == nil || plan.Phase != "opened" {
		return empty, failure(api.CodeIntegrity, "capture launch has no retained opened plan")
	}
	binding := plan.Plan.Capture
	if err := api.ValidateCaptureBinding(binding); err != nil {
		return empty, dependency(err)
	}
	if binding.ID != record.BindingID {
		return empty, failure(api.CodeIntegrity, "capture belongs to a different registered producer")
	}
	identity, err := s.deps.State.LaunchBinding(ctx, plan.Reservation.LaunchID)
	if err != nil {
		return empty, dependency(err)
	}
	if err := api.ValidateLaunchBindingPlan(identity, *plan.Plan); err != nil {
		return empty, dependency(err)
	}
	if err := s.refusalPolicy(ctx, selected.Scope, binding); err != nil {
		return empty, err
	}
	if binding.Status == "refused" {
		return empty, binding.Refusal
	}
	state, err := s.deps.State.CaptureState(ctx, selected.Scope, record.BindingID)
	if err != nil {
		return empty, dependency(err)
	}
	if !reflect.DeepEqual(state.Binding, binding) || state.Generation < binding.Generation || state.LastSeq == 0 {
		return empty, failure(api.CodeIntegrity, "capture state differs from its retained launch binding")
	}
	reconciled, err := s.deps.CaptureControl.ReconcileCapture(ctx, binding)
	if err != nil {
		return empty, dependency(err)
	}
	if !reflect.DeepEqual(reconciled, binding) {
		return empty, failure(api.CodeIntegrity, "capture producer lifetime or pipes changed")
	}
	streamID := api.ID("")
	registered := map[api.ID]bool{}
	for _, stream := range binding.Streams {
		registered[stream.ID] = true
		if stream.Stream == record.Stream || stream.Stream == "vendor" && record.Stream == "structured" {
			streamID = stream.ID
		}
	}
	if streamID == "" || record.Offset < 0 || record.Data.Bytes > api.MaxChunkBytes || record.Offset > 1<<53-1-record.Data.Bytes || len(state.Positions) != len(binding.Streams) {
		return empty, failure(api.CodeIntegrity, "capture stream or range is not registered primary evidence")
	}
	covered := false
	seen := map[api.ID]bool{}
	for _, position := range state.Positions {
		if !registered[position.StreamID] || seen[position.StreamID] || position.NextOffset < 0 || position.NextOffset > 1<<53-1 {
			return empty, failure(api.CodeIntegrity, "capture acknowledgement positions are invalid")
		}
		seen[position.StreamID] = true
		covered = covered || position.StreamID == streamID && position.NextOffset >= record.Offset+record.Data.Bytes
	}
	if !covered {
		return empty, failure(api.CodeIntegrity, "capture range has not been durably acknowledged")
	}
	if _, err := s.objectBytes(ctx, selected.Scope, record.Data, "capture", binding.OperationID, record.Target.LifeID); err != nil {
		return empty, err
	}
	return selected.Scope, nil
}

// Refusal metadata and the plan's snapshot are comparison claims. Only the
// protected current policy can enable this default-false D6 exception. Its
// publisher/store must verify the actual consumed approval and revocation.
// Registered capture needs no exception; extraction still validates its full
// plan/binding. This adapter never turns an allowed refusal into capture.
func (s *Service) refusalPolicy(ctx context.Context, scope api.Scope, binding api.CaptureBinding) error {
	if binding.Status != "refused" {
		return nil
	}
	policy, err := s.deps.State.Policy(ctx, scope)
	if err != nil {
		return dependency(err)
	}
	return dependency(api.ValidateCapturePolicy(binding, policy))
}

func (s *Service) outsideUsage(ctx context.Context, request api.RunnerRequest, profile api.ProfileGrant, exit api.ProcessObservation) (api.BlobRef, error) {
	var empty api.BlobRef
	if s.deps.UsageWindows == nil {
		return empty, api.NotImplemented("lb-v2-secrets", "secrets.ReadUsageWindow")
	}
	if s.deps.UsageWorker == nil || s.deps.UsageProfile == nil {
		return empty, api.NotImplemented("lb-v2-claudock", "protected outside usage bindings")
	}
	selected, retained, err := s.retainedLaunch(ctx, request.Target)
	if err != nil {
		return empty, err
	}
	if retained.Plan == nil || retained.Phase != "opened" {
		return empty, failure(api.CodeIntegrity, "usage requires the causing opened launch")
	}
	cause := retained.Reservation
	query := api.UsageWindowRequest{Target: request.Target, LaunchID: cause.LaunchID, OperationID: cause.OperationID,
		ProfileGrantID: profile.ID, ProfileID: profile.ProfileID, Provider: profile.Provider, RunEndedAt: exit.ObservedAt,
		AdapterVersion: AdapterVersion, Executable: s.deps.Executable, RuntimeManifest: retained.Inputs.Sources.Runtime.Manifest}
	evidence, err := s.deps.UsageWindows.ReadUsageWindow(ctx, selected.Scope, query)
	if err != nil {
		return empty, dependency(err)
	}
	endpoint, peer, err := s.deps.UsageWorker(ctx, selected.Scope, evidence.WorkerLeaseID)
	if err != nil {
		return empty, dependency(err)
	}
	producer, err := s.deps.State.WorkerBinding(ctx, endpoint, peer)
	if err != nil {
		return empty, dependency(err)
	}
	if endpoint.Config != s.deps.Config || endpoint.WorkerLeaseID != evidence.WorkerLeaseID {
		return empty, failure(api.CodeIntegrity, "usage lookup returned a foreign installed worker")
	}
	if err := api.ValidateWorkerPrincipal(producer, endpoint, peer, api.WorkerResultAppend, s.deps.Clock.Now()); err != nil {
		return empty, dependency(err)
	}
	if err := api.ValidateUsageWindow(evidence, query, producer, s.deps.Clock.Now()); err != nil {
		return empty, dependency(err)
	}
	reset, valid := timestamp(evidence.ResetsAt)
	if !valid || !reset.After(s.deps.Clock.Now()) {
		return empty, failure(api.CodeIntegrity, "usage window reset is no longer in the future")
	}
	raw, err := s.usageObject(ctx, selected.Scope, evidence.Raw, "usage_raw", cause, producer)
	if err != nil {
		return empty, err
	}
	vendorProfile, err := s.deps.UsageProfile(ctx, profile)
	if err != nil {
		return empty, dependency(err)
	}
	if err := api.ValidateUsageSource(evidence, raw, vendorProfile); err != nil {
		return empty, dependency(err)
	}
	// The normalized ID selects its committed private usage_window object.
	// Read back its actual reference and bytes; returning an unretained DTO is
	// insufficient, even if all of its comparison fields happen to agree.
	metadata, err := s.deps.State.ObjectMetadata(ctx, selected.Scope, evidence.ID)
	if err != nil {
		return empty, dependency(err)
	}
	if metadata.Ref.ID != evidence.ID {
		return empty, failure(api.CodeIntegrity, "usage envelope object selector changed")
	}
	data, err := s.usageObject(ctx, selected.Scope, metadata.Ref, "usage_window", cause, producer)
	if err != nil {
		return empty, err
	}
	var committed api.UsageWindowEvidence
	if err := api.DecodeObject(data, &committed); err != nil || !reflect.DeepEqual(committed, evidence) {
		return empty, failure(api.CodeIntegrity, "usage envelope differs from its committed bytes")
	}
	return metadata.Ref, nil
}

func (s *Service) usageObject(ctx context.Context, scope api.Scope, ref api.BlobRef, class string, cause api.LaunchReservation, producer api.WorkerPrincipal) ([]byte, error) {
	if ref.Bytes > api.MaxFrameBytes {
		return nil, failure(api.CodeIntegrity, "usage object exceeds the bounded result size")
	}
	metadata, err := s.deps.State.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, dependency(err)
	}
	if metadata.ACL.Audience != "service" || metadata.ACL.Generation == 0 || metadata.ACL.Owner != producer.Record.Actor || producer.Record.Actor.Kind != "worker" || len(metadata.ACL.Participants) != 0 {
		return nil, failure(api.CodeIntegrity, "usage object is not private service evidence")
	}
	return s.objectBytes(ctx, scope, ref, class, cause.OperationID, cause.Target.LifeID)
}
