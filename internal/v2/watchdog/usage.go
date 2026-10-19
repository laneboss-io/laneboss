package watchdog

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// These facts come from the installed worker registry and protected profile/
// runtime enrollment, never from usage TSV or caller-supplied producer labels.
// The owner must authorize the actual job/result read before returning them.
type UsageProvenance = api.UsageProvenance

func sameLimitCause(left, right api.LimitSignal) bool {
	// Outside usage may be remeasured after a pending receipt expires. This
	// changes only its separately validated immutable evidence reference.
	left.UsageEvidence, right.UsageEvidence = nil, nil
	return reflect.DeepEqual(left, right)
}

// The full envelope/source/producer was validated before this intent committed.
// Reread its immutable bytes and age before pending dispatch; only reassessment
// can obtain a new outside measurement. This method never changes the envelope.
func (s *Service) pendingUsageObservation(ctx context.Context, lane api.Lane, intent api.ContinuationIntent) (time.Time, error) {
	ref := intent.Swap.Limit.UsageEvidence
	if ref == nil || ref.Class != "usage_window" {
		return time.Time{}, problem(api.CodeIntegrity, "pending continuation lost its usage envelope")
	}
	data, err := s.blob(ctx, *ref, api.MaxFrameBytes)
	if err != nil {
		return time.Time{}, err
	}
	var evidence api.UsageWindowEvidence
	if err := decodePayload(data, &evidence); err != nil {
		return time.Time{}, err
	}
	if evidence.ID != ref.ID || evidence.Target != intent.Target || evidence.LaunchID != lane.LaunchID ||
		evidence.ProfileGrantID != lane.ProfileGrantID || evidence.ProfileID != intent.Swap.Limit.ProfileID ||
		evidence.Provider != intent.Swap.Limit.Provider || evidence.AdapterVersion != intent.Swap.Limit.AdapterVersion {
		return time.Time{}, problem(api.CodeIntegrity, "pending usage envelope differs from its causing life and profile")
	}
	// The envelope's operation identifies the causing launch, not the later
	// continuation journal operation. Assessment checked that original binding.
	return timestamp(evidence.ObservedAt)
}

func (s *Service) usageEvidence(ctx context.Context, signal api.LimitSignal, lane api.Lane, operation api.ID, exit api.ProcessObservation, refresh bool) (api.BlobRef, error) {
	if signal.UsageEvidence == nil {
		return api.BlobRef{}, problem(api.CodeInvalid, "outside usage-window evidence is absent")
	}
	if s.deps.ResolveUsage == nil {
		return api.BlobRef{}, api.NotImplemented("lb-v2-secrets", "watchdog outside usage producer and enrollment read")
	}
	ref := *signal.UsageEvidence
	if ref.Class != "usage_window" {
		return api.BlobRef{}, problem(api.CodeIntegrity, "usage envelope has another object class")
	}
	data, err := s.blob(ctx, ref, api.MaxFrameBytes)
	if err != nil {
		return api.BlobRef{}, err
	}
	var evidence api.UsageWindowEvidence
	if err := decodePayload(data, &evidence); err != nil {
		return api.BlobRef{}, err
	}
	provenance, err := s.deps.ResolveUsage(ctx, s.readScope(), ref)
	if err != nil {
		return api.BlobRef{}, err
	}
	if provenance.Evidence != ref || evidence.ID != ref.ID || provenance.Producer.Endpoint.Config != s.deps.Config {
		return api.BlobRef{}, problem(api.CodeIntegrity, "usage producer read differs from the retained envelope")
	}
	request := api.UsageWindowRequest{Target: signal.Target, LaunchID: lane.LaunchID, OperationID: operation,
		ProfileGrantID: lane.ProfileGrantID, ProfileID: signal.ProfileID, Provider: signal.Provider,
		RunEndedAt: exit.ObservedAt, AdapterVersion: signal.AdapterVersion,
		Executable: provenance.Executable, RuntimeManifest: provenance.RuntimeManifest}
	observed, err := timestamp(evidence.ObservedAt)
	if err != nil {
		return api.BlobRef{}, err
	}
	if refresh && s.deps.Clock.Now().Sub(observed) > 30*time.Second {
		source, ok := s.deps.Credentials.(api.UsageWindowSource)
		if !ok {
			return api.BlobRef{}, api.NotImplemented("lb-v2-secrets", "secrets.ReadUsageWindow")
		}
		fresh, err := source.ReadUsageWindow(ctx, s.readScope(), request)
		if err != nil {
			return api.BlobRef{}, err
		}
		metadata, err := s.deps.Store.ObjectMetadata(ctx, s.readScope(), fresh.ID)
		if err != nil {
			return api.BlobRef{}, err
		}
		freshBytes, err := s.blob(ctx, metadata.Ref, api.MaxFrameBytes)
		if err != nil {
			return api.BlobRef{}, err
		}
		var retained api.UsageWindowEvidence
		if err := decodePayload(freshBytes, &retained); err != nil {
			return api.BlobRef{}, err
		}
		if !reflect.DeepEqual(fresh, retained) {
			return api.BlobRef{}, problem(api.CodeIntegrity, "fresh usage result differs from its committed envelope")
		}
		signal.UsageEvidence = &metadata.Ref
		return s.usageEvidence(ctx, signal, lane, operation, exit, false)
	}
	raw, err := s.blob(ctx, evidence.Raw, api.MaxFrameBytes)
	if err != nil {
		return api.BlobRef{}, err
	}
	for _, object := range []api.BlobRef{ref, evidence.Raw} {
		metadata, err := s.deps.Store.ObjectMetadata(ctx, s.readScope(), object.ID)
		if err != nil {
			return api.BlobRef{}, err
		}
		committed, err := timestamp(metadata.CommittedAt)
		if err != nil {
			return api.BlobRef{}, err
		}
		if metadata.Ref != object || metadata.ACL.Config != s.deps.Config || metadata.ACL.LifeID != lane.LifeID ||
			metadata.ACL.Audience != "service" || metadata.ACL.Generation == 0 || len(metadata.ACL.Participants) != 0 ||
			metadata.ACL.Owner != provenance.Producer.Record.Actor || metadata.SourceOperationID != operation ||
			(metadata.Origin != "service" && metadata.Origin != "worker") || committed.Before(observed) || committed.After(s.deps.Clock.Now()) {
			return api.BlobRef{}, problem(api.CodeIntegrity, "usage object lacks private outside worker provenance")
		}
	}
	if err := api.ValidateUsageSource(evidence, raw, provenance.VendorProfile); err != nil {
		return api.BlobRef{}, err
	}
	if err := api.ValidateUsageWindow(evidence, request, provenance.Producer, s.deps.Clock.Now()); err != nil {
		return api.BlobRef{}, err
	}
	reset, err := timestamp(evidence.ResetsAt)
	if err != nil {
		return api.BlobRef{}, err
	}
	if !reset.After(s.deps.Clock.Now()) {
		return api.BlobRef{}, problem(api.CodeInvalid, "outside usage window has already reset")
	}
	return ref, nil
}
