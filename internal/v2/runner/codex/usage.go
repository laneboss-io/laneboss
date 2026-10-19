package codex

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// The source owns the real outside query and normalization. This adapter never
// invents a Codex usage command or accepts a lane's quoted quota text as proof.
func (s *Service) outsideUsage(ctx context.Context, lane api.Lane, profile api.ProfileGrant, exit api.ProcessObservation) (api.BlobRef, error) {
	var empty api.BlobRef
	if s.deps.UsageWindows == nil {
		return empty, api.NotImplemented("lb-v2-secrets", "secrets.ReadUsageWindow")
	}
	if s.deps.UsageWorker == nil || s.deps.UsageProfile == nil {
		return empty, api.NotImplemented("lb-v2-codex", "protected outside usage bindings")
	}
	retained, err := s.retainedLaunch(ctx, lane.LaunchID)
	if err != nil {
		return empty, err
	}
	r := retained.Reservation
	if retained.Phase != "opened" || r.Target != (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) {
		return empty, problem(api.CodeIntegrity, "Codex usage requires the causing opened launch")
	}
	query := api.UsageWindowRequest{Target: r.Target, LaunchID: r.LaunchID, OperationID: r.OperationID,
		ProfileGrantID: profile.ID, ProfileID: profile.ProfileID, Provider: profile.Provider, RunEndedAt: exit.ObservedAt,
		AdapterVersion: AdapterVersion, Executable: s.deps.Runtime.Executable, RuntimeManifest: retained.Inputs.Sources.Runtime.Manifest}
	evidence, err := s.deps.UsageWindows.ReadUsageWindow(ctx, s.deps.ReadScope, query)
	if err != nil {
		return empty, dependencyError(err)
	}
	endpoint, peer, err := s.deps.UsageWorker(ctx, s.deps.ReadScope, evidence.WorkerLeaseID)
	if err != nil {
		return empty, dependencyError(err)
	}
	producer, err := s.usagePrincipal(ctx, endpoint, peer)
	if err != nil {
		return empty, dependencyError(err)
	}
	if endpoint.Config != r.Config || endpoint.WorkerLeaseID != evidence.WorkerLeaseID {
		return empty, problem(api.CodeIntegrity, "Codex usage lookup returned a foreign installed worker")
	}
	if err := s.usageWindow(evidence, query, producer); err != nil {
		return empty, err
	}
	reset, err := timestamp(evidence.ResetsAt)
	if err != nil || !reset.After(s.deps.Clock.Now()) {
		return empty, problem(api.CodeIntegrity, "Codex usage window reset is no longer in the future")
	}
	raw, err := s.usageObject(ctx, evidence.Raw, "usage_raw", r)
	if err != nil {
		return empty, err
	}
	vendorProfile, err := s.deps.UsageProfile(ctx, profile)
	if err != nil {
		return empty, dependencyError(err)
	}
	if err := api.ValidateUsageSource(evidence, raw, vendorProfile); err != nil {
		return empty, dependencyError(err)
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ReadScope, evidence.ID)
	if err != nil {
		return empty, dependencyError(err)
	}
	if metadata.Ref.ID != evidence.ID {
		return empty, problem(api.CodeIntegrity, "Codex usage envelope object selector changed")
	}
	data, err := s.usageObject(ctx, metadata.Ref, "usage_window", r)
	if err != nil {
		return empty, err
	}
	var committed api.UsageWindowEvidence
	if decode(data, &committed) != nil || !reflect.DeepEqual(committed, evidence) {
		return empty, problem(api.CodeIntegrity, "Codex usage envelope differs from its committed bytes")
	}
	// File/profile reads can outlive the producing claim. Reload the protected
	// principal and check its current lease immediately before using the result.
	current, err := s.usagePrincipal(ctx, endpoint, peer)
	if err != nil {
		return empty, err
	}
	if err := s.usageWindow(evidence, query, current); err != nil {
		return empty, err
	}
	return metadata.Ref, nil
}

func (s *Service) usagePrincipal(ctx context.Context, endpoint api.InstalledBinding, peer api.PeerFacts) (api.WorkerPrincipal, error) {
	producer, err := s.deps.Store.WorkerBinding(ctx, endpoint, peer)
	if err != nil {
		return api.WorkerPrincipal{}, dependencyError(err)
	}
	if err := api.ValidateWorkerPrincipal(producer, endpoint, peer, api.WorkerResultAppend, s.deps.Clock.Now()); err != nil {
		return api.WorkerPrincipal{}, dependencyError(err)
	}
	return producer, nil
}

func (s *Service) usageWindow(evidence api.UsageWindowEvidence, query api.UsageWindowRequest, producer api.WorkerPrincipal) error {
	if err := api.ValidateUsageWindow(evidence, query, producer, s.deps.Clock.Now()); err != nil {
		return dependencyError(err)
	}
	return nil
}

func (s *Service) usageObject(ctx context.Context, ref api.BlobRef, class string, cause api.LaunchReservation) ([]byte, error) {
	if ref.Class != class || ref.Bytes > api.MaxFrameBytes {
		return nil, problem(api.CodeIntegrity, "Codex usage object has the wrong bounded class")
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ReadScope, ref.ID)
	if err != nil {
		return nil, dependencyError(err)
	}
	if metadata.Ref != ref || metadata.Origin != "service" || metadata.SourceOperationID != cause.OperationID ||
		metadata.ACL.Config != cause.Config || metadata.ACL.LifeID != cause.Target.LifeID ||
		metadata.ACL.Audience != "service" || metadata.ACL.Owner.Kind != "service" || len(metadata.ACL.Participants) != 0 {
		return nil, problem(api.CodeIntegrity, "Codex usage object is not private original service evidence")
	}
	return s.readBlob(ctx, ref)
}
