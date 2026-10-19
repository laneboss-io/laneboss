package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// DataWorkerNativeBinding is an administrator observation of the original
// closed worker, not a launch permit or a caller-supplied WorkerPrincipal.
// The identity owner must still join the durable worker/claim/commit records.
type DataWorkerNativeBinding struct {
	Selector api.StorageProjectionRequest
	Lease    api.HelperLease
	Prepared api.PreparedLaunch
	Endpoint api.InstalledBinding
	Peer     api.PeerFacts
	BootID   string
}

type DataWorkerNativeSource interface {
	DataWorkerNative(context.Context, api.StorageProjectionRequest) (DataWorkerNativeBinding, error)
}

var _ DataWorkerNativeSource = (*Service)(nil)

func (s *Service) DataWorkerNative(ctx context.Context, q api.StorageProjectionRequest) (DataWorkerNativeBinding, error) {
	r, _, err := s.dataAuthority(ctx, q, true)
	if err != nil {
		return DataWorkerNativeBinding{}, err
	}
	var observed DataWorkerNativeBinding
	if err := s.call(ctx, "data_native", r, &observed); err != nil {
		return DataWorkerNativeBinding{}, err
	}
	if err := validateWorkerNative(observed, r, s.binding); err != nil {
		return DataWorkerNativeBinding{}, err
	}
	return observed, nil
}

func validateWorkerNative(observed DataWorkerNativeBinding, r dataReg, binding installation) error {
	q := r.Request
	if observed.Selector != q || observed.Lease.ID == q.AgentLeaseID || validateLease(observed.Lease, binding) != nil ||
		observed.Prepared.Target != r.Worker.Target || observed.Prepared.ContainmentID != observed.Lease.ContainmentID ||
		observed.Peer.HostUID != observed.Lease.UID || observed.Peer.HostGID != observed.Lease.GID || observed.Peer.HostPID <= 1 ||
		observed.Peer.ProcessGeneration == "" || observed.Peer.ContainmentID != observed.Lease.ContainmentID || observed.BootID == "" ||
		!validID(observed.Prepared.ID) || !validID(observed.Prepared.GateID) || !validDigest(observed.Prepared.SpecSHA256) ||
		observed.Prepared.ProcessGeneration == "" || observed.Prepared.EndpointGeneration != binding.Generation ||
		api.ValidateBinding(observed.Endpoint, binding.Config, binding.Release.Version) != nil ||
		observed.Endpoint.Class != api.EndpointWorker || observed.Endpoint.WorkerLeaseID != r.Worker.ID || observed.Endpoint.LaunchID != r.LaunchID ||
		observed.Endpoint.Target == nil || *observed.Endpoint.Target != r.Worker.Target || observed.Endpoint.Socket != "/runtime/laneboss-worker.sock" ||
		observed.Endpoint.ServiceUID != binding.Service.UID || observed.Endpoint.ServiceGID != binding.Service.GID ||
		observed.Endpoint.ArtifactSHA256 != binding.Artifact.SHA256 || observed.Endpoint.InstallationGeneration != binding.Generation {
		return failure(api.CodeIntegrity, "native worker observation differs from its retained stage")
	}
	return nil
}
