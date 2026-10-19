package admin

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

const isolationProbeTimeout = helperWorkTimeout - helperReplyTimeout

type isolationCanary struct {
	Nonce           api.ID
	UID, GID        uint32
	InputSHA256     api.Digest
	WrittenSHA256   api.Digest
	NoNewPrivileges int
	Seccomp         int
	UnshareErrno    int
	RuntimeErrno    int
	LandlockErrno   int
	NetworkErrno    int
	PrivateProc     bool
}

type isolationProof struct {
	Schema                 string
	Config                 string
	BootID                 string
	InstallationGeneration api.Generation
	ArtifactSHA256         api.Digest
	Runtime                api.BlobRef
	Kernel                 string
	LandlockABI            int
	Nonce                  api.ID
	UID, GID               uint32
	Peer                   api.PeerFacts
	InputSHA256            api.Digest
	CgroupDevice           string
	CgroupInode            string
	NamespaceDevice        string
	NamespaceInode         string
	PrivateNamespaces      bool
	Limits                 [][2]string
	HostControl            bool
	ClosedGate             bool
	SecondReleaseRefused   bool
	PipeMarker             string
	Canary                 isolationCanary
	Observation            api.ProcessObservation
	Collected              bool
	ObservedAt             api.Timestamp
}

type isolationPacket struct {
	Reference api.BlobRef     `json:"reference"`
	Bytes     json.RawMessage `json:"bytes"`
}

// The helper retains and reads back these bytes before returning the pin.
// Generic helper prerequisite booleans cannot enter this independent port.
func (s *Service) IsolationEvidence(ctx context.Context) (api.IsolationCapabilities, error) {
	if err := contextError(ctx); err != nil {
		return api.IsolationCapabilities{}, err
	}
	var packet isolationPacket
	if err := s.call(ctx, "isolation_evidence", s.deps.RuntimeManifest, &packet); err != nil {
		return api.IsolationCapabilities{}, err
	}
	if packet.Reference.Class != "manifest" || !validID(packet.Reference.ID) || len(packet.Bytes) == 0 || len(packet.Bytes) > api.MaxFrameBytes ||
		packet.Reference.Bytes != int64(len(packet.Bytes)) || packet.Reference.SHA256 != digestBytes(packet.Bytes) {
		return api.IsolationCapabilities{}, failure(api.CodeIntegrity, "installed isolation evidence bytes differ from their retained pin")
	}
	var proof isolationProof
	if err := decodeStrict(packet.Bytes, &proof); err != nil {
		return api.IsolationCapabilities{}, err
	}
	if err := verifyIsolationHost(proof); err != nil {
		return api.IsolationCapabilities{}, err
	}
	return isolationCapabilities(proof, packet.Reference, s.binding, s.deps.RuntimeManifest, time.Now())
}

func isolationCapabilities(p isolationProof, ref api.BlobRef, binding installation, runtime api.BlobRef, now time.Time) (api.IsolationCapabilities, error) {
	if ref.Class != "manifest" || !validID(ref.ID) || !validDigest(ref.SHA256) || ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes {
		return api.IsolationCapabilities{}, failure(api.CodeIntegrity, "isolation capabilities require a retained nonempty proof pin")
	}
	observed, err := time.Parse(time.RFC3339Nano, string(p.ObservedAt))
	if err != nil || observed.After(now) || now.Sub(observed) > time.Minute || p.Schema != "laneboss.isolation-proof.v1" || p.Config != binding.Config ||
		p.InstallationGeneration != binding.Generation || p.ArtifactSHA256 != binding.Artifact.SHA256 || p.Runtime != runtime || p.BootID == "" || p.Kernel == "" || p.LandlockABI < 3 ||
		p.UID == 0 || p.UID == binding.Service.UID || p.Peer.HostUID != p.UID || p.Peer.HostGID != p.GID || p.Peer.HostPID <= 1 || p.Peer.ProcessGeneration == "" ||
		!validID(p.Peer.ContainmentID) || !validID(p.Nonce) || len(p.Nonce) < 32 || !validDigest(p.InputSHA256) || p.CgroupDevice == "" || p.CgroupInode == "" ||
		p.NamespaceDevice == "" || p.NamespaceInode == "" || !p.PrivateNamespaces || !strings.HasPrefix(p.Peer.ProcessGeneration, p.BootID+":") ||
		!reflect.DeepEqual(p.Limits, limitValues(leaseRecord{Request: api.HelperLeaseRequest{Budget: isolationBudget()}})) ||
		!p.HostControl || !p.ClosedGate || !p.SecondReleaseRefused || !p.Collected ||
		p.Canary.Nonce != p.Nonce || p.Canary.UID != p.UID || p.Canary.GID != p.GID || p.Canary.InputSHA256 != p.InputSHA256 ||
		p.Canary.WrittenSHA256 != digestBytes([]byte(p.Nonce)) || p.Canary.NoNewPrivileges != 1 || p.Canary.Seccomp != 2 || !p.Canary.PrivateProc ||
		!isolationDenials(p.Canary) || p.PipeMarker != string(p.Nonce)+"\n" ||
		p.Observation.State != "exited" || p.Observation.ExitCode == nil || *p.Observation.ExitCode != 0 || p.Observation.Signal != nil ||
		p.Observation.Survivors == nil || *p.Observation.Survivors != 0 || p.Observation.Handle.ContainmentID != p.Peer.ContainmentID ||
		p.Observation.Handle.Generation == "" || !validID(p.Observation.Handle.ID) || ref.ID != p.Observation.Handle.ID {
		return api.IsolationCapabilities{}, failure(api.CodeIntegrity, "independent installed isolation measurements are incomplete or mismatched")
	}
	pool := false
	for _, account := range binding.Lanes {
		pool = pool || account.UID == p.UID && account.GID == p.GID
	}
	if !pool {
		return api.IsolationCapabilities{}, failure(api.CodeIntegrity, "isolation proof uses an account outside its installed pool")
	}
	result := api.IsolationCapabilities{Backend: "linux-bwrap-landlock", Kernel: p.Kernel, LandlockABI: p.LandlockABI}
	checks := []struct {
		name   string
		passed bool
	}{
		{"bwrap_options", p.Canary.NoNewPrivileges == 1 && p.PrivateNamespaces},
		{"namespace_boundary", p.PrivateNamespaces && p.NamespaceInode != ""},
		{"seccomp_deny_filter", p.HostControl && p.Canary.UnshareErrno != 0 && p.Canary.Seccomp == 2},
		{"uid_pool", pool && p.Peer.HostUID == p.UID && p.Peer.HostGID == p.GID},
		{"cgroup_containment", p.CgroupInode != "" && p.Collected && p.Observation.Survivors != nil && *p.Observation.Survivors == 0},
		{"controlled_egress", p.HostControl && p.Canary.NetworkErrno != 0 && p.NamespaceInode != ""},
		{"runtime_projection", p.Canary.InputSHA256 == p.InputSHA256 && p.Canary.RuntimeErrno != 0 && p.Canary.LandlockErrno != 0},
		{"capture_pipes", p.PipeMarker == string(p.Nonce)+"\n" && p.Canary.Nonce == p.Nonce},
		{"launch_gate", p.ClosedGate && p.SecondReleaseRefused && p.Observation.ExitCode != nil && *p.Observation.ExitCode == 0},
	}
	result.Available = len(checks) != 0
	for _, check := range checks {
		pin := ref
		result.Checks = append(result.Checks, api.Capability{Name: check.name, Available: check.passed, Evidence: &pin,
			Reason: "observed installed default-deny boundary; nonempty network grants remain unsupported"})
		result.Available = result.Available && check.passed
	}
	return result, nil
}

func isolationBudget() api.Budget {
	return api.Budget{WallMS: 5000, CPUSeconds: 5, MemoryBytes: 256 << 20, Processes: 64, DiskBytes: 1 << 20}
}
