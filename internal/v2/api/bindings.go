package api

import (
	"context"
	"net"
	"os"
)

type EndpointClass string

const (
	EndpointLane   EndpointClass = "lane"
	EndpointHuman  EndpointClass = "human"
	EndpointWorker EndpointClass = "worker"
)

// InstalledBinding is protected installation data, never request authority.
// A lane sees only its generated read-only projection of this object.
type InstalledBinding struct {
	Schema                 string        `json:"schema"`
	ContractRevision       string        `json:"contract_revision"`
	Protocol               string        `json:"protocol"`
	APISchema              uint32        `json:"api_schema"`
	Config                 string        `json:"config"`
	Class                  EndpointClass `json:"class"`
	InstallationGeneration Generation    `json:"installation_generation"`
	EndpointGeneration     Generation    `json:"endpoint_generation"`
	ServiceUID             uint32        `json:"service_uid"`
	ServiceGID             uint32        `json:"service_gid"`
	MappedServiceUID       uint32        `json:"mapped_service_uid"`
	MappedServiceGID       uint32        `json:"mapped_service_gid"`
	Socket                 string        `json:"socket"`
	ArtifactSHA256         Digest        `json:"artifact_sha256"`
	ServiceVersion         string        `json:"service_version"`
	Backend                string        `json:"backend"`
	LaunchID               ID            `json:"launch_id,omitempty"`
	Target                 *LifeRef      `json:"target,omitempty"`
	WorkerLeaseID          ID            `json:"worker_lease_id,omitempty"`
}

// ConnectionContext is owned and closed by the transport. Its peer is pinned
// for the connection lifetime, and is rechecked before each request/delivery.
// Transport creates it with Conn/Binding before Authenticate. Identity first
// verifies that raw socket with the binding, then binds its peer exactly once.
// BindReadAuthority is identity-only after a committed human.session proof;
// replacement peers, cross-connection sessions and post-close binds refuse.
type ConnectionContext interface {
	ID() ID
	Conn() net.Conn
	Binding() InstalledBinding
	BindPeer(VerifiedPeer) error
	Peer() VerifiedPeer
	BindReadAuthority(ReadAuthority) error
	ReadAuthority(context.Context) (ReadAuthority, error)
	Close() error
}

// FrameContext is produced only by the credential-aware transport. Verify
// checks every recvmsg fragment's writer against the connector lifetime and
// rejects missing/truncated/extra ancillary data or passed descriptors.
type FrameContext interface {
	Bytes() []byte
	Verify(context.Context, ConnectionContext) error
}

type ReadAuthority struct {
	Generation         Generation
	SimulatedPresence  bool
	ConnectionID       ID
	SessionID          ID
	PrincipalID        ID
	CredentialID       ID
	Config             string
	EndpointGeneration Generation
	IdleExpiresAt      Timestamp
	ExpiresAt          Timestamp
}

type ContainmentBinding struct {
	Config     string
	Lease      HelperLease
	Target     LifeRef
	Backend    string
	BootID     string
	Generation Generation
	Revoked    bool
	// Directory is an owned duplicate of the helper-created cgroup identity.
	// Native Darwin instead resolves its protected UID lease/kernel lifetime.
	Directory *os.File `json:"-"`
}

type ContainmentRegistry interface {
	RegisterContainment(context.Context, ContainmentBinding) error
	ResolveContainment(context.Context, PeerFacts, InstalledBinding) (ContainmentBinding, error)
	RevokeContainment(context.Context, ID) error
}

type IdentityCommit struct {
	LaunchID     ID
	EventID      ID
	CommittedSeq Sequence
	RecordSHA256 Digest
}

type LaunchBindingRequest struct {
	Record   LaunchRecord
	Prepared PreparedLaunch
	Identity IdentityCommit
	// Required for agent bindings; workers retain their separate leased job.
	Recovery *LaunchRecovery
}

type PreparedSpecHandoff struct {
	Cause       InternalIntent `json:"cause"`
	Config      string         `json:"config"`
	Spec        LaunchSpec     `json:"spec"`
	Original    BlobRef        `json:"original"`
	SpecSHA256  Digest         `json:"spec_sha256"`
	OperationID ID             `json:"operation_id"`
	RequestID   ID             `json:"request_id"`
}

type PreparedSpecReceipt struct {
	SpecID          ID      `json:"spec_id"`
	Config          string  `json:"config"`
	Target          LifeRef `json:"target"`
	LeaseID         ID      `json:"lease_id"`
	SpecSHA256      Digest  `json:"spec_sha256"`
	RuntimeManifest BlobRef `json:"runtime_manifest"`
	OperationID     ID      `json:"operation_id"`
}

type HelperOpenRequest struct {
	Cause       InternalIntent `json:"cause"`
	Prepared    PreparedLaunch `json:"prepared"`
	Permit      LaunchPermit   `json:"permit"`
	OperationID ID             `json:"operation_id"`
	EffectID    ID             `json:"effect_id"`
}

type HelperObserveRequest struct {
	LeaseID ID            `json:"lease_id"`
	Handle  ProcessHandle `json:"handle"`
}

type HelperStopRequest struct {
	Cause       InternalIntent       `json:"cause"`
	Target      HelperObserveRequest `json:"target"`
	Reason      string               `json:"reason"`
	OperationID ID                   `json:"operation_id"`
	EffectID    ID                   `json:"effect_id"`
}

type HelperAbortRequest struct {
	Cause       InternalIntent `json:"cause"`
	LeaseID     ID             `json:"lease_id"`
	PreparedID  ID             `json:"prepared_id"`
	SpecSHA256  Digest         `json:"spec_sha256"`
	OperationID ID             `json:"operation_id"`
	EffectID    ID             `json:"effect_id"`
}

// Observation is the service's comparison claim only. Under its lease lock the
// helper independently measures the pinned cgroup (Linux) or protected UID/kernel
// process set (Darwin), live connections, queued jobs and writable exports.
// Any unknown, nonzero or disagreement refuses and retains the lease. Release
// never substitutes for stopping a process or aborting an unopened gate.
type HelperReleaseRequest struct {
	Cause       InternalIntent     `json:"cause"`
	LeaseID     ID                 `json:"lease_id"`
	Observation ProcessObservation `json:"observation"`
}

// ReleaseReceipt contains helper-measured facts, not copies of request fields.
// Nil counts mean unknown and cannot represent a successful release. The store
// correlates its lease/effect/operation and commits these measured facts only.
type ReleaseReceipt struct {
	ID              ID                 `json:"id"`
	LeaseID         ID                 `json:"lease_id"`
	ContainmentID   ID                 `json:"containment_id"`
	Backend         string             `json:"backend"`
	OperationID     ID                 `json:"operation_id"`
	EffectID        ID                 `json:"effect_id"`
	Quiescence      ProcessObservation `json:"quiescence"`
	LiveConnections *uint64            `json:"live_connections"`
	QueuedJobs      *uint64            `json:"queued_jobs"`
	WritableExports *uint64            `json:"writable_exports"`
	ObservedAt      Timestamp          `json:"observed_at"`
}

type EndpointProjection struct {
	Binding    InstalledBinding
	Generation Generation
	Revoked    bool
}

type AbortReceipt struct {
	ID            ID                 `json:"id"`
	LeaseID       ID                 `json:"lease_id"`
	PreparedID    ID                 `json:"prepared_id"`
	AgentExecuted bool               `json:"agent_executed"`
	Quiescence    ProcessObservation `json:"quiescence"`
	ObservedAt    Timestamp          `json:"observed_at"`
}

type HelperReconcileRequest struct {
	LeaseID     ID `json:"lease_id"`
	LaunchID    ID `json:"launch_id"`
	PreparedID  ID `json:"prepared_id"`
	OperationID ID `json:"operation_id"`
}

type LaunchReconciliation struct {
	Prepared       *PreparedLaunch    `json:"prepared,omitempty"`
	Process        *ProcessHandle     `json:"process,omitempty"`
	Observation    ProcessObservation `json:"observation"`
	GateState      string             `json:"gate_state"`
	ConsumedPermit *LaunchPermit      `json:"consumed_permit,omitempty"`
}

// HelperControl is a fixed authenticated service-to-helper control surface.
// It adds no public method, root argv, path, URL or executable-selection input.
type HelperControl interface {
	CredentialProjectionControl
	LaunchDataStorage
	Helper
	ContainmentRegistry
	RuntimeResolver
	LaunchSourceResolver
	LaunchStorageResolver
	CaptureControl
	RegisterSpec(context.Context, PreparedSpecHandoff) (PreparedSpecReceipt, error)
	OpenGate(context.Context, HelperOpenRequest) (ProcessHandle, error)
	ObserveGate(context.Context, HelperObserveRequest) (ProcessObservation, error)
	StopGate(context.Context, HelperStopRequest) (ProcessObservation, error)
	AbortGate(context.Context, HelperAbortRequest) (AbortReceipt, error)
	ReconcileGate(context.Context, HelperReconcileRequest) (LaunchReconciliation, error)
}

type ProbeBinder interface {
	BindIsolationProbe(Launcher) error
}

type RuntimeObject struct {
	ID           ID       `json:"id"`
	Role         string   `json:"role"`
	RootID       ID       `json:"root_id"`
	RelativePath string   `json:"relative_path"`
	Aliases      []string `json:"aliases,omitempty"`
	Content      BlobRef  `json:"content"`
	Mode         uint32   `json:"mode"`
}

type RuntimeManifest struct {
	Schema     string             `json:"schema"`
	Generation Generation         `json:"generation"`
	Artifact   Executable         `json:"artifact"`
	Bootstrap  Executable         `json:"bootstrap"`
	Objects    []RuntimeObject    `json:"objects"`
	Bindings   []InstalledBinding `json:"bindings"`
}

type NetworkLease struct {
	ID           ID
	GrantSetID   ID
	NamespaceID  ID
	EndpointIDs  []ID
	Generation   Generation
	PolicySHA256 Digest
	ExpiresAt    Timestamp
}

type ResolvedRuntime struct {
	Manifest    RuntimeManifest
	SpecReceipt PreparedSpecReceipt
	Network     NetworkLease
	Home        PrivateHome
	Workspace   Workspace
}

type RuntimeResolver interface {
	ResolveRuntime(context.Context, PreparedSpecHandoff) (ResolvedRuntime, error)
}
