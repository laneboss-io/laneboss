package api

import "context"

// All launch-plan ports are installed service dependencies, never public RPCs.
// IDs select retained records; possession of an ID is not authority.
type LaunchReservationRequest struct {
	Loop           *LoopTurnSelector  `json:"loop,omitempty"`
	OperationID    ID                 `json:"operation_id"`
	ContinuationID ID                 `json:"continuation_id,omitempty"`
	Guards         []TransactionGuard `json:"guards,omitempty"`
}

// A retained reference to authority consumed by this reservation's operation.
// The store verifies the actual ticket/proof use or authentic starter record.
type LaunchAuthority struct {
	Kind string `json:"kind"`
	ID   ID     `json:"id"`
}

// The store issues every ID and derives this record from the original request,
// current life/ticket, policy and cancellation fence in one short transaction.
type LaunchReservation struct {
	Loop              *LoopTurnCause  `json:"loop,omitempty"`
	ID                ID              `json:"id"`
	Config            string          `json:"config"`
	Mode              string          `json:"mode"`
	Level             int             `json:"level"`
	Role              string          `json:"role"`
	Driver            Driver          `json:"driver"`
	Authority         LaunchAuthority `json:"authority"`
	Target            LifeRef         `json:"target"`
	LaunchID          ID              `json:"launch_id"`
	SpecID            ID              `json:"spec_id"`
	GrantSetID        ID              `json:"grant_set_id"`
	Generation        Generation      `json:"generation"`
	BaseGeneration    Generation      `json:"base_generation"`
	CancellationEpoch Generation      `json:"cancellation_epoch"`
	PolicyGeneration  Generation      `json:"policy_generation"`
	ParentLifeID      ID              `json:"parent_life_id,omitempty"`
	RootLifeID        ID              `json:"root_life_id"`
	StarterChain      []ID            `json:"starter_chain"`
	StarterEventSeq   Sequence        `json:"starter_event_seq"`
	OperationID       ID              `json:"operation_id"`
	RequestID         ID              `json:"request_id"`
	RequestSHA256     Digest          `json:"request_sha256"`
	RequestedBy       Actor           `json:"requested_by"`
	OriginalRequest   BlobRef         `json:"original_request"`
	PreviousLaunchID  ID              `json:"previous_launch_id,omitempty"`
}

type LaunchPlanEffect struct {
	ReservationID ID `json:"reservation_id"`
}

type LaunchPlanRequest struct {
	Lease EffectLease
}

// Unlike the public preview, resolution can only bind a store reservation.
// Grants and role/level come from its retained request, not another input copy.
type GrantResolveRequest struct {
	ReservationID ID `json:"reservation_id"`
}

type LaunchSourceRequest struct {
	Claim         LaunchClaim `json:"-"`
	ReservationID ID          `json:"reservation_id"`
	GrantSetID    ID          `json:"grant_set_id"`
}

// Administrator-installed metadata in the existing protected object store.
// Runtime paths remain root-relative RuntimeObjects in RuntimeManifest.
type LaunchEnrollment struct {
	Schema     string              `json:"schema"`
	Config     string              `json:"config"`
	Generation Generation          `json:"generation"`
	Projects   []ProjectEnrollment `json:"projects"`
	Runtimes   []LaunchRuntime     `json:"runtimes"`
	Supervisor *Executable         `json:"supervisor,omitempty"`
	Network    []NetworkEndpoint   `json:"network,omitempty"`
}

// NetworkEndpoint is administrator enrollment, never a lane supplied hostname.
// HostAddresses includes public NAT addresses absent from the host interfaces.
type NetworkEndpoint struct {
	ID            ID       `json:"id"`
	Host          string   `json:"host"`
	Protocol      string   `json:"protocol"`
	Port          uint16   `json:"port"`
	HostAddresses []string `json:"host_addresses,omitempty"`
}

type ProjectEnrollment struct {
	ID           ID         `json:"id"`
	Generation   Generation `json:"generation"`
	ProjectID    ID         `json:"project_id"`
	Object       BlobRef    `json:"object"`
	Base         string     `json:"base"`
	HistoryScope string     `json:"history_scope"`
}

// These are projections of protected enrollment and committed grant objects.
// Object/Manifest are immutable content references, never host-path resolvers.
type ProjectLaunchSource struct {
	EnrollmentID ID         `json:"enrollment_id"`
	Generation   Generation `json:"generation"`
	ProjectID    ID         `json:"project_id"`
	GrantID      ID         `json:"grant_id"`
	Object       BlobRef    `json:"object"`
	Base         string     `json:"base"`
	HistoryScope string     `json:"history_scope"`
}

type LaunchRuntime struct {
	EnrollmentID ID         `json:"enrollment_id"`
	Generation   Generation `json:"generation"`
	Backend      string     `json:"backend"`
	Driver       Driver     `json:"driver"`
	Executable   Executable `json:"executable"`
	Manifest     BlobRef    `json:"manifest"`
	// SessionExecutable is the exact history-owning vendor, which may differ
	// from the wrapper in Executable. Both pins select installed runtime files.
	SessionExecutable Executable `json:"session_executable,omitempty,omitzero"`
}

type LaunchSources struct {
	ReservationID ID                  `json:"reservation_id"`
	Project       ProjectLaunchSource `json:"project"`
	Runtime       LaunchRuntime       `json:"runtime"`
}

type LaunchDataRequest struct {
	Claim         LaunchClaim `json:"-"`
	ReservationID ID          `json:"reservation_id"`
	GrantSetID    ID          `json:"grant_set_id"`
	LeaseID       ID          `json:"lease_id"`
}

// RootID resolves only through the helper's protected life-owned storage
// registry. It is not a directory name, caller path or generic object blob.
type PrivateHomeBinding struct {
	LifeID     ID          `json:"life_id"`
	RootID     ID          `json:"root_id"`
	Generation Generation  `json:"generation"`
	Home       PrivateHome `json:"home"`
}

// Read from the allocation journal before materialization, without a spec.
// The fixed worker bootstrap resolves these IDs to its confined destinations.
type LaunchStorage struct {
	ReservationID ID                 `json:"reservation_id"`
	Target        LifeRef            `json:"target"`
	LeaseID       ID                 `json:"lease_id"`
	WorkspaceID   ID                 `json:"workspace_id"`
	Home          PrivateHomeBinding `json:"home"`
}

type LaunchData struct {
	ReservationID   ID                  `json:"reservation_id"`
	Target          LifeRef             `json:"target"`
	LeaseID         ID                  `json:"lease_id"`
	Source          ProjectLaunchSource `json:"source"`
	Workspace       Workspace           `json:"workspace"`
	Home            PrivateHomeBinding  `json:"home"`
	Materialization Materialization     `json:"materialization"`
}

type LaunchInputs struct {
	Grants  GrantSet      `json:"grants"`
	Sources LaunchSources `json:"sources"`
}

// A complete pre-spec plan. Runner argv is produced by one pinned D8 adapter;
// no client, data object or runtime resolver supplies arbitrary helper argv.
type LaunchPlan struct {
	CapturePolicy *EffectivePolicy  `json:"capture_policy,omitempty"`
	Reservation   LaunchReservation `json:"reservation"`
	Inputs        LaunchInputs      `json:"inputs"`
	Lease         HelperLease       `json:"lease"`
	Data          LaunchData        `json:"data"`
	Runner        RunnerPlan        `json:"runner"`
	Injection     Injection         `json:"injection"`
	Budget        Budget            `json:"budget"`
	Capture       CaptureBinding    `json:"capture"`
}

// Phase is reserved, sourced, planned, spec_retained, bound, opened or failed.
// External stage receipts stay in the original EffectStore alongside this
// projection. A missing/unknown stage never authorizes a replacement launch.
type LaunchPlanRecord struct {
	DataStageID ID                   `json:"data_stage_id,omitempty"`
	Reservation LaunchReservation    `json:"reservation"`
	Generation  Generation           `json:"generation"`
	Phase       string               `json:"phase"`
	Inputs      *LaunchInputs        `json:"inputs,omitempty"`
	Plan        *LaunchPlan          `json:"plan,omitempty"`
	Handoff     *PreparedSpecHandoff `json:"handoff,omitempty"`
	Error       *Error               `json:"error,omitempty"`
}

type LaunchRecovery struct {
	PlanID          ID                  `json:"plan_id"`
	OriginalRequest BlobRef             `json:"original_request"`
	Handoff         PreparedSpecHandoff `json:"handoff"`
	Home            PrivateHomeBinding  `json:"home"`
	Capture         CaptureBinding      `json:"capture"`
}

type LaunchPlanner interface {
	PlanLaunch(context.Context, Scope, LaunchPlanRequest) (LaunchPlan, error)
}

type LaunchSourceResolver interface {
	ResolveLaunchSources(context.Context, LaunchSourceRequest) (LaunchSources, error)
}

type LaunchStorageResolver interface {
	ResolveLaunchStorage(context.Context, LaunchDataRequest) (LaunchStorage, error)
}

type LaunchStore interface {
	ReserveLaunch(context.Context, Scope, LaunchReservationRequest) (LaunchReservation, error)
	LaunchPlan(context.Context, Scope, ID) (LaunchPlanRecord, error)
}

// The Linux ControlSource contract is shared with service/assembly here.
// Each lookup resolves the current durable effect claim and original retained
// objects. An ambient label or in-memory launch-ID map cannot implement it.
type LaunchControlSource interface {
	Plan(context.Context, ID) (LaunchPlanRecord, error)
	Handoff(context.Context, LaunchSpec) (PreparedSpecHandoff, error)
	Original(context.Context, BlobRef) ([]byte, error)
	PrepareIntent(context.Context, PreparedSpecHandoff) (InternalIntent, error)
	Binding(context.Context, ID) (LaunchBindingRequest, error)
	Open(context.Context, PreparedLaunch, LaunchPermit) (HelperOpenRequest, error)
	Observe(context.Context, ProcessHandle) (HelperObserveRequest, error)
	Stop(context.Context, ProcessHandle, string) (HelperStopRequest, error)
	Abort(context.Context, PreparedLaunch) (HelperAbortRequest, error)
	Release(context.Context, ID, ProcessObservation) (HelperReleaseRequest, error)
	RecordRelease(context.Context, HelperReleaseRequest, ReleaseReceipt) error
	RecordAbort(context.Context, HelperAbortRequest, AbortReceipt) error
	Probe(context.Context) (IsolationCapabilities, error)
}
