package api

type Driver string

const (
	DriverClaudock Driver = "claudock-cli"
	DriverCodex    Driver = "codex"
)

type Session struct {
	HistoryID     ID     `json:"history_id"`
	ID            ID     `json:"id"`
	Driver        Driver `json:"driver"`
	VendorID      string `json:"vendor_id"`
	VendorVersion string `json:"vendor_version"`
	HomeID        ID     `json:"home_id"`
	LogicalCWD    string `json:"logical_cwd"`
}

type Executable struct {
	ID      ID     `json:"id"`
	SHA256  Digest `json:"sha256"`
	Version string `json:"version"`
}

type PrivateHome struct {
	ID              ID     `json:"id"`
	WorkspaceID     ID     `json:"workspace_id"`
	VendorDirectory string `json:"vendor_directory"`
	HistoryID       ID     `json:"history_id"`
}

type CredentialSlot struct {
	ID             ID        `json:"id"`
	ProfileGrantID ID        `json:"profile_grant_id"`
	ProfileID      ID        `json:"profile_id"`
	Mode           string    `json:"mode"`
	LeaseID        ID        `json:"lease_id"`
	ExpiresAt      Timestamp `json:"expires_at"`
}

type RunnerRequest struct {
	Target        LifeRef        `json:"target"`
	LogicalTurnID ID             `json:"logical_turn_id"`
	Session       Session        `json:"session"`
	Prompt        BlobRef        `json:"prompt"`
	Home          PrivateHome    `json:"home"`
	Slot          CredentialSlot `json:"slot"`
	Executable    Executable     `json:"executable"`
	Model         string         `json:"model"`
	Effort        string         `json:"effort"`
	Budget        Budget         `json:"budget"`
}

type RunnerPlan struct {
	Driver           Driver         `json:"driver"`
	Executable       Executable     `json:"executable"`
	Argv             []string       `json:"argv"`
	CWD              string         `json:"cwd"`
	EnvironmentNames []string       `json:"environment_names"`
	Prompt           BlobRef        `json:"prompt"`
	Home             PrivateHome    `json:"home"`
	Slot             CredentialSlot `json:"slot"`
	Session          Session        `json:"session"`
	InnerSandbox     string         `json:"inner_sandbox"`
	AdapterVersion   string         `json:"adapter_version"`
}

type CaptureRecord struct {
	BindingID     ID        `json:"binding_id,omitempty"`
	ID            ID        `json:"id"`
	Target        LifeRef   `json:"target"`
	Stream        string    `json:"stream"`
	Offset        int64     `json:"offset"`
	Data          BlobRef   `json:"data"`
	ObservedAt    Timestamp `json:"observed_at"`
	Primary       bool      `json:"primary"`
	Coverage      string    `json:"coverage"`
	ReplacementOf ID        `json:"replacement_of,omitempty"`
}

type LimitSignal struct {
	UsageEvidence  *BlobRef  `json:"usage_evidence,omitempty"`
	Target         LifeRef   `json:"target"`
	Kind           string    `json:"kind"`
	ProfileID      ID        `json:"profile_id"`
	Provider       string    `json:"provider"`
	CaptureID      ID        `json:"capture_id"`
	CaptureSHA256  Digest    `json:"capture_sha256"`
	ExitCode       *int      `json:"exit_code,omitempty"`
	AdapterVersion string    `json:"adapter_version"`
	ObservedAt     Timestamp `json:"observed_at"`
}

type Room struct {
	ProfileID ID        `json:"profile_id"`
	Available bool      `json:"available"`
	CheckedAt Timestamp `json:"checked_at"`
	ExpiresAt Timestamp `json:"expires_at"`
	Evidence  BlobRef   `json:"evidence"`
	Reason    string    `json:"reason"`
}

type ProfileSwap struct {
	ProfileGrantID     ID          `json:"profile_grant_id"`
	EligibilityID      ID          `json:"eligibility_id"`
	ExpectedGeneration Generation  `json:"expected_generation"`
	CancellationEpoch  Generation  `json:"cancellation_epoch"`
	FromProfileID      ID          `json:"from_profile_id"`
	ToProfileID        ID          `json:"to_profile_id"`
	CausingRun         RunNumber   `json:"causing_run"`
	ContinuationRun    RunNumber   `json:"continuation_run"`
	LogicalTurnID      ID          `json:"logical_turn_id"`
	Limit              LimitSignal `json:"limit"`
	Room               Room        `json:"room"`
	OperationID        ID          `json:"operation_id"`
}

type SecretInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	SourceHandle ID     `json:"source_handle"`
	KeyID        ID     `json:"key_id"`
	Revoked      bool   `json:"revoked"`
}

type SecretImportRequest struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	SealedUploadID ID     `json:"sealed_upload_id"`
}

type SecretRotateRequest struct {
	Name            string `json:"name"`
	ExpectedVersion string `json:"expected_version"`
	SealedUploadID  ID     `json:"sealed_upload_id"`
}

type SecretRevokeRequest struct {
	Name            string `json:"name"`
	ExpectedVersion string `json:"expected_version"`
}

type Injection struct {
	Target              LifeRef  `json:"target"`
	SlotIDs             []ID     `json:"slot_ids"`
	TaskSecretNames     []string `json:"task_secret_names"`
	TaskSecretFileNames []string `json:"task_secret_file_names"`
	GrantIDs            []ID     `json:"grant_ids"`
	SourceVersions      []string `json:"source_versions"`
	Outcome             string   `json:"outcome"`
}

type IsolationCapabilities struct {
	Backend     string       `json:"backend"`
	Available   bool         `json:"available"`
	Kernel      string       `json:"kernel"`
	LandlockABI int          `json:"landlock_abi"`
	Checks      []Capability `json:"checks"`
}

type LaunchSpec struct {
	PlanID             ID              `json:"plan_id,omitempty"`
	Capture            *CaptureBinding `json:"capture,omitempty"`
	Kind               string          `json:"kind"`
	Worker             *WorkerPlan     `json:"worker,omitempty"`
	ID                 ID              `json:"id"`
	Target             LifeRef         `json:"target"`
	LaunchID           ID              `json:"launch_id"`
	Backend            string          `json:"backend"`
	UIDLeaseID         ID              `json:"uid_lease_id"`
	Workspace          Workspace       `json:"workspace"`
	Materialization    Materialization `json:"materialization"`
	Grants             GrantSet        `json:"grants"`
	Runner             *RunnerPlan     `json:"runner,omitempty"`
	Injection          Injection       `json:"injection"`
	Budget             Budget          `json:"budget"`
	EndpointGeneration Generation      `json:"endpoint_generation"`
	RuntimeManifest    BlobRef         `json:"runtime_manifest"`
	PolicyGeneration   Generation      `json:"policy_generation"`
}

type PreparedLaunch struct {
	ID                 ID         `json:"id"`
	SpecSHA256         Digest     `json:"spec_sha256"`
	Target             LifeRef    `json:"target"`
	ContainmentID      ID         `json:"containment_id"`
	ProcessGeneration  string     `json:"process_generation"`
	EndpointGeneration Generation `json:"endpoint_generation"`
	GateID             ID         `json:"gate_id"`
}

type LaunchPermit struct {
	LaunchID     ID       `json:"launch_id"`
	PreparedID   ID       `json:"prepared_id"`
	RecordSHA256 Digest   `json:"record_sha256"`
	CommittedSeq Sequence `json:"committed_seq"`
}

type ProcessHandle struct {
	ID            ID      `json:"id"`
	Target        LifeRef `json:"target"`
	ContainmentID ID      `json:"containment_id"`
	Generation    string  `json:"generation"`
}

type ProcessObservation struct {
	Handle       ProcessHandle `json:"handle"`
	State        string        `json:"state"`
	ExitCode     *int          `json:"exit_code,omitempty"`
	Signal       *int          `json:"signal,omitempty"`
	Survivors    *uint64       `json:"survivors,omitempty"`
	PromptStatus string        `json:"prompt_status"`
	ObservedAt   Timestamp     `json:"observed_at"`
}

type LaunchRecord struct {
	Kind               string     `json:"kind,omitempty"`
	ID                 ID         `json:"id"`
	Config             string     `json:"config"`
	Target             LifeRef    `json:"target"`
	ParentLifeID       ID         `json:"parent_life_id,omitempty"`
	RootLifeID         ID         `json:"root_life_id"`
	StarterChain       []ID       `json:"starter_chain"`
	StarterEventSeq    Sequence   `json:"starter_event_seq"`
	Actor              Actor      `json:"actor"`
	UIDLeaseID         ID         `json:"uid_lease_id"`
	HostUID            uint32     `json:"host_uid"`
	ProcessGeneration  string     `json:"process_generation"`
	ContainmentID      ID         `json:"containment_id"`
	GrantSetID         ID         `json:"grant_set_id"`
	GrantsSHA256       Digest     `json:"grants_sha256"`
	PolicyGeneration   Generation `json:"policy_generation"`
	EndpointGeneration Generation `json:"endpoint_generation"`
	Revoked            bool       `json:"revoked"`
}

type HelperLeaseRequest struct {
	ReservationID     ID             `json:"reservation_id,omitempty"`
	Cause             InternalIntent `json:"cause"`
	Config            string         `json:"config"`
	LifeID            ID             `json:"life_id"`
	Backend           string         `json:"backend"`
	Budget            Budget         `json:"budget"`
	RuntimeManifestID ID             `json:"runtime_manifest_id"`
}

type HelperLease struct {
	ID                 ID         `json:"id"`
	UID                uint32     `json:"uid"`
	GID                uint32     `json:"gid"`
	ContainmentID      ID         `json:"containment_id"`
	EndpointGeneration Generation `json:"endpoint_generation"`
}

type HelperLaunchRequest struct {
	Cause          InternalIntent `json:"cause"`
	LeaseID        ID             `json:"lease_id"`
	PreparedSpecID ID             `json:"prepared_spec_id"`
	SpecSHA256     Digest         `json:"spec_sha256"`
}
