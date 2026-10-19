package api

type Actor struct {
	Kind   string `json:"kind"`
	ID     ID     `json:"id"`
	LifeID ID     `json:"life_id,omitempty"`
	Level  int    `json:"level,omitempty"`
	Role   string `json:"role,omitempty"`
}

type Scope struct {
	scheduler          *schedulerAuthority
	Connection         ConnectionContext `json:"-"`
	Frame              FrameContext      `json:"-"`
	ReadView           ReadView          `json:"-"`
	ReadAuthority      *ReadAuthority    `json:"-"`
	Source             string            `json:"-"`
	Request            Request           `json:"-"`
	Config             string            `json:"config"`
	Actor              Actor             `json:"actor"`
	LaunchID           ID                `json:"launch_id,omitempty"`
	EndpointGeneration Generation        `json:"endpoint_generation"`
	PolicyGeneration   Generation        `json:"policy_generation"`
}

type LifeRef struct {
	LifeID ID        `json:"life_id"`
	Run    RunNumber `json:"run"`
}

type BlobRef struct {
	ID     ID     `json:"id"`
	SHA256 Digest `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Class  string `json:"class"`
}

type BlobBeginRequest struct {
	Class  string `json:"class"`
	Bytes  int64  `json:"bytes"`
	SHA256 Digest `json:"sha256"`
}

type BlobUpload struct {
	ObjectID      ID        `json:"object_id"`
	MaxChunkBytes int       `json:"max_chunk_bytes"`
	ExpiresAt     Timestamp `json:"expires_at"`
}

type BlobChunk struct {
	ObjectID ID     `json:"object_id"`
	Offset   int64  `json:"offset"`
	Data     []byte `json:"data"`
	SHA256   Digest `json:"sha256"`
}

type BlobCommitRequest struct {
	ObjectID ID     `json:"object_id"`
	SHA256   Digest `json:"sha256"`
}

type BlobReadRequest struct {
	ObjectID ID    `json:"object_id"`
	Offset   int64 `json:"offset"`
	Limit    int   `json:"limit"`
}

type Operation struct {
	SimulatedPresence bool        `json:"simulated_presence,omitempty"`
	ID                ID          `json:"id"`
	Status            string      `json:"status"`
	LifeID            ID          `json:"life_id,omitempty"`
	Run               RunNumber   `json:"run,omitempty"`
	FirstSeq          Sequence    `json:"first_seq"`
	LastSeq           Sequence    `json:"last_seq"`
	Result            *BlobRef    `json:"result,omitempty"`
	Error             *Error      `json:"error,omitempty"`
	Stop              *StopResult `json:"stop,omitempty"`
}

// StopResult reports an already committed end. It does not claim collection
// or change the lane's review/decision state. Ordinary stop intents omit it.
type StopResult struct {
	State       string      `json:"state"`
	EndEventID  ID          `json:"end_event_id"`
	EndSequence Sequence    `json:"end_sequence"`
	End         RunEndEvent `json:"end"`
}

type OperationGetRequest struct {
	OperationID ID `json:"operation_id"`
}

type HealthRequest struct {
	ClientVersion  string `json:"client_version"`
	ArtifactSHA256 Digest `json:"artifact_sha256"`
}

type Health struct {
	Protocol       string       `json:"protocol"`
	Schema         uint32       `json:"schema"`
	ServiceVersion string       `json:"service_version"`
	ArtifactSHA256 Digest       `json:"artifact_sha256"`
	Ready          bool         `json:"ready"`
	Capabilities   []Capability `json:"capabilities"`
}

type Capability struct {
	Name      string   `json:"name"`
	Available bool     `json:"available"`
	Reason    string   `json:"reason"`
	Evidence  *BlobRef `json:"evidence,omitempty"`
}

type Budget struct {
	WallMS      int64  `json:"wall_ms"`
	CPUSeconds  uint64 `json:"cpu_seconds"`
	MemoryBytes uint64 `json:"memory_bytes"`
	Processes   uint32 `json:"processes"`
	DiskBytes   uint64 `json:"disk_bytes"`
	SpendMicros int64  `json:"spend_micros"`
	Currency    string `json:"currency"`
}

type CursorRequest struct {
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit"`
}

type ListRequest struct {
	LifeID ID     `json:"life_id,omitempty"`
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit"`
}

type ProofRef struct {
	SimulatedPresence bool      `json:"simulated_presence,omitempty"`
	ID                ID        `json:"id"`
	RequestSHA256     Digest    `json:"request_sha256"`
	ExpiresAt         Timestamp `json:"expires_at"`
}
