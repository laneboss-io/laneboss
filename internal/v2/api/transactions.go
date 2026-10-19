package api

import (
	"context"
	"encoding/json"
)

type CompareKind string

const (
	CompareLane         CompareKind = "lane"
	CompareGrants       CompareKind = "grants"
	CompareOrg          CompareKind = "org"
	CompareChange       CompareKind = "change"
	CompareApproval     CompareKind = "approval"
	CompareRecord       CompareKind = "record"
	CompareMail         CompareKind = "mail"
	CompareGuidance     CompareKind = "guidance"
	CompareContinuation CompareKind = "continuation"
	CompareEndpoint     CompareKind = "endpoint"
	CompareUpgrade      CompareKind = "upgrade"
	CompareLaunchPlan   CompareKind = "launch_plan"
)

type InternalKind string

const (
	InternalHelperAllocate   InternalKind = "helper_allocate"
	InternalHelperRegister   InternalKind = "helper_register"
	InternalHelperPrepare    InternalKind = "helper_prepare"
	InternalHelperOpen       InternalKind = "helper_open"
	InternalHelperStop       InternalKind = "helper_stop"
	InternalHelperRelease    InternalKind = "helper_release"
	InternalHelperAbort      InternalKind = "helper_abort"
	InternalEffectComplete   InternalKind = "effect_complete"
	InternalMailDeliver      InternalKind = "mail_deliver"
	InternalGuidanceComplete InternalKind = "guidance_complete"
	InternalGuidanceRecover  InternalKind = "guidance_recover"
	InternalProfileContinue  InternalKind = "profile_continue"
	InternalProfileCancel    InternalKind = "profile_cancel"
	InternalOrgPublish       InternalKind = "org_publish"
	InternalOrgBootstrap     InternalKind = "org_bootstrap"
	InternalUpgradeApply     InternalKind = "upgrade_apply"
	InternalMigrationApply   InternalKind = "migration_apply"
	InternalCaptureAppend    InternalKind = "capture_append"
	InternalObjectRetain     InternalKind = "object_retain"
	InternalJudgeEvaluate    InternalKind = "judge_evaluate"
	InternalLifecycleEffect  InternalKind = "lifecycle_effect"
	InternalChannelReceive   InternalKind = "channel_receive"
	InternalAdminEnroll      InternalKind = "admin_enroll"
	InternalLaunchPlan       InternalKind = "launch_plan"
	InternalPolicyRefresh    InternalKind = "policy_refresh"
)

// InternalIntent comes from a bound service component, never from a public
// Request. Kind has a closed emitter/effect catalog in the contract document.
type InternalIntent struct {
	ID                ID           `json:"id"`
	Kind              InternalKind `json:"kind"`
	Config            string       `json:"config"`
	Actor             Actor        `json:"actor"`
	RequestedBy       Actor        `json:"requested_by"`
	CauseOperationID  ID           `json:"cause_operation_id"`
	CauseRequestID    ID           `json:"cause_request_id"`
	EffectID          ID           `json:"effect_id"`
	Target            LifeRef      `json:"target"`
	LogicalTurnID     ID           `json:"logical_turn_id"`
	CancellationEpoch Generation   `json:"cancellation_epoch"`
}

type RequestKey struct {
	Method         Method
	IdempotencyKey ID
	RequestSHA256  Digest
}

// RPCReply is a closed result selected by Scope.Request.Method, not a map or
// command forwarding result. Exactly one of Result and Error is present.
type RPCReply struct {
	Result json.RawMessage
	Error  *Error
}

// DeferredReply binds a pending synchronous public reply to its original
// reservation and one guarded outbox effect. It is never a public RPC result.
// Only CompleteEffect with the current claim can seal that reservation's reply.
type DeferredReply struct {
	Key         RequestKey
	OperationID ID
	EffectID    ID
}

type MutationReceipt struct {
	PolicyGeneration  Generation
	SimulatedPresence bool
	Config            string
	Key               RequestKey
	Actor             Actor
	Operation         Operation
	Reply             *RPCReply
	Deferred          *DeferredReply
	RawRequest        []byte
	FirstSeq          Sequence
	LastSeq           Sequence
	RecordedAt        Timestamp
}

type RequestReservation struct {
	Scope      Scope
	RawRequest []byte
	Deadline   Timestamp
}

type ProofUse struct {
	Proof  ProofRef
	Target HumanChallengeRequest
}

type TicketUse struct {
	TicketID           ID
	PrincipalID        ID
	Config             string
	EndpointGeneration Generation
	Level              int
	Role               string
	GrantSetID         ID
	Target             LifeRef
}

type ApprovalUse struct {
	ApprovalID     ID
	ChangeID       ID
	ManifestSHA256 Digest
	BaseGeneration Generation
}

type CancellationCheck struct {
	LifeID ID
	Epoch  Generation
}

type TransactionGuard struct {
	Proof        *ProofUse
	Ticket       *TicketUse
	Approval     *ApprovalUse
	Cancellation *CancellationCheck
}

type ReadSnapshot struct {
	ID               ID
	Config           string
	LastSeq          Sequence
	PolicyGeneration Generation
	AsOf             Timestamp
}

type ReadView interface {
	Snapshot() ReadSnapshot
	Close() error
}

type StateWrites struct {
	LaunchPlans      []LaunchPlanRecord
	Grants           []GrantSet
	JudgeAudits      []JudgeAudit
	Channels         []EnrolledChannel
	WorkerLeases     []WorkerLease
	Lanes            []Lane
	Endpoints        []EndpointProjection
	Decisions        []DecisionProjection
	Enrollments      []EnrollmentInstall
	IdentityBindings []LaunchBindingRequest
	Challenges       []StoredChallenge
	Proofs           []VerifiedHumanProof
	Counters         []CredentialCounterChange
	Tickets          []Ticket
	ReadSessions     []StoredReadSession
	Objects          []ObjectWrite
	UploadBegins     []UploadLease
	UploadChunks     []BlobChunk
	UploadCommits    []BlobCommitRequest
	Changes          []ChangeRequest
	Approvals        []ChangeApproval
	Applications     []ChangeReceipt
	OrgSnapshots     []OrgSnapshot
	Turns            []TurnSnapshot
	Guidance         []GuidanceSelection
	Continuations    []ContinuationIntent
	Mail             []Mail
	Deliveries       []Delivery
	Deployments      []DeploymentPlan
	Policy           *EffectivePolicy
}

type EffectRecord struct {
	Effect         Effect
	Generation     Generation
	State          EffectState
	ClaimID        ID
	ClaimantID     ID
	ClaimExpiresAt Timestamp
	Outcome        *EffectOutcome `json:"Outcome,omitempty"`
	LastSeq        Sequence
}

type EffectClaimRequest struct {
	EffectID           ID
	ExpectedGeneration Generation
	ClaimantID         ID
	Deadline           Timestamp
}

type EffectLease struct {
	Record    EffectRecord
	ClaimID   ID
	ExpiresAt Timestamp
}

type EffectOutcome struct {
	LaunchPlan         *LaunchPlan
	Reply              *DeferredCompletion
	HelperLease        *HelperLease
	Prepared           *PreparedLaunch
	Process            *ProcessHandle
	EffectID           ID
	ClaimID            ID
	ExpectedGeneration Generation
	Status             string
	Observation        *ProcessObservation
	Abort              *AbortReceipt
	Release            *ReleaseReceipt
	Delivery           *Delivery
	Publication        *ChangeReceipt
	Bootstrap          *BootstrapReceipt
	Deployment         *DeploymentReceipt
	Output             *BlobRef
	Error              *Error
}

// DeferredCompletion carries the final typed reply alongside the measured
// outcome. The store commits both atomically, without consuming guards again.
type DeferredCompletion struct {
	Deferred DeferredReply
	Reply    RPCReply
}

type ReceiptStore interface {
	LookupReceipt(context.Context, Scope, RequestKey) (MutationReceipt, error)
	ReserveRequest(context.Context, RequestReservation) (MutationReceipt, error)
	AwaitReceipt(context.Context, Scope, RequestKey) (MutationReceipt, error)
	BeginRead(context.Context, Scope) (ReadView, error)
}

type EffectStore interface {
	Effect(context.Context, Scope, ID) (EffectRecord, error)
	ClaimEffect(context.Context, Scope, EffectClaimRequest) (EffectLease, error)
	CompleteEffect(context.Context, Scope, EffectOutcome) (Commit, error)
}

// StateStore composes the single service-owned store's typed capabilities.
// Adding these ports does not add a lane socket operation or another writer.
type StateStore interface {
	CredentialProjectionStore
	PolicyStore
	LaunchDataStageStore
	ChannelJobStore
	LaunchStore
	CaptureStore
	Store
	ReceiptStore
	EffectStore
	IdentityStore
	ObjectStore
	OrgStore
	TurnStore
	DeliveryStore
	DeploymentStore
}
