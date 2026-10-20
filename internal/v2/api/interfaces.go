package api

import (
	"context"
	"encoding/json"
	"time"
)

// SecretMaterial never serializes and never enters the generic blob/event store.
type SecretMaterial struct {
	Bytes []byte `json:"-"`
}

type TokenFit struct {
	Proved          bool
	InputBytes      int
	InputTokens     int
	ContextTokens   int
	TokenizerSHA256 Digest
	Reason          string
}

type Clock interface{ Now() time.Time }

type Handler func(context.Context, Scope, json.RawMessage) (json.RawMessage, error)
type StreamHandler func(context.Context, Scope, json.RawMessage) (EventStream, error)
type Registrar interface {
	Register(Method, Handler) error
	RegisterStream(Method, StreamHandler) error
}
type Module interface{ Register(Registrar) error }
type EventStream interface {
	Next(context.Context) (StreamFrame, error)
	Close() error
}

// ResponseStream is returned by Client.Stream after authenticating/validating
// the initial typed response. Server-side event producers need only EventStream.
// It preserves the required initial snapshot before follow/attach frames.
type ResponseStream interface {
	EventStream
	Initial() Response
}

type Compare struct {
	Kind       CompareKind
	ID         ID
	Generation Generation
}

// Effect is a closed internal union; exactly one payload is present.
// It is committed with its causal events, then reconciled idempotently.
// Inactive arms are absent, not null, when a claim crosses a strict JSON port.
type Effect struct {
	PlanLaunch     *LaunchPlanEffect      `json:"PlanLaunch,omitempty"`
	HelperAllocate *HelperLeaseRequest    `json:"HelperAllocate,omitempty"`
	HelperPrepare  *HelperLaunchRequest   `json:"HelperPrepare,omitempty"`
	HelperRelease  *HelperReleaseRequest  `json:"HelperRelease,omitempty"`
	HelperAbort    *HelperAbortRequest    `json:"HelperAbort,omitempty"`
	Context        *InternalIntent        `json:"Context,omitempty"`
	Bootstrap      *BootstrapEffect       `json:"Bootstrap,omitempty"`
	Channel        *ChannelJob            `json:"Channel,omitempty"`
	Worker         *WorkerPlan            `json:"Worker,omitempty"`
	ApplyChange    *ChangeApplyRequest    `json:"ApplyChange,omitempty"`
	Migration      *MigrationApplyRequest `json:"Migration,omitempty"`
	Upgrade        *UpgradeApplyRequest   `json:"Upgrade,omitempty"`
	Rebuild        *RebuildRequest        `json:"Rebuild,omitempty"`
	ID             ID
	OperationID    ID
	Launch         *LaunchSpec    `json:"Launch,omitempty"`
	Stop           *ProcessHandle `json:"Stop,omitempty"`
	Deliver        *Mail          `json:"Deliver,omitempty"`
	Clean          *CleanRequest  `json:"Clean,omitempty"`
	Swap           *ProfileSwap   `json:"Swap,omitempty"`
}

type Transaction struct {
	launchPolicy *launchPolicyFence
	RawRequest   []byte
	Reply        *RPCReply
	Deferred     *DeferredReply
	Internal     *InternalIntent
	Guards       []TransactionGuard
	Writes       StateWrites
	Scope        Scope
	Compare      []Compare
	Events       []Event
	Effects      []Effect
}

type Commit struct {
	Reply     *RPCReply
	Deferred  *DeferredReply
	Operation Operation
	FirstSeq  Sequence
	LastSeq   Sequence
	Replayed  bool
}

type Authenticator interface {
	Authenticate(ctx context.Context, connection ConnectionContext) (Scope, error)
	Authorize(ctx context.Context, scope Scope, request Request) error
	BindLaunch(ctx context.Context, request LaunchBindingRequest) (LaunchPermit, error)
	RevokeLaunch(ctx context.Context, launchID ID) error
}

type HumanVerifier interface {
	Challenge(ctx context.Context, scope Scope, request HumanChallengeRequest) (HumanChallenge, error)
	Confirm(ctx context.Context, scope Scope, request HumanConfirmRequest) (ProofRef, error)
	CheckProof(ctx context.Context, scope Scope, proof ProofRef, target HumanChallengeRequest) (VerifiedHumanProof, error)
}

type Launcher interface {
	Probe(ctx context.Context) (IsolationCapabilities, error)
	Prepare(ctx context.Context, spec LaunchSpec) (PreparedLaunch, error)
	Launch(ctx context.Context, prepared PreparedLaunch, permit LaunchPermit) (ProcessHandle, error)
	Observe(ctx context.Context, process ProcessHandle) (ProcessObservation, error)
	Stop(ctx context.Context, process ProcessHandle, reason string) (ProcessObservation, error)
	Abort(ctx context.Context, prepared PreparedLaunch) error
	Collect(ctx context.Context, leaseID ID, observation ProcessObservation) error
}

// Helper is called only by the service over the authenticated helper channel.
// Release measures registered containment, connections, jobs and writable exports
// under the helper's lease lock. Unknown/nonzero/disagreeing facts retain the
// lease with containment_unknown; caller observations never establish quiescence.
type Helper interface {
	Allocate(ctx context.Context, request HelperLeaseRequest) (HelperLease, error)
	Prepare(ctx context.Context, request HelperLaunchRequest) (PreparedLaunch, error)
	Release(ctx context.Context, request HelperReleaseRequest) (ReleaseReceipt, error)
}

type Runner interface {
	Start(ctx context.Context, request RunnerRequest) (RunnerPlan, error)
	Resume(ctx context.Context, request RunnerRequest) (RunnerPlan, error)
	Turn(ctx context.Context, request RunnerRequest) (RunnerPlan, error)
	SessionFromCapture(ctx context.Context, record CaptureRecord) (Session, error)
	LimitFromCapture(ctx context.Context, record CaptureRecord, exit ProcessObservation) (*LimitSignal, error)
}

type CredentialBroker interface {
	CredentialProjectionBroker
	Eligibility(ctx context.Context, request ProfileEligibilityRequest) (ProfileEligibility, error)
	InjectWorker(ctx context.Context, lease WorkerLease, grants []WorkerCredential) (Injection, error)
	Acquire(ctx context.Context, target LifeRef, grant ProfileGrant) (CredentialSlot, error)
	Release(ctx context.Context, slot CredentialSlot, quiescence ProcessObservation) error
	Room(ctx context.Context, grant ProfileGrant) (Room, error)
	Inject(ctx context.Context, target LifeRef, grants []SecretGrant) (Injection, error)
	RevokeInjection(ctx context.Context, injection Injection, quiescence ProcessObservation) error
}

type SecretBackend interface {
	Fetch(ctx context.Context, grant SecretGrant) (SecretMaterial, error)
	Store(ctx context.Context, info SecretInfo, material SecretMaterial) (SecretInfo, error)
	Revoke(ctx context.Context, info SecretInfo) error
}

type GrantResolver interface {
	Resolve(ctx context.Context, scope Scope, request GrantResolveRequest) (GrantSet, error)
	Materialize(ctx context.Context, grants GrantSet) (Materialization, error)
	Revalidate(ctx context.Context, grants GrantSet) (GrantSet, error)
	BoundChildTest(ctx context.Context, scope Scope, request TestChildRequest) (GrantSet, error)
}

type Judge interface {
	Fit(ctx context.Context, request JudgeRequest) (TokenFit, error)
	Evaluate(ctx context.Context, request JudgeRequest) (JudgeReply, error)
}

// ScopedJudge resolves authoritative context/provider policy and retains audit
// objects around the raw provider port. It resolves EffectivePolicy.Judge at
// Scope.PolicyGeneration and refuses a differing JudgeRequest.Config. Installed
// endpoints supply capability, never policy selection. No provider fallback.
type ScopedJudge interface {
	FitForScope(context.Context, Scope, JudgeRequest) (TokenFit, error)
	EvaluateForScope(context.Context, Scope, JudgeRequest) (JudgeReply, error)
}

// Continuation is service-internal; no lane RPC registers this interface.
type Continuation interface {
	Continue(context.Context, Scope, ContinuationRequest) (Operation, error)
}

type Watchdog interface {
	ObserveLimit(ctx context.Context, signal LimitSignal) (Operation, error)
	Cancel(ctx context.Context, target LifeRef) error
	Reconcile(ctx context.Context, target LifeRef) (Operation, error)
}

type Store interface {
	Transact(ctx context.Context, transaction Transaction) (Commit, error)
	Operation(ctx context.Context, scope Scope, id ID) (Operation, error)
	// Run 0 selects the current run of this authentic life for this internal
	// lookup only; Compare.Generation 0 still means an absent projection.
	Lane(ctx context.Context, scope Scope, target LifeRef) (Lane, error)
	Lanes(ctx context.Context, scope Scope, request ListRequest) (LanePage, error)
	Events(ctx context.Context, scope Scope, request EventTailRequest) (EventPage, error)
	Records(ctx context.Context, scope Scope, request RecordQuery) (RecordPage, error)
	Blob(ctx context.Context, scope Scope, request BlobReadRequest) (BlobChunk, error)
	Launch(ctx context.Context, launchID ID) (LaunchRecord, error)
	Grants(ctx context.Context, grantSetID ID) (GrantSet, error)
	Policy(ctx context.Context, scope Scope) (EffectivePolicy, error)
	Mail(ctx context.Context, scope Scope, request ListRequest) (MailPage, error)
	Change(ctx context.Context, scope Scope, id ID) (ChangeRequest, error)
	PendingEffects(ctx context.Context, request CursorRequest) ([]Effect, error)
	Verify(ctx context.Context, request VerifyRequest) (Verification, error)
}

type DataWorker interface {
	MaterializeLaunch(context.Context, LaunchDataRequest) (LaunchData, error)
	Render(context.Context, ChangeRequest) (ChangeRequest, error)
	Materialize(ctx context.Context, grants GrantSet) (Materialization, error)
	TestChild(ctx context.Context, request TestChildRequest, grants GrantSet) (Operation, error)
	Archive(ctx context.Context, request ArchiveRequest) (ArchiveReceipt, error)
}

type ServiceAPI interface {
	Health(context.Context, Scope, HealthRequest) (Health, error)
	OperationGet(context.Context, Scope, OperationGetRequest) (Operation, error)
	BlobBegin(context.Context, Scope, BlobBeginRequest) (BlobUpload, error)
	BlobChunk(context.Context, Scope, BlobChunk) (BlobUpload, error)
	BlobCommit(context.Context, Scope, BlobCommitRequest) (BlobRef, error)
	BlobRead(context.Context, Scope, BlobReadRequest) (BlobChunk, error)
	StoreVerify(context.Context, Scope, VerifyRequest) (Verification, error)
	StoreRebuild(context.Context, Scope, RebuildRequest) (Operation, error)
}

type IdentityAPI interface {
	IdentitySelf(context.Context, Scope, Empty) (Scope, error)
	HumanChallenge(context.Context, Scope, HumanChallengeRequest) (HumanChallenge, error)
	HumanConfirm(context.Context, Scope, HumanConfirmRequest) (ProofRef, error)
	HumanSession(context.Context, Scope, HumanSessionRequest) (HumanSession, error)
	TicketIssue(context.Context, Scope, TicketIssueRequest) (Ticket, error)
}

type GrantsAPI interface {
	GrantsEnroll(context.Context, Scope, CapabilityEnrollmentRequest) (BlobRef, error)
	GrantsRoot(context.Context, Scope, RootGrantRequest) (GrantSet, error)
	GrantsValidate(context.Context, Scope, GrantValidateRequest) (GrantValidation, error)
	GrantsGet(context.Context, Scope, GrantGetRequest) (GrantSet, error)
	GrantsRevoke(context.Context, Scope, GrantRevokeRequest) (Operation, error)
	GrantsTestChild(context.Context, Scope, TestChildRequest) (Operation, error)
}

type LifecycleAPI interface {
	LaneStart(context.Context, Scope, StartRequest) (Operation, error)
	LaneAdopt(context.Context, Scope, AdoptRequest) (Operation, error)
	LaneResume(context.Context, Scope, ResumeRequest) (Operation, error)
	LaneTurn(context.Context, Scope, TurnRequest) (Operation, error)
	LaneStop(context.Context, Scope, StopRequest) (Operation, error)
	LaneMark(context.Context, Scope, MarkRequest) (Operation, error)
	LaneReview(context.Context, Scope, ReviewRequest) (ReviewReceipt, error)
	LaneClean(context.Context, Scope, CleanRequest) (Operation, error)
	LaneArchive(context.Context, Scope, ArchiveRequest) (ArchiveReceipt, error)
	LaneRestore(context.Context, Scope, RestoreRequest) (RestoreReceipt, error)
	LaneStatus(context.Context, Scope, LifeRef) (Lane, error)
	LaneList(context.Context, Scope, ListRequest) (LanePage, error)
	LaneCheck(context.Context, Scope, LifeRef) (ProcessObservation, error)
	LaneLoop(context.Context, Scope, LoopRequest) (Operation, error)
	LaneAttach(context.Context, Scope, AttachRequest) (StreamFrame, error)
	LaneInput(context.Context, Scope, AttachInputRequest) (Operation, error)
	EventTail(context.Context, Scope, EventTailRequest) (EventPage, error)
}

type MessagingAPI interface {
	MailSend(context.Context, Scope, MailSendRequest) (Mail, error)
	MailList(context.Context, Scope, ListRequest) (MailPage, error)
	ReportSubmit(context.Context, Scope, ReportRequest) (Mail, error)
}

type PolicyAPI interface {
	PolicyGet(context.Context, Scope, PolicyGetRequest) (EffectivePolicy, error)
	PolicyEvaluate(context.Context, Scope, PolicyEvaluateRequest) (PolicyDecision, error)
	ConfigRead(context.Context, Scope, ConfigReadRequest) (ConfigView, error)
	ConfigValidate(context.Context, Scope, Empty) (OrgValidation, error)
}

type GuidanceAPI interface {
	GuidanceSelect(context.Context, Scope, GuidanceRequest) (Guidance, error)
}

type JudgeAPI interface {
	JudgeAsk(context.Context, Scope, JudgeRequest) (JudgeReply, error)
	JudgeList(context.Context, Scope, Empty) (ConfigView, error)
}

type TemplatesAPI interface {
	BriefRender(context.Context, Scope, TemplateRequest) (Briefing, error)
	BriefStart(context.Context, Scope, BriefingRequest) (Briefing, error)
	OrgValidate(context.Context, Scope, OrgValidateRequest) (OrgValidation, error)
	OrgBootstrap(context.Context, Scope, BootstrapRequest) (Operation, error)
}

type ApprovalAPI interface {
	OrgChangePropose(context.Context, Scope, ChangeProposeRequest) (ChangeRequest, error)
	OrgChangeGet(context.Context, Scope, ChangeGetRequest) (ChangeRequest, error)
	OrgChangeApprove(context.Context, Scope, ChangeApproveRequest) (ChangeApproval, error)
	OrgChangeApply(context.Context, Scope, ChangeApplyRequest) (ChangeReceipt, error)
}

type SecretsAPI interface {
	SecretKey(context.Context, Scope, Empty) (SecretKey, error)
	SecretStage(context.Context, Scope, SecretStageRequest) (SecretStage, error)
	SecretImport(context.Context, Scope, SecretImportRequest) (SecretInfo, error)
	SecretRotate(context.Context, Scope, SecretRotateRequest) (SecretInfo, error)
	SecretRevoke(context.Context, Scope, SecretRevokeRequest) (Operation, error)
	SecretList(context.Context, Scope, Empty) (SecretList, error)
}

type DashboardAPI interface {
	DashboardTree(context.Context, Scope, DashboardQuery) (TreeView, error)
	DashboardRaw(context.Context, Scope, DashboardQuery) (RawView, error)
	DashboardDecisions(context.Context, Scope, DashboardQuery) (DecisionView, error)
	DashboardRefusals(context.Context, Scope, DashboardQuery) (RefusalView, error)
	DashboardPlugins(context.Context, Scope, DashboardQuery) (ResourceView, error)
	DashboardResources(context.Context, Scope, DashboardQuery) (ResourceView, error)
	DashboardLifecycle(context.Context, Scope, DashboardQuery) (LanePage, error)
	DashboardApprovals(context.Context, Scope, DashboardQuery) (ApprovalView, error)
}

type IntegrateAPI interface {
	RecordsQuery(context.Context, Scope, RecordQuery) (RecordPage, error)
	RecordsGet(context.Context, Scope, RecordGetRequest) (Record, error)
	RecordsAppend(context.Context, Scope, RecordAppendRequest) (Record, error)
	DecisionsMutate(context.Context, Scope, DecisionMutateRequest) (Record, error)
	RecordsImport(context.Context, Scope, TransferRequest) (Operation, error)
	RecordsExport(context.Context, Scope, RecordQuery) (BlobRef, error)
	BoxLaunch(context.Context, Scope, BoxLaunchRequest) (Box, error)
	BoxRun(context.Context, Scope, BoxRunRequest) (Operation, error)
	BoxHarvest(context.Context, Scope, BoxControlRequest) (BlobRef, error)
	BoxEnd(context.Context, Scope, BoxControlRequest) (Operation, error)
	BoxList(context.Context, Scope, ListRequest) (BoxPage, error)
}

type MigrationAPI interface {
	MigrationPlan(context.Context, Scope, MigrationPlanRequest) (MigrationPlan, error)
	MigrationApply(context.Context, Scope, MigrationApplyRequest) (Operation, error)
}

type PackagingAPI interface {
	UpgradePlan(context.Context, Scope, UpgradePlanRequest) (UpgradePlan, error)
	UpgradeApply(context.Context, Scope, UpgradeApplyRequest) (Operation, error)
}

type AdminAPI interface {
	Doctor(context.Context, Scope, Empty) (Health, error)
}
