package api

import "context"

type TaskCounters struct {
	Failures uint64 `json:"failures"`
	Retries  uint64 `json:"retries"`
}

type TurnSnapshot struct {
	Target           LifeRef
	LogicalTurnID    ID
	Task             BlobRef
	Prompt           *BlobRef
	Trigger          Trigger
	PolicyGeneration Generation
	Generation       Generation
	GuidanceID       ID
	MailIDs          []ID
	Status           string
	CreatedAt        Timestamp
	LastSeq          Sequence
}

type DecisionAuthority struct {
	Kind          string     `json:"kind"`
	ReceiptID     ID         `json:"receipt_id"`
	OrgGeneration Generation `json:"org_generation"`
	SourceSeq     Sequence   `json:"source_seq"`
}

type DecisionApplicability struct {
	Levels     []int    `json:"levels"`
	Roles      []string `json:"roles"`
	ProjectIDs []ID     `json:"project_ids"`
	LifeIDs    []ID     `json:"life_ids"`
}

type DecisionDocument struct {
	Schema      string                `json:"schema"`
	Text        string                `json:"text"`
	EffectiveAt Timestamp             `json:"effective_at"`
	AppliesTo   DecisionApplicability `json:"applies_to"`
	Binding     bool                  `json:"binding"`
}

type DecisionProjection struct {
	RecordID     ID
	Candidate    DecisionCandidate
	Status       string
	SupersedesID ID
}

type DecisionQuery struct {
	Target     LifeRef
	SnapshotID ID
	Kind       string
	Cursor     string
	Limit      int
}

type DecisionPage struct {
	SnapshotID       ID
	PolicyGeneration Generation
	AsOf             Timestamp
	Candidates       []DecisionCandidate
	Cursor           string
	Complete         bool
}

type GuidanceReservationRequest struct {
	AttemptID              ID
	ExpectedTurnGeneration Generation
	CancellationEpoch      Generation
	MaxCostMicros          int64
	Target                 LifeRef
	LogicalTurnID          ID
	ExpectedTask           BlobRef
	PolicyGeneration       Generation
	CandidateSnapshotID    ID
	Deadline               Timestamp
}

type GuidanceReservation struct {
	// Only the protected launch reservation port sets these internal bindings.
	LaunchReservationID ID
	LaunchEffectID      ID
	TurnGeneration      Generation
	Config              string
	// Acquired is invocation-specific, true only for the atomic winning call;
	// reads/replays/awaiters return false, even for an identical AttemptID.
	Acquired            bool
	OwnerAttemptID      ID
	OwnerOperationID    ID
	OwnerRequestID      ID
	OwnerKey            RequestKey
	RequestedBy         Actor
	CancellationEpoch   Generation
	MaxCostMicros       int64
	BindingItems        []GuidanceItem
	ID                  ID
	Target              LifeRef
	LogicalTurnID       ID
	Task                BlobRef
	PolicyGeneration    Generation
	CandidateSnapshotID ID
	Generation          Generation
	ClaimID             ID
	Status              string
	ReservedAt          Timestamp
	Deadline            Timestamp
	Result              *Guidance
}

type GuidanceSelection struct {
	AttemptID          ID
	ReservationID      ID
	ClaimID            ID
	ExpectedGeneration Generation
	Result             Guidance
}

type JudgeAudit struct {
	ID          ID
	Request     BlobRef
	Reply       JudgeReply
	Fit         TokenFit
	StartedAt   Timestamp
	CompletedAt Timestamp
}

type ProfileEligibilityRequest struct {
	Target      LifeRef
	GrantSetID  ID
	FromGrantID ID
	ToGrantID   ID
	Driver      Driver
	Model       string
	Session     Session
	HistoryID   ID
}

type ProfileEligibility struct {
	ID         ID
	Request    ProfileEligibilityRequest
	Compatible bool
	Reason     string
	Evidence   BlobRef
	CheckedAt  Timestamp
	ExpiresAt  Timestamp
}

type ContinuationRequest struct {
	IntentID ID
	// Swap is the sole submitted copy of the life/epoch/eligibility fence.
	// Lifecycle compares it with the durable intent under the per-life lock
	// and derives/checks logical turn and both run numbers from the life.
	Swap ProfileSwap
}

type ContinuationIntent struct {
	ID                 ID
	Target             LifeRef
	LogicalTurnID      ID
	ExpectedGeneration Generation
	CancellationEpoch  Generation
	Generation         Generation
	Status             string
	Swap               ProfileSwap
	Eligibility        ProfileEligibility
	Slot               *CredentialSlot
	// Store-assigned at pending selection; Swap.OperationID must be identical.
	// Continue returns this same operation through claim, launch and recovery.
	OperationID ID
}

type ContinuationClaimRequest struct {
	Intent  InternalIntent
	Request ContinuationRequest
}

type TurnStore interface {
	AwaitGuidance(context.Context, Scope, GuidanceAwaitRequest) (GuidanceReservation, error)
	Turn(context.Context, Scope, LifeRef, ID) (TurnSnapshot, error)
	// Decision returns the scoped retained projection, including superseded
	// history, so metadata/supersession preserve original authority and content.
	Decision(context.Context, Scope, ID) (DecisionProjection, error)
	DecisionCandidates(context.Context, Scope, DecisionQuery) (DecisionPage, error)
	ReserveGuidance(context.Context, Scope, GuidanceReservationRequest) (GuidanceReservation, error)
	GuidanceReservation(context.Context, Scope, LifeRef, ID) (GuidanceReservation, error)
	JudgeAudit(context.Context, Scope, ID) (JudgeAudit, error)
	ClaimContinuation(context.Context, Scope, ContinuationClaimRequest) (ContinuationIntent, error)
	ContinuationIntent(context.Context, Scope, ID) (ContinuationIntent, error)
}
