package api

import (
	"encoding/json"
	"reflect"
)

type Event struct {
	Schema          uint32          `json:"schema"`
	ID              ID              `json:"id"`
	Config          string          `json:"config"`
	Seq             Sequence        `json:"seq"`
	Kind            EventKind       `json:"kind"`
	Actor           Actor           `json:"actor"`
	RequestedBy     Actor           `json:"requested_by"`
	RequestID       ID              `json:"request_id"`
	OperationID     ID              `json:"operation_id"`
	LifeID          ID              `json:"life_id,omitempty"`
	Run             RunNumber       `json:"run,omitempty"`
	LogicalTurnID   ID              `json:"logical_turn_id,omitempty"`
	ParentLifeID    ID              `json:"parent_life_id,omitempty"`
	RootLifeID      ID              `json:"root_life_id,omitempty"`
	StarterChain    []ID            `json:"starter_chain"`
	StarterEventSeq Sequence        `json:"starter_event_seq"`
	RecordedAt      Timestamp       `json:"recorded_at"`
	RequestedAt     Timestamp       `json:"requested_at"`
	ObservedAt      Timestamp       `json:"observed_at"`
	Origin          string          `json:"origin"`
	Payload         json.RawMessage `json:"payload"`
}

type ServiceEvent struct {
	Version             string `json:"version"`
	ArtifactSHA256      Digest `json:"artifact_sha256"`
	RecoveredOperations []ID   `json:"recovered_operations"`
}

type OperationEvent struct {
	Operation     Operation `json:"operation"`
	RequestSHA256 Digest    `json:"request_sha256"`
}

type LaunchEvent struct {
	Task                  BlobRef      `json:"task"`
	LaunchID              ID           `json:"launch_id"`
	Lane                  Lane         `json:"lane"`
	GrantSetID            ID           `json:"grant_set_id"`
	GrantsSHA256          Digest       `json:"grants_sha256"`
	PolicyGeneration      Generation   `json:"policy_generation"`
	PromptTemplate        TemplateRef  `json:"prompt_template"`
	TaskSHA256            Digest       `json:"task_sha256"`
	Prompt                BlobRef      `json:"prompt"`
	BoundaryBackend       string       `json:"boundary_backend"`
	EndpointGeneration    Generation   `json:"endpoint_generation"`
	TaskSecretNames       []string     `json:"task_secret_names"`
	TaskSecretFileNames   []string     `json:"task_secret_file_names"`
	SecretGrantIDs        []ID         `json:"secret_grant_ids"`
	SecretSourceVersions  []string     `json:"secret_source_versions"`
	InjectionOutcome      string       `json:"injection_outcome"`
	Trigger               Trigger      `json:"trigger"`
	ProfileContinuationOf RunNumber    `json:"profile_continuation_of,omitempty"`
	ProfileSwap           *ProfileSwap `json:"profile_swap,omitempty"`
}

type LaunchFailedEvent struct {
	LaunchID      ID     `json:"launch_id"`
	Stage         string `json:"stage"`
	Error         Error  `json:"error"`
	AgentExecuted bool   `json:"agent_executed"`
}

type RunEndEvent struct {
	LaunchID            ID                 `json:"launch_id"`
	Reason              string             `json:"reason"`
	Observation         ProcessObservation `json:"observation"`
	ProfileContinuation bool               `json:"profile_continuation"`
	BudgetRemaining     Budget             `json:"budget_remaining"`
}

type StateEvent struct {
	From       string     `json:"from"`
	To         string     `json:"to"`
	Generation Generation `json:"generation"`
	ReviewID   ID         `json:"review_id,omitempty"`
	Reason     *BlobRef   `json:"reason,omitempty"`
}

type UnownedRetained struct {
	Objects int   `json:"objects"`
	Bytes   int64 `json:"bytes"`
}

type CleanEvent struct {
	ArchiveReceipt    ArchiveReceipt     `json:"archive_receipt"`
	RemovedObjectIDs  []ID               `json:"removed_object_ids"`
	RetainedObjectIDs []ID               `json:"retained_object_ids"`
	UnownedRetained   UnownedRetained    `json:"unowned_retained"`
	Quiescence        ProcessObservation `json:"quiescence"`
}

type TurnEvent struct {
	Task    BlobRef `json:"task"`
	Trigger Trigger `json:"trigger"`
	Prompt  BlobRef `json:"prompt"`
	Status  string  `json:"status"`
	MailIDs []ID    `json:"mail_ids"`
}

type GrantEvent struct {
	GrantSet GrantSet `json:"grant_set"`
	Reason   *BlobRef `json:"reason,omitempty"`
}

type SecretEvent struct {
	Names    []string `json:"names"`
	Versions []string `json:"versions"`
	GrantIDs []ID     `json:"grant_ids"`
	Outcome  string   `json:"outcome"`
	KeyID    ID       `json:"key_id,omitempty"`
}

type CredentialEvent struct {
	Slot    CredentialSlot `json:"slot"`
	Outcome string         `json:"outcome"`
}

type WatchdogEvent struct {
	Signal          *LimitSignal `json:"signal,omitempty"`
	Swap            *ProfileSwap `json:"swap,omitempty"`
	Reason          string       `json:"reason"`
	RetryAfterMS    int64        `json:"retry_after_ms"`
	BudgetRemaining Budget       `json:"budget_remaining"`
}

type ChangeEvent struct {
	Change   ChangeRequest   `json:"change"`
	Approval *ChangeApproval `json:"approval,omitempty"`
	Receipt  *ChangeReceipt  `json:"receipt,omitempty"`
	Reason   string          `json:"reason"`
}

type MigrationEvent struct {
	Plan             MigrationPlan `json:"plan"`
	Manifest         BlobRef       `json:"manifest"`
	LegacyEventCount uint64        `json:"legacy_event_count"`
}

type WorkerEvent struct {
	WorkerID ID       `json:"worker_id"`
	Kind     string   `json:"kind"`
	Input    BlobRef  `json:"input"`
	Output   *BlobRef `json:"output,omitempty"`
	Status   string   `json:"status"`
	Error    *Error   `json:"error,omitempty"`
}

// EventSchemas is the closed payload catalog; entries never confer authority on observations.
var EventSchemas = map[EventKind]reflect.Type{
	"spend.reconciled":    reflect.TypeFor[SpendJournal](),
	"spend.recorded":      reflect.TypeFor[SpendRecorded](),
	"spend.stopped":       reflect.TypeFor[SpendJournal](),
	"spend.unknown":       reflect.TypeFor[SpendJournal](),
	"loop.reserved":       reflect.TypeFor[LoopTurnCause](),
	"launch.planned":      reflect.TypeFor[LaunchPlanRecord](),
	"capture.bound":       reflect.TypeFor[CaptureBinding](),
	"capture.refused":     reflect.TypeFor[CaptureBinding](),
	"capture.closed":      reflect.TypeFor[CaptureAppendReceipt](),
	"human.proof.used":    reflect.TypeFor[ProofUseReceipt](),
	"identity.bound":      reflect.TypeFor[LaunchRecord](),
	"identity.revoked":    reflect.TypeFor[LaunchRecord](),
	"runner.session":      reflect.TypeFor[Session](),
	"helper.allocated":    reflect.TypeFor[HelperLease](),
	"helper.released":     reflect.TypeFor[ReleaseReceipt](),
	"org.bootstrapped":    reflect.TypeFor[ConfigView](),
	"service.started":     reflect.TypeFor[ServiceEvent](),
	"service.recovered":   reflect.TypeFor[ServiceEvent](),
	"operation.accepted":  reflect.TypeFor[OperationEvent](),
	"operation.completed": reflect.TypeFor[OperationEvent](),
	"operation.failed":    reflect.TypeFor[OperationEvent](),
	"human.challenge":     reflect.TypeFor[HumanChallenge](),
	"human.confirmed":     reflect.TypeFor[ProofRef](),
	"human.session":       reflect.TypeFor[HumanSession](),
	"human.enrollment":    reflect.TypeFor[HumanAdmission](),
	"ticket.issued":       reflect.TypeFor[Ticket](),
	"ticket.redeemed":     reflect.TypeFor[Ticket](),
	"lane.created":        reflect.TypeFor[LaunchEvent](),
	"lane.adopted":        reflect.TypeFor[LaunchEvent](),
	"launch.prepared":     reflect.TypeFor[LaunchEvent](),
	"launch.failed":       reflect.TypeFor[LaunchFailedEvent](),
	"lane.started":        reflect.TypeFor[LaunchEvent](),
	"lane.resumed":        reflect.TypeFor[LaunchEvent](),
	"lane.turn":           reflect.TypeFor[TurnEvent](),
	"prompt.observed":     reflect.TypeFor[TurnEvent](),
	"lane.stopping":       reflect.TypeFor[StateEvent](),
	"lane.ended":          reflect.TypeFor[RunEndEvent](),
	"lane.lost":           reflect.TypeFor[RunEndEvent](),
	"lane.state":          reflect.TypeFor[StateEvent](),
	"lane.policy":         reflect.TypeFor[PolicyAdvanceEvent](),
	"lane.cleaned":        reflect.TypeFor[CleanEvent](),
	"lane.reviewed":       reflect.TypeFor[ReviewReceipt](),
	"lane.loop":           reflect.TypeFor[LoopRequest](),
	"run.observed":        reflect.TypeFor[ProcessObservation](),
	"capture.appended":    reflect.TypeFor[CaptureRecord](),
	"capture.framed":      reflect.TypeFor[CaptureRecord](),
	"capture.gap":         reflect.TypeFor[CaptureGap](),
	"grants.issued":       reflect.TypeFor[GrantEvent](),
	"grants.revoked":      reflect.TypeFor[GrantEvent](),
	"data.materialized":   reflect.TypeFor[Materialization](),
	"secret.imported":     reflect.TypeFor[SecretEvent](),
	"secret.rotated":      reflect.TypeFor[SecretEvent](),
	"secret.revoked":      reflect.TypeFor[SecretEvent](),
	"secret.injected":     reflect.TypeFor[Injection](),
	"credential.leased":   reflect.TypeFor[CredentialEvent](),
	"credential.released": reflect.TypeFor[CredentialEvent](),
	"watchdog.limit":      reflect.TypeFor[WatchdogEvent](),
	"watchdog.waiting":    reflect.TypeFor[WatchdogEvent](),
	"watchdog.swapped":    reflect.TypeFor[WatchdogEvent](),
	"watchdog.cancelled":  reflect.TypeFor[WatchdogEvent](),
	"mail.queued":         reflect.TypeFor[Mail](),
	"mail.delivered":      reflect.TypeFor[MailReceipt](),
	"mail.returned":       reflect.TypeFor[MailReceipt](),
	"report.submitted":    reflect.TypeFor[Mail](),
	"channel.delivered":   reflect.TypeFor[Delivery](),
	"channel.failed":      reflect.TypeFor[Delivery](),
	"policy.evaluated":    reflect.TypeFor[PolicyDecision](),
	"judge.completed":     reflect.TypeFor[JudgeReply](),
	"guidance.selected":   reflect.TypeFor[Guidance](),
	"org.change.proposed": reflect.TypeFor[ChangeEvent](),
	"org.change.approved": reflect.TypeFor[ChangeEvent](),
	"org.change.applied":  reflect.TypeFor[ChangeEvent](),
	"org.change.rejected": reflect.TypeFor[ChangeEvent](),
	"archive.verified":    reflect.TypeFor[ArchiveReceipt](),
	"blob.committed":      reflect.TypeFor[BlobRef](),
	"record.appended":     reflect.TypeFor[Record](),
	"decision.changed":    reflect.TypeFor[Record](),
	"migration.completed": reflect.TypeFor[MigrationEvent](),
	"upgrade.applied":     reflect.TypeFor[UpgradePlan](),
	"worker.completed":    reflect.TypeFor[WorkerEvent](),
	"worker.failed":       reflect.TypeFor[WorkerEvent](),
	"box.changed":         reflect.TypeFor[Box](),
}
