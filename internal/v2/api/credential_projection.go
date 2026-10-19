package api

import (
	"context"
	"os"
)

// Private native control ports only. No credential value, source pathname,
// content digest or descriptor number enters a public RPC or durable record.
type CredentialProjectionRequest struct {
	Cause             InternalIntent
	Claim             EffectLease
	Handoff           PreparedSpecHandoff
	Prepared          PreparedLaunch
	Lease             HelperLease
	Home              PrivateHomeBinding
	Worker            *WorkerLease       `json:"Worker,omitempty"`
	WorkerCredentials []WorkerCredential `json:"WorkerCredentials,omitempty"`
}

// Private job metadata selected from the sealed input and enrolled runtime.
// This is not a caller-selected list and contains no credential values.
type CredentialWorkerSelection struct {
	Lease       WorkerLease
	Credentials []WorkerCredential
}

type CredentialWorkerSelectionStore interface {
	CredentialWorkerSelection(context.Context, Scope, PreparedSpecHandoff) (CredentialWorkerSelection, error)
}

type CredentialWorkerRegistrationStore interface {
	RegisterCredentialWorker(context.Context, Scope, PreparedSpecHandoff) error
}

type CredentialWorkerSelector interface {
	SelectCredentialWorker(context.Context, PreparedSpecHandoff) (CredentialWorkerSelection, error)
}

type CredentialProjectionReservationBroker interface {
	ReserveCredentials(context.Context, VerifiedPeer, CredentialProjectionRequest) (CredentialProjectionRecord, error)
}

// Existing sealed usage input schema, shared by the broker and protected store.
type UsageCredentialInput struct {
	Schema            string             `json:"schema"`
	Request           UsageWindowRequest `json:"request"`
	VendorProfile     string             `json:"vendor_profile"`
	ProfileGeneration Generation         `json:"profile_generation"`
	Source            SecretGrant        `json:"source"`
}

// Source versions are broker-owned inventory facts, never hashes of plaintext.
// Key is a slot ID for a profile, otherwise its selected secret grant/name key.
type CredentialSourceVersion struct {
	Key        ID
	Generation Generation
	Version    string
	Revoked    bool
}

type CredentialTarget struct {
	Key             ID
	GrantID         ID
	SlotID          ID
	SourceHandle    ID
	Version         string
	Delivery        string
	RelativePath    string
	EnvironmentName string
	FileMode        uint32
}

// Identity resolves both pinned executables and real native peer lifetimes;
// the store/broker resolves current versions, grants, claim and cancellation.
// These observations are not authority when deserialized from a caller.
type CredentialProjectionAuthority struct {
	ID                     ID
	Generation             Generation
	Request                CredentialProjectionRequest
	Targets                []CredentialTarget
	Sources                []CredentialSourceVersion
	Helper                 Executable
	Broker                 Executable
	HelperPeer             PeerFacts
	BrokerPeer             PeerFacts
	ServiceUID             uint32
	InstallationGeneration Generation
	BootID                 string
	Revoked                bool
}

// Transfer is direct broker-worker to root-helper SCM_RIGHTS, never the lane,
// public transport, service UID, argv, JSON, a blob, or /proc/self/fd lookup.
// Receiver owns received duplicates immediately, including on partial failure.
// Broker retains its originals until AcknowledgeCredentials durably succeeds.
type CredentialTransfer struct {
	Authority CredentialProjectionAuthority
	Files     []*os.File `json:"-"`
}

// Native helper fstat/fcntl and held-directory observations. The API validator
// correlates them; it performs no I/O and proves no kernel fact by itself.
type CredentialDescriptorFact struct {
	ObjectID    string
	OwnerUID    uint32
	Mode        uint32
	Size        int64
	Links       uint64
	Regular     bool
	ReadOnly    bool
	CloseOnExec bool
	// WritableHandles counts open write-access aliases in the observing Linux
	// process's FD table. Immutable write seals independently prohibit writes
	// through aliases outside that observed scope.
	WritableHandles *uint64
}

type CredentialHeldTarget struct {
	Target           CredentialTarget
	SourceObjectID   string
	ObjectID         string
	RootID           ID
	HomeGeneration   Generation
	OwnerUID         uint32
	Mode             uint32
	ParentMode       uint32
	Links            uint64
	WritableByOthers bool
	ReadOnlyView     bool
}

type CredentialProjectionReceipt struct {
	ProjectionID      ID
	Generation        Generation
	Prepared          PreparedLaunch
	HelperLeaseID     ID
	SpecSHA256        Digest
	Home              PrivateHomeBinding
	CancellationEpoch Generation
	Targets           []CredentialHeldTarget
	HeldDescriptors   *uint64
	InheritedSources  *uint64
	GateClosed        bool
	ObservedAt        Timestamp
}

// Reserved -> held -> withdrawing -> withdrawn, with one revision per move.
// A refusal, source revocation, cancellation or restart uncertainty fences the
// projection before cleanup. A missing record never means an empty credential.
type CredentialProjectionRecord struct {
	Authority  CredentialProjectionAuthority
	Generation Generation
	State      string
	// Revoked is a monotonic withdrawal decision, separate from the immutable
	// authority snapshot and from an ordinary containment stop.
	Revoked bool                         `json:"Revoked,omitempty"`
	Receipt *CredentialProjectionReceipt `json:"Receipt,omitempty"`
	Fence   *CredentialWithdrawalRequest `json:"Fence,omitempty"`
	// An escalation retains the exact first fence for restart verification.
	PriorFence *CredentialWithdrawalRequest `json:"PriorFence,omitempty"`
	Withdrawal *CredentialWithdrawalReceipt `json:"Withdrawal,omitempty"`
}

type CredentialGateRequest struct {
	ProjectionID       ID
	ExpectedGeneration Generation
	Open               HelperOpenRequest
}

// A live, nonserializable outside-worker lock over this projection and its
// canonical refresh lease. Helper holds it together with its lease lock through
// the existing one-use OpenGate exec acknowledgement, then closes it on all paths.
// Withdrawal fences new locks and waits for an acquired guard before stopping.
type CredentialGateGuard interface {
	Projection() CredentialProjectionRecord
	Check(context.Context) error
	Close() error
}

type CredentialWithdrawalRequest struct {
	ProjectionID       ID
	ExpectedGeneration Generation
	Cause              InternalIntent
	Reason             string
}

// CredentialStopReason is the explicit containment stop's withdrawal reason.
// Revocation keeps its distinct "revoked" fence and cannot use stop completion.
const CredentialStopReason = "cancelled"

// Helper counts describe its own held objects. The outside broker measures its
// tracked original exports with Stat and independently probes the kernel locks
// for its selected canonical refresh leases after closing them. Durable slot
// ownership is retained until store completion; journal metadata is not a live
// count. Unknown original-process inventory refuses. Neither producer copies
// caller claims.
type CredentialWithdrawalReceipt struct {
	ProjectionID       ID
	Generation         Generation
	Cause              InternalIntent
	Prepared           PreparedLaunch
	HelperLeaseID      ID
	Home               PrivateHomeBinding
	Observation        ProcessObservation
	HelperDescriptors  *uint64
	ProjectedFiles     *uint64
	EnvironmentBuffers *uint64
	OpenGates          *uint64
	BrokerDescriptors  *uint64 `json:"BrokerDescriptors,omitempty"`
	RefreshLeases      *uint64 `json:"RefreshLeases,omitempty"`
	RotationRequired   bool
	// Nil retains the conservative exposure rule. A native helper supplies
	// false only after closing a gate whose one-use permit was never consumed.
	AgentExecuted *bool `json:"AgentExecuted,omitempty"`
	ObservedAt    Timestamp
}

type CredentialWithdrawalReader interface {
	ReadCredentialWithdrawal(context.Context, CredentialProjectionRecord) (CredentialWithdrawalReceipt, error)
}

// Optional Codex refresh return after a normal, measured stop. This is another
// direct helper-to-broker anonymous descriptor transfer, never a lane pathname.
// The helper owns its export until acknowledgement; the broker owns and closes
// every received duplicate on both success and refusal.
type CredentialRefresh struct {
	ProjectionID             ID
	ExpectedGeneration       Generation
	SlotID                   ID
	ExpectedSourceGeneration Generation
	Observation              ProcessObservation
	Fact                     CredentialDescriptorFact
	File                     *os.File `json:"-"`
}

type CredentialProjectionBroker interface {
	TransferCredentials(context.Context, VerifiedPeer, CredentialProjectionRequest) (CredentialTransfer, error)
	AcknowledgeCredentials(context.Context, CredentialProjectionReceipt) (CredentialProjectionRecord, error)
	LockCredentialProjection(context.Context, CredentialGateRequest) (CredentialGateGuard, error)
	BeginCredentialWithdrawal(context.Context, CredentialWithdrawalRequest) (CredentialProjectionRecord, error)
	AcceptCredentialRefresh(context.Context, VerifiedPeer, CredentialRefresh) (CredentialSourceVersion, error)
	FinishCredentialWithdrawal(context.Context, CredentialProjectionRecord, CredentialWithdrawalReceipt) (CredentialProjectionRecord, error)
}

type CredentialProjectionControl interface {
	InspectCredentialTransfer(context.Context, CredentialTransfer) ([]CredentialDescriptorFact, error)
	ProjectCredentials(context.Context, CredentialTransfer) (CredentialProjectionReceipt, error)
	ObserveCredentials(context.Context, ID) (CredentialProjectionReceipt, error)
	WithdrawCredentials(context.Context, CredentialProjectionRecord) (CredentialWithdrawalReceipt, error)
	CollectCredentialRefresh(context.Context, CredentialProjectionRecord) (CredentialRefresh, error)
}

type CredentialProjectionIdentity interface {
	AuthorizeCredentialProjection(context.Context, VerifiedPeer, CredentialProjectionRequest) (CredentialProjectionAuthority, error)
	CheckLaunchCredentials(context.Context, LaunchBindingRequest) (CredentialProjectionRecord, error)
}

// Break the helper/identity/broker cycle at the first credential-bearing
// Prepare or recovery Launch. Binding is one successful use with nonnil
// clients. A failed attempt is retryable only via CredentialBindingFailure
// certifying Unbound with an unavailable, retryable owning error; all partial,
// uncertain and permanent failures remain fenced for this process lifetime.
type CredentialProjectionBinder interface {
	BindCredentialProjection(CredentialProjectionBroker, CredentialProjectionIdentity) error
}

type CredentialProjectionStore interface {
	CredentialProjection(context.Context, string, ID) (CredentialProjectionRecord, error)
	ReserveCredentialProjection(context.Context, Scope, CredentialProjectionRequest) (CredentialProjectionRecord, error)
	CommitCredentialProjection(context.Context, Scope, CredentialProjectionReceipt) (CredentialProjectionRecord, error)
	FenceCredentialProjection(context.Context, Scope, CredentialWithdrawalRequest) (CredentialProjectionRecord, error)
	CompleteCredentialWithdrawal(context.Context, Scope, CredentialWithdrawalReceipt) (CredentialProjectionRecord, error)
}
