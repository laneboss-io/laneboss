package api

import "context"

type DecisionAnswer struct {
	DecisionID ID                `json:"decision_id"`
	Source     SourceRef         `json:"source"`
	Content    BlobRef           `json:"content"`
	Authority  DecisionAuthority `json:"authority"`
}

type ChannelDestination struct {
	ID                ID
	Transport         string
	EndpointID        ID
	CredentialHandle  ID
	DeliverySemantics string
}

type EnrolledChannel struct {
	Runtime      *ChannelRuntime
	ID           ID
	Config       string
	Generation   Generation
	Source       SourceRef
	Destinations []ChannelDestination
	ExpiresAt    Timestamp
	Revoked      bool
}

type WorkerLease struct {
	ID              ID
	Kind            string
	Target          LifeRef
	OperationID     ID
	EffectID        ID
	Input           BlobRef
	RuntimeManifest BlobRef
	GrantSetID      ID
	Generation      Generation
	ExpiresAt       Timestamp
	ConsumedBy      ID
}

type WorkerCredential struct {
	Name         string
	SourceHandle ID
	Version      string
	Delivery     string
	Target       string
}

type ChannelJob struct {
	Runtime                *ChannelRuntime
	Payload                BlobRef
	Lease                  WorkerLease
	ChannelID              ID
	ChannelGeneration      Generation
	DestinationID          ID
	MailID                 ID
	Content                BlobRef
	Artifacts              []BlobRef
	ProviderIdempotencyKey ID
}

type DeliveryTurnRequest struct {
	Lease              EffectLease
	Target             LifeRef
	LogicalTurnID      ID
	MailIDs            []ID
	ExpectedGeneration Generation
	CancellationEpoch  Generation
}

type DeliveryBatch struct {
	Intent        InternalIntent
	Target        LifeRef
	LogicalTurnID ID
	Mail          []Mail
	Generation    Generation
}

type DeliveryReceiptRequest struct {
	Intent             InternalIntent
	MailID             ID
	ExpectedGeneration Generation
	Receipt            MailReceipt
	CaptureIDs         []ID
}

type MailDelivery interface {
	BeginDelivery(context.Context, Scope, DeliveryTurnRequest) (DeliveryBatch, error)
	RecordDelivery(context.Context, Scope, DeliveryReceiptRequest) (Operation, error)
	DeliverChannel(context.Context, Scope, ChannelJob) (Delivery, error)
	ReconcileChannel(context.Context, Scope, ChannelJob) (Delivery, error)
}

type ChannelJobRequest struct {
	Lease          EffectLease
	MailID         ID
	ChannelGrantID ID
	DestinationID  ID
}

type DeliveryStore interface {
	Channel(context.Context, Scope, ID) (EnrolledChannel, error)
	ChannelJob(context.Context, Scope, ChannelJobRequest) (ChannelJob, error)
	WorkerLease(context.Context, Scope, ID) (WorkerLease, error)
	MailForTurn(context.Context, Scope, DeliveryTurnRequest) (DeliveryBatch, error)
	Relation(context.Context, Scope, ID) (RelationFacts, error)
}

type RelationFacts struct {
	LifeID           ID
	ParentLifeID     ID
	RootLifeID       ID
	StarterChain     []ID
	Level            int
	Role             string
	State            string
	Generation       Generation
	GrantSetID       ID
	PolicyGeneration Generation
	Revoked          bool
}

// Intake is service-internal. Received channel/sheet content remains inert
// until verified against current enrollment and, for decisions, human proof.
type ExternalMessage struct {
	ChannelID          ID
	ChannelGeneration  Generation
	DestinationID      ID
	RemoteSenderID     ID
	RemoteMessageID    ID
	Content            BlobRef
	ReceiveEvidence    BlobRef
	ContinuationCursor string
}

type OwnerSheetInput struct {
	SheetID            ID
	Snapshot           BlobRef
	ExpectedGeneration Generation
}

type OwnerIntake interface {
	ReceiveExternal(context.Context, Scope, WorkerLease, ExternalMessage) (Mail, error)
	ImportOwnerSheet(context.Context, Scope, WorkerLease, OwnerSheetInput) (Operation, error)
}
