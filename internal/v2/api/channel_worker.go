package api

import "context"

// This capability comes from protected channel/runtime enrollment, never a
// mail body, task, URL, executable selector or caller-supplied WorkerPlan.
type ChannelRuntime struct {
	Executable Executable
	Manifest   BlobRef
	Reconcile  string
}

type ChannelPrepareRequest struct {
	OperationID    ID
	ChannelGrantID ID
	DestinationID  ID
}

type ChannelExecution struct {
	Job     ChannelJob
	Handoff PreparedSpecHandoff
	Binding LaunchBindingRequest
}

type ChannelSendInput struct {
	Schema                 string     `json:"schema"`
	LeaseID                ID         `json:"lease_id"`
	MailID                 ID         `json:"mail_id"`
	ChannelID              ID         `json:"channel_id"`
	ChannelGeneration      Generation `json:"channel_generation"`
	DestinationID          ID         `json:"destination_id"`
	ProviderIdempotencyKey ID         `json:"provider_idempotency_key"`
	Payload                BlobRef    `json:"payload"`
	Content                BlobRef    `json:"content"`
	Artifacts              []BlobRef  `json:"artifacts"`
}

type ChannelReadBack struct {
	RemoteReceiptID string    `json:"remote_receipt_id"`
	PayloadSHA256   Digest    `json:"payload_sha256"`
	Response        BlobRef   `json:"response"`
	ObservedAt      Timestamp `json:"observed_at"`
}

// Confirmed requires actual provider acknowledgement and matching read-back.
// An exit code or injected credential is never a delivery receipt.
type ChannelSendEvidence struct {
	Schema                 string           `json:"schema"`
	LeaseID                ID               `json:"lease_id"`
	OperationID            ID               `json:"operation_id"`
	EffectID               ID               `json:"effect_id"`
	MailID                 ID               `json:"mail_id"`
	ChannelID              ID               `json:"channel_id"`
	ChannelGeneration      Generation       `json:"channel_generation"`
	DestinationID          ID               `json:"destination_id"`
	ProviderIdempotencyKey ID               `json:"provider_idempotency_key"`
	PayloadSHA256          Digest           `json:"payload_sha256"`
	Outcome                string           `json:"outcome"`
	RemoteReceiptID        string           `json:"remote_receipt_id,omitempty"`
	Response               *BlobRef         `json:"response,omitempty"`
	ReadBack               *ChannelReadBack `json:"read_back,omitempty"`
	Error                  *Error           `json:"error,omitempty"`
}

type ChannelJobStore interface {
	PrepareChannelJob(context.Context, Scope, ChannelPrepareRequest) (ChannelJob, error)
}

// Protected read of the writer's frozen native plan; never a public RPC.
type ChannelPlanSource interface {
	ChannelPlan(context.Context, Scope, EffectLease) (WorkerPlan, error)
}

type ChannelWorker interface {
	PrepareChannel(context.Context, Scope, ChannelJob) (ChannelExecution, error)
	SendChannel(context.Context, Scope, ChannelExecution) (ChannelSendEvidence, error)
	ReadBackChannel(context.Context, Scope, ChannelExecution) (ChannelSendEvidence, error)
}

// These ports use the worker-only installed connection and carry no secret
// values. The selected credential is projected by the existing native broker.
type ChannelContext struct {
	Job         ChannelJob
	Destination ChannelDestination
	Credential  WorkerCredential
	ReadOnly    bool
}

type ChannelReceiptRequest struct {
	LeaseID ID
	Bytes   []byte
}

type ChannelBootstrap interface {
	ChannelContext(context.Context, Scope, WorkerInputRequest) (ChannelContext, error)
	ChannelReceipt(context.Context, Scope, ChannelReceiptRequest) (BlobRef, error)
}
