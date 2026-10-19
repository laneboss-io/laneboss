package api

import "context"

type CaptureStreamBinding struct {
	ID     ID     `json:"id"`
	Stream string `json:"stream"`
	PipeID ID     `json:"pipe_id"`
}

// Registered bindings are attestations returned over the installed helper
// channel, not claims from a lane or a supplied descriptor. Refused is an
// explicit pre-release incomplete-evidence result, never an omitted binding.
type CaptureBinding struct {
	RefusalPolicy      *CaptureRefusalPolicy  `json:"refusal_policy,omitempty"`
	ID                 ID                     `json:"id"`
	Config             string                 `json:"config"`
	ReservationID      ID                     `json:"reservation_id"`
	Target             LifeRef                `json:"target"`
	LaunchID           ID                     `json:"launch_id"`
	HelperLeaseID      ID                     `json:"helper_lease_id"`
	OperationID        ID                     `json:"operation_id"`
	RequestID          ID                     `json:"request_id"`
	RequestedBy        Actor                  `json:"requested_by"`
	Generation         Generation             `json:"generation"`
	Status             string                 `json:"status"`
	WorkerLeaseID      ID                     `json:"worker_lease_id,omitempty"`
	EffectID           ID                     `json:"effect_id,omitempty"`
	ProducerID         ID                     `json:"producer_id,omitempty"`
	ProducerGeneration string                 `json:"producer_generation,omitempty"`
	BootID             string                 `json:"boot_id,omitempty"`
	Supervisor         *Executable            `json:"supervisor,omitempty"`
	Streams            []CaptureStreamBinding `json:"streams"`
	Refusal            *Error                 `json:"refusal,omitempty"`
}

type CaptureRefusalPolicy struct {
	Allowed          bool       `json:"allowed"`
	PolicyGeneration Generation `json:"policy_generation"`
	ApprovalID       ID         `json:"approval_id"`
}

type CaptureRegistrationRequest struct {
	Claim         LaunchClaim    `json:"-"`
	Cause         InternalIntent `json:"cause"`
	ReservationID ID             `json:"reservation_id"`
	HelperLeaseID ID             `json:"helper_lease_id"`
	WorkerLeaseID ID             `json:"worker_lease_id"`
}

type CapturePosition struct {
	StreamID   ID    `json:"stream_id"`
	NextOffset int64 `json:"next_offset"`
	EOF        bool  `json:"eof"`
}

type CaptureState struct {
	Binding    CaptureBinding    `json:"binding"`
	Generation Generation        `json:"generation"`
	Positions  []CapturePosition `json:"positions"`
	LastSeq    Sequence          `json:"last_seq"`
}

// Exactly one of a nonempty committed chunk or EOF. The store derives the
// record ID, primary provenance, original requester and acknowledgement.
type CaptureAppendRequest struct {
	Intent             InternalIntent `json:"intent"`
	BindingID          ID             `json:"binding_id"`
	ExpectedGeneration Generation     `json:"expected_generation"`
	StreamID           ID             `json:"stream_id"`
	Offset             int64          `json:"offset"`
	Data               *BlobRef       `json:"data,omitempty"`
	EOF                bool           `json:"eof"`
}

type CaptureAppendReceipt struct {
	BindingID  ID         `json:"binding_id"`
	RecordID   ID         `json:"record_id"`
	StreamID   ID         `json:"stream_id"`
	Offset     int64      `json:"offset"`
	NextOffset int64      `json:"next_offset"`
	Generation Generation `json:"generation"`
	LastSeq    Sequence   `json:"last_seq"`
	EOF        bool       `json:"eof"`
	Replayed   bool       `json:"replayed"`
}

type CaptureControl interface {
	RegisterCapture(context.Context, CaptureRegistrationRequest) (CaptureBinding, error)
	ReconcileCapture(context.Context, CaptureBinding) (CaptureBinding, error)
}

type CaptureStore interface {
	CaptureState(context.Context, Scope, ID) (CaptureState, error)
	AppendCapture(context.Context, Scope, CaptureAppendRequest) (CaptureAppendReceipt, error)
}
