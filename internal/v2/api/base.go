// Package api defines the frozen v2 wire and component contracts.
// Implementations must follow docs/design/v2-contracts.md. This package has no I/O.
package api

import (
	"encoding/json"
	"fmt"
)

const (
	ContractRevision = "v2.0-draft.4"
	Protocol         = "laneboss.rpc.v2"
	SchemaVersion    = 2
	MaxFrameBytes    = 1048576
	MaxChunkBytes    = 262144
	MaxObjectBytes   = 67108864
	MaxJudgeBytes    = 262144
)

// MaxVendorBytes allows native vendor binaries (currently about 256 MB)
// roughly twice that size, with a fixed installation-file ceiling. It is
// never a store-object or wire-frame allowance.
const MaxVendorBytes = 512 << 20

type ID string
type Digest string
type Timestamp string
type Generation uint64
type Sequence uint64
type RunNumber uint64
type Method string
type EventKind string
type ErrorCode string

const (
	CodeNotImplemented      ErrorCode = "not_implemented"
	CodeInvalid             ErrorCode = "invalid_request"
	CodeUnauthenticated     ErrorCode = "unauthenticated"
	CodeForbidden           ErrorCode = "forbidden"
	CodeNotFound            ErrorCode = "not_found"
	CodeConflict            ErrorCode = "conflict"
	CodeIdempotencyConflict ErrorCode = "idempotency_conflict"
	CodeVersion             ErrorCode = "version_mismatch"
	CodeUnavailable         ErrorCode = "unavailable"
	CodePrerequisite        ErrorCode = "prerequisite_missing"
	CodeUnsupported         ErrorCode = "unsupported"
	CodeIntegrity           ErrorCode = "integrity"
	CodeBudget              ErrorCode = "budget_exhausted"
	CodeUnscored            ErrorCode = "unscored"
	CodeCursorExpired       ErrorCode = "cursor_expired"
	CodeContainmentUnknown  ErrorCode = "containment_unknown"
	CodeCancelled           ErrorCode = "cancelled"
	CodeDeadline            ErrorCode = "deadline_exceeded"
)

type Error struct {
	component   string
	Code        ErrorCode `json:"code"`
	Message     string    `json:"message"`
	Instead     string    `json:"instead"`
	Retryable   bool      `json:"retryable"`
	OperationID ID        `json:"operation_id,omitempty"`
	Owner       string    `json:"owner,omitempty"`
}

func (e *Error) Error() string {
	return string(e.Code) + ": " + e.Message
}

// NotImplemented is a failing scaffold result, never a successful empty response.
func NotImplemented(owner, operation string) *Error {
	return &Error{
		Code:    CodeNotImplemented,
		Message: fmt.Sprintf("%s is not implemented", operation),
		Instead: "Wait for the owning implementation lane and its acceptance evidence.",
		Owner:   owner,
	}
}

// Params and Result are closed discriminated unions selected by Method.
// They are not arbitrary maps or a command/argv forwarding API.
type Request struct {
	Protocol       string          `json:"protocol"`
	Schema         uint32          `json:"schema"`
	Config         string          `json:"config"`
	RequestID      ID              `json:"request_id"`
	IdempotencyKey ID              `json:"idempotency_key"`
	RequestSHA256  Digest          `json:"request_sha256"`
	Method         Method          `json:"method"`
	Params         json.RawMessage `json:"params"`
	Proof          *ProofRef       `json:"proof,omitempty"`
}

type Response struct {
	Protocol  string          `json:"protocol"`
	Schema    uint32          `json:"schema"`
	RequestID ID              `json:"request_id"`
	LastSeq   Sequence        `json:"last_seq"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *Error          `json:"error,omitempty"`
}

type StreamFrame struct {
	RequestID ID         `json:"request_id"`
	Index     uint64     `json:"index"`
	Cursor    string     `json:"cursor"`
	Event     *Event     `json:"event,omitempty"`
	Chunk     *BlobChunk `json:"chunk,omitempty"`
	End       bool       `json:"end"`
	Error     *Error     `json:"error,omitempty"`
}

type Empty struct{}
