package api

import "context"

// JudgeExecution is the private durable egress effect. Acquired is returned
// only to its creation winner and is never persisted as authority. An expired
// or interrupted execution is not reclaimed: sending twice can spend twice.
type JudgeExecution struct {
	ID         ID
	Pin        Digest
	Request    JudgeRequest
	Intent     InternalIntent
	ClaimID    ID
	AttemptID  ID
	ReservedAt Timestamp
	Deadline   Timestamp
	Acquired   bool
	Audit      *JudgeAudit `json:",omitempty"`
	Outcome    string
	UsageKnown bool
}

type JudgeExecutionRequest struct {
	Request   JudgeRequest
	AttemptID ID
	Deadline  Timestamp
}

type JudgeExecutionStore interface {
	ReserveJudgeExecution(context.Context, Scope, JudgeExecutionRequest) (JudgeExecution, error)
	ValidateJudgeExecution(context.Context, Scope, JudgeExecution) error
	CompleteJudgeExecution(context.Context, Scope, JudgeExecution, JudgeAudit) (JudgeAudit, error)
}

// JudgeWorker is an enrolled outside-lane provider with per-job retention.
// Credentials, price and the tokenizer are protected worker dependencies.
type JudgeWorker interface {
	EvaluateLeased(context.Context, JudgeExecution, func(context.Context, string, []byte) (BlobRef, error)) (JudgeReply, TokenFit, error)
}
