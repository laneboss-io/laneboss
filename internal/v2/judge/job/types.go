// Package job defines private native judge handoffs, never public RPC input.
package job

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

type Job struct {
	Execution     api.JudgeExecution
	Lease         api.WorkerLease
	Plan          api.WorkerPlan
	Claim         api.EffectLease
	LaunchID      api.ID
	Actor         api.Actor
	ParentLeaseID api.ID
}

func Validate(j Job, now time.Time) error {
	e, lease, plan := j.Execution, j.Lease, j.Plan
	raw, err := json.Marshal(e.Request)
	deadline, timeErr := time.Parse(time.RFC3339Nano, string(e.Deadline))
	if err != nil || timeErr != nil || !now.Before(deadline) || wire.Digest(raw) != e.Pin || e.Acquired ||
		e.Audit != nil || e.Outcome != "pending" || e.Intent.Kind != api.InternalJudgeEvaluate || e.Intent.Actor.Kind != "service" ||
		!wire.ValidID(e.ID) || !wire.ValidID(e.ClaimID) || !wire.ValidID(e.AttemptID) ||
		lease.Kind != "judge" || lease.Target != e.Intent.Target || lease.OperationID != e.Intent.CauseOperationID ||
		lease.EffectID != e.ID || lease.ExpiresAt != e.Deadline || lease.Input.Class != "worker_input" ||
		lease.Input.Bytes <= 0 || lease.Input.Bytes > api.MaxFrameBytes || !wire.ValidID(lease.ID) ||
		plan.Schema != "laneboss.worker-plan.v2" || plan.Kind != "judge" || plan.Input != lease.Input || plan.GrantSetID != lease.GrantSetID ||
		!reflect.DeepEqual(plan.Argv, []string{"laneboss", "internal", "judge", "--binding", "/runtime/laneboss-worker.json", "--lease", string(lease.ID)}) ||
		j.Actor.Kind != "worker" || j.Actor.LifeID != "" || !wire.ValidID(j.Actor.ID) || !wire.ValidID(j.LaunchID) || !wire.ValidID(j.ParentLeaseID) ||
		!api.EffectLeaseClaimed(j.Claim) || j.Claim.ClaimID != e.ClaimID || j.Claim.ExpiresAt != e.Deadline ||
		j.Claim.Record.Effect.Context == nil || j.Claim.Record.Effect.Worker == nil || !reflect.DeepEqual(*j.Claim.Record.Effect.Worker, plan) ||
		j.Claim.Record.Effect.ID != e.ID || j.Claim.Record.Effect.OperationID != lease.OperationID || j.Claim.Record.ClaimantID != e.Intent.Actor.ID {
		return &api.Error{Code: api.CodeConflict, Owner: "lb-v2-judge", Message: "native judge differs from its original current execution claim"}
	}
	return nil
}

// Setup crosses only the credential-pinned worker connection. It is never a
// retained input, record or event. Paths are fixed native runtime projections.
type Setup struct {
	Config                 api.JudgeConfig
	Endpoint               string
	CredentialHandle       api.ID
	Credential             []byte `json:",omitempty"`
	TokenizerPath          string
	TokenizerArgs          []string
	ProviderSocket         string
	SafetyTokens           int
	ReserveMicros          int64
	InputMicrosPerMillion  int64
	OutputMicrosPerMillion int64
}

func (Setup) String() string   { return "native judge setup (redacted)" }
func (Setup) GoString() string { return "native judge setup (redacted)" }

type RetainRequest struct {
	LeaseID api.ID
	Class   string
	Bytes   []byte
}

type Result struct {
	Reply api.JudgeReply
	Fit   api.TokenFit
}

type Bootstrap interface {
	JudgeSetup(context.Context, api.Scope, api.WorkerInputRequest) (Setup, error)
	JudgeRetain(context.Context, api.Scope, RetainRequest) (api.BlobRef, error)
}

type Store interface {
	PrepareJudgeWorker(context.Context, api.Scope, api.JudgeExecution, api.BlobRef, api.Executable) (api.WorkerLease, error)
	JudgeWorkerJob(context.Context, api.Scope, api.JudgeExecution) (Job, error)
	JudgeHandoff(context.Context, api.Scope, api.JudgeExecution, api.HelperLease, api.InstalledBinding) (api.PreparedSpecHandoff, error)
	BindJudgeWorker(context.Context, api.Scope, api.JudgeExecution, api.PreparedLaunch) (api.LaunchBindingRequest, error)
	RecordJudgeProcess(context.Context, api.Scope, api.JudgeExecution, api.ProcessHandle) error
	JudgeWorkerResult(context.Context, api.Scope, api.JudgeExecution) (Result, error)
	RecordJudgeObservation(context.Context, api.Scope, api.JudgeExecution, api.ProcessObservation) error
}

type Helper interface {
	JudgeWorkerLease(context.Context, Job) (api.HelperLease, error)
	RegisterJudgeWorker(context.Context, Job, api.PreparedSpecHandoff, api.InstalledBinding) (api.PreparedSpecReceipt, error)
	PrepareJudgeWorker(context.Context, Job) (api.PreparedLaunch, error)
	OpenJudgeWorker(context.Context, Job, api.HelperOpenRequest) (api.ProcessHandle, error)
	ObserveJudgeWorker(context.Context, Job) (api.ProcessObservation, error)
	CollectJudgeWorker(context.Context, Job) (api.ProcessObservation, error)
}
