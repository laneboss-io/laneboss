package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// This is the original execution's private native stage, not another egress
// reservation. Its already-claimed effect is never independently dispatched.
type judgeNative struct {
	Execution   api.JudgeExecution
	Worker      api.WorkerLease
	Plan        api.WorkerPlan
	Claim       api.EffectLease
	LaunchID    api.ID
	Actor       api.Actor
	Allocation  api.HelperLease
	Endpoint    *api.InstalledBinding    `json:",omitempty"`
	Handoff     *api.PreparedSpecHandoff `json:",omitempty"`
	Process     *api.ProcessHandle       `json:",omitempty"`
	Observation *api.ProcessObservation  `json:",omitempty"`
	Ack         *dataAcknowledgement     `json:",omitempty"`
	ReceivedAt  api.Timestamp
}

func (s *Service) judgeNativeClaim(ctx context.Context, db queryer, scope api.Scope, e api.JudgeExecution) (judgeNative, error) {
	if _, err := s.judgeExecutionClaim(ctx, db, scope, e); err != nil {
		return judgeNative{}, err
	}
	var stage judgeNative
	err := storedProjection(ctx, db, "judge_native", e.ID, &stage)
	return stage, err
}

func saveJudgeNative(ctx context.Context, tx *sql.Tx, stage judgeNative) error {
	var generation api.Generation
	err := tx.QueryRowContext(ctx, "SELECT generation FROM projections WHERE kind='judge_native' AND id=?", string(stage.Execution.ID)).Scan(&generation)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	return put(ctx, tx, "judge_native", stage.Execution.ID, generation+1, stage)
}

func judgeEndpointID(config api.JudgeConfig) api.ID {
	return api.ID("judge-" + config.Provider)
}

// PrepareJudgeWorker consumes only the original winner's exact durable claim.
// A retry reads the same input, worker, plan and deadline. No parent profile,
// data, secret, resource or channel capability is copied to this worker.
func (s *Service) PrepareJudgeWorker(ctx context.Context, scope api.Scope, e api.JudgeExecution, runtime api.BlobRef, executable api.Executable) (result api.WorkerLease, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if _, err := s.judgeExecutionClaim(ctx, s.db, scope, e); err != nil {
		return result, err
	}
	metadata, raw, err := objectRow(ctx, s.db, runtime.ID)
	if err != nil {
		return result, err
	}
	var manifest api.RuntimeManifest
	if metadata.Ref != runtime || runtime.Class != "manifest" || api.DecodeObject(raw, &manifest) != nil || manifest.Bootstrap != executable {
		return result, fault(api.CodeForbidden, "judge worker differs from the retained fixed runtime")
	}
	var prior judgeNative
	if err := storedProjection(ctx, s.db, "judge_native", e.ID, &prior); err == nil {
		if prior.Worker.RuntimeManifest != runtime || prior.Plan.Executable != executable {
			return result, fault(api.CodeConflict, "judge retry changed its original runtime")
		}
		return prior.Worker, nil
	} else if !absent(err) {
		return result, err
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", e.Intent.Target.LifeID, &lane); err != nil {
		return result, err
	}
	budget := lane.BudgetRemaining
	budget.WallMS = min(budget.WallMS, e.Request.DeadlineMS)
	budget.CPUSeconds, budget.MemoryBytes = min(budget.CPUSeconds, 10), min(budget.MemoryBytes, 256<<20)
	budget.Processes, budget.DiskBytes = min(budget.Processes, 16), min(budget.DiskBytes, 4<<20)
	budget.SpendMicros = e.Request.MaxCostMicros
	ids := make([]api.ID, 5)
	for i := range ids {
		ids[i], err = wire.NewID()
		if err != nil {
			return result, err
		}
	}
	grants := api.GrantSet{ID: ids[0], LifeID: e.Intent.Target.LifeID, PolicyGeneration: e.Request.Context.PolicyGeneration,
		Generation: 1, ExpiresAt: e.Deadline, Resources: []api.ResourceGrant{}, Data: []api.DataGrant{}, Secrets: []api.SecretGrant{},
		Profiles: []api.ProfileGrant{}, Channels: []api.ChannelGrant{}, Network: []api.NetworkGrant{{ID: ids[1],
			EndpointID: judgeEndpointID(e.Request.Config), Mode: "service", ExpiresAt: e.Deadline}}}
	grantBytes, err := canonicalValue(grants)
	if err != nil {
		return result, err
	}
	grants.SHA256 = api.Digest(hash(grantBytes))
	sealed := e
	sealed.Acquired = false
	input, err := json.Marshal(sealed)
	if err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	ref, err := s.retain(context.WithValue(ctx, dataObjectKey{}, s), tx, scope,
		api.ObjectWrite{ObjectKey: ids[2], Class: "worker_input", Bytes: input, SHA256: api.Digest(hash(input)), Origin: "service",
			ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: e.Intent.Target.LifeID, Audience: "private", Generation: 1}},
		e.Intent.CauseOperationID, e.ReservedAt)
	if err != nil {
		return result, err
	}
	result = api.WorkerLease{ID: ids[3], Kind: "judge", Target: e.Intent.Target, OperationID: e.Intent.CauseOperationID,
		EffectID: e.ID, Input: ref, RuntimeManifest: runtime, GrantSetID: grants.ID, Generation: 1, ExpiresAt: e.Deadline}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "judge", Executable: executable, Input: ref,
		GrantSetID: grants.ID, Budget: budget, Argv: []string{"laneboss", "internal", "judge", "--binding", "/runtime/laneboss-worker.json", "--lease", string(result.ID)}}
	cause := e.Intent
	cause.Kind = api.InternalObjectRetain
	effect := api.Effect{ID: e.ID, OperationID: result.OperationID, Context: &cause, Worker: &plan}
	if err := validateEffect(effect); err != nil {
		return result, err
	}
	claim := api.EffectLease{ClaimID: e.ClaimID, ExpiresAt: e.Deadline, Record: api.EffectRecord{Effect: effect,
		State: api.EffectClaimed, Generation: 2, ClaimID: e.ClaimID, ClaimantID: scope.Actor.ID, ClaimExpiresAt: e.Deadline}}
	if _, err := encodeEffectState(claim.Record); err != nil {
		return result, err
	}
	// The child claim is retained in this original execution's projection,
	// outside the outbox. Effect's protected read joins it back to the real
	// execution; observing it never permits acquisition or another send.
	stage := judgeNative{Execution: sealed, Worker: result, Plan: plan, Claim: claim,
		LaunchID: ids[4], Actor: api.Actor{Kind: "worker", ID: api.ID("judge-worker-" + string(ids[4]))}}
	if err := put(ctx, tx, "grants", grants.ID, grants.Generation, grants); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "worker_lease", result.ID, result.Generation, result); err != nil {
		return result, err
	}
	if err := saveJudgeNative(ctx, tx, stage); err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func (s *Service) JudgeWorkerPlan(ctx context.Context, scope api.Scope, e api.JudgeExecution) (api.WorkerPlan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stage, err := s.judgeNativeClaim(ctx, s.db, scope, e)
	return stage.Plan, err
}
