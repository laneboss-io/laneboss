package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/job"
)

type judgeRecoveryKey struct{}

func (s *Service) JudgeWorkerResult(ctx context.Context, scope api.Scope, e api.JudgeExecution) (job.Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stage, err := s.judgeNativeClaim(ctx, s.db, scope, e)
	if err != nil {
		return job.Result{}, err
	}
	if stage.Ack == nil {
		return job.Result{}, fault(api.CodeUnavailable, "judge original native outcome is pending or unknown")
	}
	var result job.Result
	if err := json.Unmarshal(stage.Ack.Submission.Result, &result); err != nil {
		return result, err
	}
	return result, s.checkJudgeResult(ctx, s.db, stage, result)
}

func (s *Service) RecordJudgeObservation(ctx context.Context, scope api.Scope, e api.JudgeExecution, observed api.ProcessObservation) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if scope.Config != s.deps.Config || scope.Actor != e.Intent.Actor || scope.Connection != nil {
		return fault(api.CodeForbidden, "judge observation requires its original service owner")
	}
	var stage judgeNative
	if err := storedProjection(ctx, s.db, "judge_native", e.ID, &stage); err != nil {
		return err
	}
	if stage.Execution.Pin != e.Pin || stage.Execution.ClaimID != e.ClaimID || observed.Handle.ID != stage.LaunchID ||
		observed.Handle.Target != stage.Worker.Target || observed.Handle.ContainmentID != stage.Allocation.ContainmentID ||
		observed.State != "exited" || observed.Survivors == nil || *observed.Survivors != 0 {
		return fault(api.CodeContainmentUnknown, "judge retirement lacks the exact original terminal native observation")
	}
	stage.Observation = &observed
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := saveJudgeNative(ctx, tx, stage); err != nil {
		return err
	}
	return tx.Commit()
}

// RecoverJudgeExecution reads only a measured result that the original native
// worker submitted before its deadline. It never dispatches or reclaims a job.
// Unknown results keep their complete original cost reservation indefinitely.
func (s *Service) RecoverJudgeExecution(ctx context.Context, scope api.Scope, e api.JudgeExecution) (api.JudgeAudit, error) {
	s.mu.RLock()
	var stage judgeNative
	err := storedProjection(ctx, s.db, "judge_native", e.ID, &stage)
	if err == nil && (stage.Execution.Pin != e.Pin || stage.Execution.ClaimID != e.ClaimID || stage.Execution.AttemptID != e.AttemptID ||
		!sameValue(stage.Execution.Request, e.Request) || !sameValue(stage.Execution.Intent, e.Intent) || scope.Actor != stage.Execution.Intent.Actor ||
		scope.Connection != nil || scope.Config != s.deps.Config) {
		err = fault(api.CodeForbidden, "judge recovery changed its original owner or exact execution")
	}
	if err == nil && (stage.Ack == nil || stage.Observation == nil || stage.Observation.ExitCode == nil ||
		*stage.Observation.ExitCode != 0 || stage.Observation.Signal != nil || stage.Observation.Survivors == nil || *stage.Observation.Survivors != 0) {
		err = fault(api.CodeUnavailable, "judge original native outcome or terminal observation is unknown; reservation retained")
	}
	s.mu.RUnlock()
	if err != nil {
		return api.JudgeAudit{}, err
	}
	var measured job.Result
	if err := json.Unmarshal(stage.Ack.Submission.Result, &measured); err != nil {
		return api.JudgeAudit{}, err
	}
	if measured.Reply.Request == nil {
		return api.JudgeAudit{}, fault(api.CodeUnscored, "judge original result has no retained request")
	}
	e = stage.Execution
	e.Acquired = true
	audit := api.JudgeAudit{ID: e.Request.ID, Request: *measured.Reply.Request, Reply: measured.Reply, Fit: measured.Fit,
		StartedAt: e.ReservedAt, CompletedAt: stage.ReceivedAt}
	return s.CompleteJudgeExecution(context.WithValue(ctx, judgeRecoveryKey{}, s), scope, e, audit)
}
