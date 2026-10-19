package admin

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/job"
)

func (s *Service) judgeAuthority(ctx context.Context, submitted job.Job) (job.Job, error) {
	reader, ok := s.deps.Store.(interface {
		JudgeWorkerLookup(context.Context, api.Scope, api.ID) (job.Job, error)
	})
	if !ok {
		return job.Job{}, failure(api.CodePrerequisite, "judge native helper requires its original committed job lookup")
	}
	scope := api.Scope{Config: s.deps.Config, Actor: submitted.Execution.Intent.Actor,
		PolicyGeneration: submitted.Execution.Request.Context.PolicyGeneration, Source: "worker"}
	actual, err := reader.JudgeWorkerLookup(ctx, scope, submitted.Lease.ID)
	if err != nil {
		return job.Job{}, err
	}
	if !reflect.DeepEqual(actual, submitted) {
		return job.Job{}, failure(api.CodeConflict, "judge helper input differs from its retained exact job")
	}
	return actual, validJudgeReg(actual, s.deps.Config)
}

func (s *Service) JudgeWorkerLease(ctx context.Context, j job.Job) (result api.HelperLease, err error) {
	j, err = s.judgeAuthority(ctx, j)
	if err == nil {
		err = s.call(ctx, "judge_lease", j, &result)
	}
	if err == nil {
		err = validateLease(result, s.binding)
	}
	return result, err
}

func (s *Service) RegisterJudgeWorker(ctx context.Context, j job.Job, h api.PreparedSpecHandoff, endpoint api.InstalledBinding) (result api.PreparedSpecReceipt, err error) {
	j, err = s.judgeAuthority(ctx, j)
	if err != nil {
		return result, err
	}
	scope := api.Scope{Config: s.deps.Config, Actor: j.Execution.Intent.Actor, Source: "worker"}
	original, err := s.readLaunchObject(ctx, scope, h.Original, j.Lease.OperationID, j.Lease.Target.LifeID, false)
	if err != nil {
		return result, err
	}
	input, err := s.readLaunchObject(ctx, scope, j.Lease.Input, j.Lease.OperationID, j.Lease.Target.LifeID, false)
	if err != nil {
		return result, err
	}
	err = s.call(ctx, "judge_register", judgeSeal{Reg: j, Spec: specRegistration{Handoff: h, Original: original}, Endpoint: endpoint, Input: input}, &result)
	return result, err
}

func (s *Service) PrepareJudgeWorker(ctx context.Context, j job.Job) (result api.PreparedLaunch, err error) {
	j, err = s.judgeAuthority(ctx, j)
	if err == nil {
		err = s.call(ctx, "judge_prepare", j, &result)
	}
	if err == nil {
		err = s.bindJudgeContainment(ctx, j)
	}
	return result, err
}

func (s *Service) OpenJudgeWorker(ctx context.Context, j job.Job, request api.HelperOpenRequest) (result api.ProcessHandle, err error) {
	if _, err := s.judgeAuthority(ctx, j); err != nil {
		return result, err
	}
	binding, err := s.deps.Store.LaunchBinding(ctx, j.LaunchID)
	if err != nil {
		return result, err
	}
	input := judgeOpen{Reg: j, Request: request, Binding: binding}
	err = s.openJudgeCall(ctx, input, &result)
	return result, err
}

func (s *Service) ObserveJudgeWorker(ctx context.Context, j job.Job) (result api.ProcessObservation, err error) {
	err = s.call(ctx, "judge_observe", j, &result)
	return result, err
}

func (s *Service) CollectJudgeWorker(ctx context.Context, j job.Job) (result api.ProcessObservation, err error) {
	err = s.call(ctx, "judge_collect", j, &result)
	return result, err
}
