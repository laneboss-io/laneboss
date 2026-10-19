package service

import (
	"context"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/judge/job"
)

type nativeJudge struct {
	host       *Server
	helper     job.Helper
	store      job.Store
	runtime    api.BlobRef
	executable api.Executable
	setup      func(context.Context, api.JudgeConfig) (job.Setup, error)
}

// NewJudgeWorker binds the actual installed server's private worker listener.
// Settings come from protected composition; no public handler installs them.
func (s *Server) NewJudgeWorker(helper job.Helper, runtime api.BlobRef, executable api.Executable,
	setup func(context.Context, api.JudgeConfig) (job.Setup, error)) (api.JudgeWorker, error) {
	store, ok := s.deps.Store.(job.Store)
	if !ok || helper == nil || setup == nil {
		return nil, serviceError(api.CodePrerequisite, "native judge dependencies are incomplete")
	}
	w := &nativeJudge{host: s, helper: helper, store: store, runtime: runtime, executable: executable, setup: setup}
	s.mu.Lock()
	if s.judgeWorker != nil {
		s.mu.Unlock()
		return nil, serviceError(api.CodeConflict, "native judge worker is already bound")
	}
	s.judgeWorker = w
	s.mu.Unlock()
	return w, nil
}

func (w *nativeJudge) EvaluateLeased(ctx context.Context, e api.JudgeExecution, _ func(context.Context, string, []byte) (api.BlobRef, error)) (reply api.JudgeReply, fit api.TokenFit, resultErr error) {
	scope := api.Scope{Config: e.Intent.Config, Actor: e.Intent.Actor, PolicyGeneration: e.Request.Context.PolicyGeneration, Source: "worker"}
	if !e.Acquired {
		return reply, fit, serviceError(api.CodeForbidden, "judge native dispatch requires the original execution winner")
	}
	lease, err := w.store.PrepareJudgeWorker(ctx, scope, e, w.runtime, w.executable)
	if err != nil {
		return reply, fit, err
	}
	j, err := w.store.JudgeWorkerJob(ctx, scope, e)
	if err != nil {
		return reply, fit, err
	}
	allocation, err := w.helper.JudgeWorkerLease(ctx, j)
	if err != nil {
		return reply, fit, err
	}
	// Native retirement is required after every attempted allocation. It does
	// not release the original cost reservation or authorize a replacement.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		observation, err := w.helper.CollectJudgeWorker(cleanup, j)
		if err == nil {
			err = w.store.RecordJudgeObservation(cleanup, scope, e, observation)
		}
		if stopErr := w.host.stopWorkerEndpoint(cleanup, lease.ID); stopErr != nil {
			err = errors.Join(err, stopErr)
		}
		if err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	endpoint := w.host.deps.Binding
	endpoint.Class, endpoint.LaunchID, endpoint.WorkerLeaseID, endpoint.Target = api.EndpointWorker, j.LaunchID, lease.ID, &lease.Target
	endpoint.Socket, endpoint.EndpointGeneration = "/runtime/laneboss-worker.sock", allocation.EndpointGeneration
	endpoint.MappedServiceUID, endpoint.MappedServiceGID, err = wire.NamespaceServiceIDs()
	if err != nil {
		return reply, fit, err
	}
	handoff, err := w.store.JudgeHandoff(ctx, scope, e, allocation, endpoint)
	if err != nil {
		return reply, fit, err
	}
	if err := w.host.startWorkerEndpoint(ctx, lease.ID, endpoint); err != nil {
		return reply, fit, err
	}
	registered, err := w.helper.RegisterJudgeWorker(ctx, j, handoff, endpoint)
	if err != nil {
		return reply, fit, err
	}
	if registered.SpecID != handoff.Spec.ID || registered.SpecSHA256 != handoff.SpecSHA256 || registered.LeaseID != allocation.ID {
		return reply, fit, serviceError(api.CodeIntegrity, "judge helper registration changed its native spec")
	}
	prepared, err := w.helper.PrepareJudgeWorker(ctx, j)
	if err != nil {
		return reply, fit, err
	}
	binding, err := w.store.BindJudgeWorker(ctx, scope, e, prepared)
	if err != nil {
		return reply, fit, err
	}
	native, ok := w.helper.(interface {
		WithWorkerLaunch(context.Context, api.PreparedLaunch, func(context.Context) error) error
	})
	if !ok {
		return reply, fit, serviceError(api.CodePrerequisite, "judge requires the original locked native launch handoff")
	}
	var process api.ProcessHandle
	err = native.WithWorkerLaunch(ctx, prepared, func(ctx context.Context) error {
		permit, err := w.host.deps.Authenticator.BindLaunch(ctx, binding)
		if err != nil {
			return err
		}
		cause := *j.Claim.Record.Effect.Context
		cause.Kind = api.InternalHelperOpen
		process, err = w.helper.OpenJudgeWorker(ctx, j, api.HelperOpenRequest{Cause: cause, Prepared: prepared, Permit: permit, OperationID: lease.OperationID, EffectID: lease.EffectID})
		return err
	})
	if err != nil {
		return reply, fit, err
	}
	if err := w.store.RecordJudgeProcess(ctx, scope, e, process); err != nil {
		return reply, fit, err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		// Submission was checked under the worker's live endpoint and retained
		// before exit. Waiting cannot execute or infer another provider call.
		measured, err := w.store.JudgeWorkerResult(ctx, scope, e)
		if err == nil {
			finish, lockErr := w.host.workerTurn(ctx, lease.ID, "judge_observe")
			if lockErr != nil {
				return reply, fit, lockErr
			}
			observation, observeErr := w.helper.ObserveJudgeWorker(ctx, j)
			finish()
			if observeErr != nil {
				return reply, fit, observeErr
			}
			if observation.Handle != process {
				return reply, fit, serviceError(api.CodeIntegrity, "judge observed another native process")
			}
			if observation.State == "exited" {
				if observation.ExitCode == nil || *observation.ExitCode != 0 || observation.Signal != nil {
					return reply, fit, serviceError(api.CodeContainmentUnknown, "judge result lacks its original successful native exit")
				}
				return measured.Reply, measured.Fit, nil
			}
			if observation.State != "running" {
				return reply, fit, serviceError(api.CodeContainmentUnknown, "judge native process state is unknown")
			}
		}
		var typed *api.Error
		if err != nil && (!errors.As(err, &typed) || typed.Code != api.CodeUnavailable) {
			return reply, fit, err
		}
		select {
		case <-ctx.Done():
			return reply, fit, contextError(ctx.Err())
		case <-ticker.C:
		}
	}
}

func (s *Server) JudgeSetup(ctx context.Context, transport api.Scope, q api.WorkerInputRequest) (job.Setup, error) {
	scope, err := s.workerScope(ctx, transport, api.WorkerJudgeContext, q)
	if err != nil {
		return job.Setup{}, err
	}
	reader, ok := s.deps.Store.(interface {
		JudgeWorkerContext(context.Context, api.Scope, api.WorkerInputRequest) (api.JudgeRequest, error)
	})
	if !ok {
		return job.Setup{}, serviceError(api.CodePrerequisite, "native judge context store is unavailable")
	}
	r, err := reader.JudgeWorkerContext(ctx, scope, q)
	if err != nil {
		return job.Setup{}, err
	}
	s.mu.RLock()
	w := s.judgeWorker
	s.mu.RUnlock()
	if w == nil {
		return job.Setup{}, serviceError(api.CodePrerequisite, "native judge enrollment is unavailable")
	}
	return w.setup(ctx, r.Config)
}

func (s *Server) JudgeRetain(ctx context.Context, transport api.Scope, q job.RetainRequest) (api.BlobRef, error) {
	scope, err := s.workerScope(ctx, transport, api.WorkerJudgeRetain, q)
	if err != nil {
		return api.BlobRef{}, err
	}
	sink, ok := s.deps.Store.(interface {
		JudgeRetain(context.Context, api.Scope, job.RetainRequest) (api.BlobRef, error)
	})
	if !ok {
		return api.BlobRef{}, serviceError(api.CodePrerequisite, "native judge retention store is unavailable")
	}
	return sink.JudgeRetain(ctx, scope, q)
}
