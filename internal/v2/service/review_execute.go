package service

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type reviewExecutionStore interface {
	ReviewJob(context.Context, api.Scope, api.ID) (archivejob.Job, error)
	ReviewWorkerID(context.Context, api.Scope, api.EffectLease) (api.ID, error)
	ReviewHandoff(context.Context, api.Scope, api.EffectLease, api.HelperLease, api.InstalledBinding) (api.PreparedSpecHandoff, error)
	BindReviewWorker(context.Context, api.Scope, api.EffectLease, api.PreparedLaunch) (api.LaunchBindingRequest, error)
	RecordReviewProcess(context.Context, api.Scope, api.EffectLease, api.ProcessHandle) error
	ReviewRecovery(context.Context, api.Scope, api.EffectLease) (archivejob.Recovery, error)
	BeginReviewAllocation(context.Context, api.Scope, api.EffectLease) error
	RecordReviewAllocation(context.Context, api.Scope, api.EffectLease, api.HelperLease) error
	RecordReviewRetirement(context.Context, api.Scope, api.EffectLease, archivejob.Retirement) error
	ReviewAcknowledgement(context.Context, api.Scope, api.EffectLease) (api.WorkerResultReceipt, error)
}

type reviewExecutionHelper interface {
	ReviewWorkerLease(context.Context, archivejob.Job, api.EffectLease) (api.HelperLease, error)
	RegisterReviewWorker(context.Context, archivejob.Job, api.EffectLease, api.PreparedSpecHandoff, api.InstalledBinding) (api.PreparedSpecReceipt, error)
	PrepareReviewWorker(context.Context, archivejob.Job, api.EffectLease) (api.PreparedLaunch, error)
	OpenReviewWorker(context.Context, archivejob.Job, api.EffectLease, api.HelperOpenRequest) (api.ProcessHandle, error)
	ObserveReviewWorker(context.Context, archivejob.Job, api.EffectLease) (api.ProcessObservation, error)
	ReconcileReviewWorker(context.Context, archivejob.Job, api.EffectLease) (api.LaunchReconciliation, error)
	RetireReviewWorker(context.Context, archivejob.Job, api.EffectLease) (archivejob.Retirement, error)
}

func retainedReviewWorker(ctx context.Context, state api.StateStore, scope api.Scope, effect api.Effect) (bool, error) {
	if effect.Worker == nil || effect.Worker.Kind != "export" && effect.Worker.Kind != "test" {
		return false, nil
	}
	owner, ok := state.(interface {
		ReviewOwnsEffect(context.Context, api.Scope, api.Effect) (bool, error)
	})
	if !ok {
		return false, nil
	}
	return owner.ReviewOwnsEffect(ctx, scope, effect)
}

// ExecuteReviewWorker drives only the original durable job. The native helper
// owns its gate, wait and retirement; a missing response never permits another
// worker identity. No success-shaped object completes a public review here.
func (s *Server) ExecuteReviewWorker(ctx context.Context, caller api.Scope, job archivejob.Job) error {
	var scope api.Scope
	var err error
	if job.Lease.Kind == "test" {
		var request api.TestChildRequest
		if api.DecodeObject(caller.Request.Params, &request) != nil || request.Child != job.Lease.Target {
			return serviceError(api.CodeInvalid, "TestChild execution changed its original target")
		}
		scope, err = s.testCaller(ctx, caller, request)
		if err == nil {
			var receipt api.MutationReceipt
			receipt, err = s.deps.Store.LookupReceipt(ctx, caller, testRequestKey(caller))
			if err == nil && receipt.Operation.ID != job.Intent.OperationID {
				err = serviceError(api.CodeForbidden, "TestChild execution selected another original operation")
			}
			if err == nil && receipt.Reply == nil {
				// Native checker publication owns the original pending reply;
				// atomic TestChild already committed its admission reply.
				var retained api.MutationReceipt
				retained, scope, err = s.pendingCheck(ctx, caller, request)
				if err == nil && retained.Operation.ID != job.Intent.OperationID {
					err = serviceError(api.CodeForbidden, "check execution selected another original operation")
				}
			} else if err == nil && receipt.Reply.Error != nil {
				err = serviceError(api.CodeForbidden, "TestChild execution has no committed atomic admission")
			}
		}
	} else {
		var request api.ReviewRequest
		if api.DecodeObject(caller.Request.Params, &request) != nil {
			return serviceError(api.CodeInvalid, "review execution lost its original request")
		}
		var retained api.MutationReceipt
		retained, scope, err = s.pendingReview(ctx, caller, request)
		if err == nil && (job.Intent.OperationID != retained.Operation.ID || job.Lease.Kind != "export" || job.Lease.Target != request.Target) {
			err = serviceError(api.CodeForbidden, "review execution selected another original worker")
		}
	}
	if err != nil {
		return err
	}
	return s.executePostRunWorker(ctx, scope, job)
}

// Both synchronous callers and recovery drive one durably admitted job. The
// recovery entry below proves its committed admission instead of recreating
// an authenticated public frame after the original connection is gone.
func (s *Server) executePostRunWorker(ctx context.Context, scope api.Scope, job archivejob.Job) error {
	state, ok := s.deps.Store.(reviewExecutionStore)
	if !ok {
		return serviceError(api.CodePrerequisite, "review execution writer is unavailable")
	}
	s.mu.RLock()
	helper, ok := s.runtime.Helper.(reviewExecutionHelper)
	s.mu.RUnlock()
	if !ok {
		return serviceError(api.CodePrerequisite, "review native allocation, gate, observation and retirement are unavailable")
	}
	var err error
	actual, err := state.ReviewJob(ctx, scope, job.Intent.OperationID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, job) {
		return serviceError(api.CodeIntegrity, "review execution changed its retained job")
	}
	key := "review-execute:" + string(job.ID)
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return contextError(context.Canceled)
		}
		if s.flights == nil {
			s.flights = make(map[string]chan struct{})
		}
		if done := s.flights[key]; done != nil {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return contextError(ctx.Err())
			case <-done:
			}
			continue
		}
		s.flights[key] = make(chan struct{})
		s.mu.Unlock()
		break
	}
	defer func() { s.mu.Lock(); close(s.flights[key]); delete(s.flights, key); s.mu.Unlock() }()
	current, err := s.deps.Store.Effect(ctx, scope, job.Lease.EffectID)
	if err != nil {
		return err
	}
	if current.Outcome != nil {
		if current.State != api.EffectCompleted || current.Outcome.Status != "succeeded" {
			return serviceError(api.CodePrerequisite, "original review worker did not complete successfully")
		}
		return nil
	}
	expires, err := time.Parse(time.RFC3339Nano, string(job.Lease.ExpiresAt))
	if err != nil || !expires.After(s.deps.Clock.Now()) {
		return serviceError(api.CodeDeadline, "original review worker deadline expired")
	}
	var lease api.EffectLease
	if current.ClaimID != "" && futureServiceTime(current.ClaimExpiresAt, s.deps.Clock.Now()) {
		if current.ClaimantID != scope.Actor.ID {
			return serviceError(api.CodeConflict, "original review worker has another live execution owner")
		}
		lease = api.EffectLease{Record: current, ClaimID: current.ClaimID, ExpiresAt: current.ClaimExpiresAt}
	} else {
		lease, err = s.deps.Store.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: current.Effect.ID, ExpectedGeneration: current.Generation, ClaimantID: scope.Actor.ID, Deadline: job.Lease.ExpiresAt})
		if err != nil {
			return err
		}
	}
	if err := state.BeginReviewAllocation(ctx, scope, lease); err != nil {
		return err
	}
	allocation, err := helper.ReviewWorkerLease(ctx, job, lease)
	if err != nil {
		return err
	}
	if err := state.RecordReviewAllocation(ctx, scope, lease, allocation); err != nil {
		return err
	}
	workerID, err := state.ReviewWorkerID(ctx, scope, lease)
	if err != nil {
		return err
	}
	endpoint := s.deps.Binding
	endpoint.Class, endpoint.LaunchID, endpoint.Target, endpoint.WorkerLeaseID = api.EndpointWorker, workerID, &job.Lease.Target, job.Lease.ID
	endpoint.Socket, endpoint.EndpointGeneration = "/runtime/laneboss-worker.sock", allocation.EndpointGeneration
	endpoint.MappedServiceUID, endpoint.MappedServiceGID, err = wire.NamespaceServiceIDs()
	if err != nil {
		return err
	}
	handoff, err := state.ReviewHandoff(ctx, scope, lease, allocation, endpoint)
	if err != nil {
		return err
	}
	if err := s.startWorkerEndpoint(ctx, job.Lease.ID, endpoint); err != nil {
		return err
	}
	registered, err := helper.RegisterReviewWorker(ctx, job, lease, handoff, endpoint)
	if err != nil {
		return err
	}
	if registered.SpecID != handoff.Spec.ID || registered.SpecSHA256 != handoff.SpecSHA256 || registered.LeaseID != allocation.ID || registered.RuntimeManifest != job.Lease.RuntimeManifest || registered.OperationID != job.Intent.OperationID {
		return serviceError(api.CodeIntegrity, "review helper registration changed its sealed handoff")
	}
	prepared, err := helper.PrepareReviewWorker(ctx, job, lease)
	if err != nil {
		return err
	}
	binding, err := state.BindReviewWorker(ctx, scope, lease, prepared)
	if err != nil {
		return err
	}
	native, err := helper.ReconcileReviewWorker(ctx, job, lease)
	if err != nil {
		return err
	}
	if native.Prepared == nil || *native.Prepared != prepared {
		return serviceError(api.CodeIntegrity, "review recovery changed its original prepared gate")
	}
	var process api.ProcessHandle
	if native.GateState == "opened" {
		want := api.ProcessHandle{ID: binding.Record.ID, Target: binding.Record.Target, ContainmentID: binding.Record.ContainmentID, Generation: binding.Record.ProcessGeneration}
		permit := native.ConsumedPermit
		if native.Process == nil || *native.Process != want || permit == nil || permit.LaunchID != binding.Record.ID || permit.PreparedID != prepared.ID || permit.RecordSHA256 != binding.Identity.RecordSHA256 || permit.CommittedSeq != binding.Identity.CommittedSeq {
			return serviceError(api.CodeIntegrity, "review recovery changed the native consumed permit")
		}
		process = want
	} else if native.GateState != "prepared" || native.Observation.State != "prepared" || native.Process != nil || native.ConsumedPermit != nil {
		return serviceError(api.CodeContainmentUnknown, "review original gate is neither known unopened nor consumed")
	}
	if process.ID == "" {
		open := func(ctx context.Context) error {
			permit, err := s.deps.Authenticator.BindLaunch(ctx, binding)
			if err != nil {
				return err
			}
			if permit.LaunchID != binding.Record.ID || permit.PreparedID != prepared.ID || permit.RecordSHA256 != binding.Identity.RecordSHA256 || permit.CommittedSeq != binding.Identity.CommittedSeq {
				return serviceError(api.CodeIntegrity, "review identity permit differs from its actual commit")
			}
			cause := *lease.Record.Effect.Context
			cause.Kind, cause.Actor = api.InternalHelperOpen, scope.Actor
			process, err = helper.OpenReviewWorker(ctx, job, lease, api.HelperOpenRequest{Cause: cause, Prepared: prepared, Permit: permit, OperationID: job.Intent.OperationID, EffectID: job.Lease.EffectID})
			return err
		}
		if guarded, ok := helper.(interface {
			WithWorkerLaunch(context.Context, api.PreparedLaunch, func(context.Context) error) error
		}); ok {
			err = guarded.WithWorkerLaunch(ctx, prepared, open)
		} else {
			return serviceError(api.CodePrerequisite, "review native worker handoff guard is unavailable")
		}
		if err != nil {
			return err
		}
	}
	if err := state.RecordReviewProcess(ctx, scope, lease, process); err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, expires.Sub(s.deps.Clock.Now()))
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		finish, err := s.workerTurn(waitCtx, job.Lease.ID, "review_observe")
		if err != nil {
			return err
		}
		observation, err := helper.ObserveReviewWorker(waitCtx, job, lease)
		finish()
		if err != nil {
			return err
		}
		if observation.Handle != process {
			return serviceError(api.CodeIntegrity, "review observed another native process")
		}
		if observation.State == "exited" {
			if observation.Survivors == nil || *observation.Survivors != 0 || (observation.ExitCode == nil) == (observation.Signal == nil) {
				return serviceError(api.CodeContainmentUnknown, "review verifier did not measure a successful known-zero exit")
			}
			if err := s.stopWorkerEndpoint(waitCtx, job.Lease.ID); err != nil {
				return err
			}
			proof, err := helper.RetireReviewWorker(waitCtx, job, lease)
			if err != nil {
				return err
			}
			if err := state.RecordReviewRetirement(waitCtx, scope, lease, proof); err != nil {
				return err
			}
			if proof.Release == nil {
				return serviceError(api.CodeContainmentUnknown, "review verifier has no native release measurement")
			}
			if observation.ExitCode == nil || *observation.ExitCode != 0 || observation.Signal != nil {
				if job.Lease.Kind == "test" {
					_, err = s.deps.Store.CompleteEffect(waitCtx, scope, api.EffectOutcome{EffectID: job.Lease.EffectID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation,
						Status: "failed", Error: serviceError(api.CodePrerequisite, "original native TestChild worker failed; retain its measured retirement"), Observation: &proof.Release.Quiescence})
					return err
				}
				return serviceError(api.CodePrerequisite, "original native review worker failed; retain its measured retirement")
			}
			ack, err := state.ReviewAcknowledgement(waitCtx, scope, lease)
			if err != nil {
				return err
			}
			observation = proof.Release.Quiescence
			_, err = s.deps.Store.CompleteEffect(waitCtx, scope, api.EffectOutcome{EffectID: job.Lease.EffectID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "succeeded", Output: &ack.Result, Observation: &observation})
			return err
		}
		if observation.State != "running" {
			return serviceError(api.CodeContainmentUnknown, "review verifier process state is unknown")
		}
		select {
		case <-waitCtx.Done():
			return contextError(waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func futureServiceTime(value api.Timestamp, now time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, string(value))
	return err == nil && t.After(now)
}
