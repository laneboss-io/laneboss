package service

import (
	"context"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/secrets"
)

type usageSource interface {
	UsageWorkerInput(context.Context, api.Scope, api.UsageWindowRequest) (api.UsageCredentialInput, error)
	api.CredentialBroker
}

type usageStore interface {
	PrepareUsageJob(context.Context, api.Scope, api.UsageCredentialInput) (api.UsageJob, error)
	UsageHandoff(context.Context, api.Scope, api.EffectLease, api.HelperLease, api.InstalledBinding, api.Injection) (api.PreparedSpecHandoff, error)
	BindUsageWorker(context.Context, api.Scope, api.EffectLease, api.PreparedLaunch) (api.LaunchBindingRequest, error)
	UsageStage(context.Context, api.Scope, api.ID) (api.UsageStage, error)
}

type usageHelper interface {
	UsageWorkerLease(context.Context, api.UsageJob, api.EffectLease) (api.HelperLease, error)
	RegisterUsageWorker(context.Context, api.UsageJob, api.EffectLease, api.PreparedSpecHandoff, api.InstalledBinding) (api.PreparedSpecReceipt, error)
	PrepareUsageWorker(context.Context, api.UsageJob, api.EffectLease) (api.PreparedLaunch, error)
	OpenUsageWorker(context.Context, api.UsageJob, api.EffectLease, api.HelperOpenRequest) (api.ProcessHandle, error)
	ObserveUsageWorker(context.Context, api.UsageJob, api.EffectLease) (api.ProcessObservation, error)
	CollectUsageWorker(context.Context, api.UsageJob, api.EffectLease) error
	WithWorkerLaunch(context.Context, api.PreparedLaunch, func(context.Context) error) error
}

type usageSession struct {
	job           api.UsageJob
	claim         api.EffectLease
	input         chan api.Scope
	result        chan secrets.UsageCommandResult
	inputGo       chan struct{}
	resultGo      chan struct{}
	inputOnce     sync.Once
	resultOnce    sync.Once
	inputRelease  sync.Once
	resultRelease sync.Once
	retireOnce    sync.Once
	retired       chan struct{}
	retireErr     error
}

type usageOwnerKey struct{}

var _ secrets.UsageJobControl = (*Server)(nil)

// UsageServiceScope binds the credential component to this installed service
// lifetime. It supplies no worker connection or frame.
func (s *Server) UsageServiceScope() (api.Scope, error) { return s.controlScope() }

func (s *Server) BindUsageSource(source usageSource) error {
	if source == nil {
		return serviceError(api.CodePrerequisite, "usage source is missing")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.usageSource != nil {
		return serviceError(api.CodeConflict, "usage source is already bound or closed")
	}
	s.usageSource = source
	return nil
}

// UsageBootstrap borrows the exact worker frame captured by the real listener.
// The owner marker is private process state, never a request field or authority.
func (s *Server) UsageBootstrap() api.WorkerBootstrap { return usageBootstrap{s} }

type usageBootstrap struct{ server *Server }

func (b usageBootstrap) WorkerInput(ctx context.Context, scope api.Scope, q api.WorkerInputRequest) (api.WorkerJobInput, error) {
	return b.server.WorkerInput(context.WithValue(ctx, usageOwnerKey{}, true), scope, q)
}
func (b usageBootstrap) WorkerResult(ctx context.Context, scope api.Scope, q api.WorkerResultSubmission) (api.WorkerResultReceipt, error) {
	result, err := b.server.WorkerResult(context.WithValue(ctx, usageOwnerKey{}, true), scope, q)
	return result, err
}

func (s *Server) StartUsage(ctx context.Context, caller api.Scope, request api.UsageWindowRequest) (api.Scope, error) {
	scope, err := s.controlScope()
	if err != nil {
		return api.Scope{}, err
	}
	if caller.Config != scope.Config || caller.Connection != nil || caller.Frame != nil || caller.Request.Method != "" || caller.Actor.Kind != "service" && caller.Actor.Kind != "watchdog" {
		return api.Scope{}, serviceError(api.CodeForbidden, "usage admission requires its installed internal requester")
	}
	s.mu.RLock()
	source := s.usageSource
	helper, helperOK := s.runtime.Helper.(usageHelper)
	s.mu.RUnlock()
	store, storeOK := s.deps.Store.(usageStore)
	if source == nil || !helperOK || !storeOK {
		return api.Scope{}, serviceError(api.CodePrerequisite, "usage job native adapters are not bound")
	}
	input, err := source.UsageWorkerInput(ctx, caller, request)
	if err != nil {
		return api.Scope{}, err
	}
	job, err := store.PrepareUsageJob(ctx, scope, input)
	if err != nil {
		return api.Scope{}, err
	}
	claim, err := s.deps.Store.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: job.Lease.ExpiresAt})
	if err != nil {
		return api.Scope{}, err
	}
	session := &usageSession{job: job, claim: claim, input: make(chan api.Scope, 1), result: make(chan secrets.UsageCommandResult, 1), inputGo: make(chan struct{}), resultGo: make(chan struct{}), retired: make(chan struct{})}
	s.mu.Lock()
	if s.usageJobs == nil {
		s.usageJobs = map[api.ID]*usageSession{}
	}
	s.usageJobs[job.Lease.ID] = session
	s.mu.Unlock()
	allocation, err := helper.UsageWorkerLease(ctx, job, claim)
	if err != nil {
		return api.Scope{}, err
	}
	endpoint := s.deps.Binding
	endpoint.Class, endpoint.LaunchID, endpoint.WorkerLeaseID, endpoint.Target = api.EndpointWorker, job.LaunchID, job.Lease.ID, &job.Lease.Target
	endpoint.Socket, endpoint.EndpointGeneration = "/runtime/laneboss-worker.sock", allocation.EndpointGeneration
	endpoint.MappedServiceUID, endpoint.MappedServiceGID, err = wire.NamespaceServiceIDs()
	if err != nil {
		return api.Scope{}, err
	}
	secret := job.Input.Source
	injection, err := source.InjectWorker(ctx, job.Lease, []api.WorkerCredential{{Name: secret.Name, SourceHandle: secret.SourceHandle, Version: secret.Version, Delivery: secret.Delivery, Target: secret.Target}})
	if err != nil {
		return api.Scope{}, err
	}
	handoff, err := store.UsageHandoff(ctx, scope, claim, allocation, endpoint, injection)
	if err != nil {
		return api.Scope{}, err
	}
	if err := s.startWorkerEndpoint(ctx, job.Lease.ID, endpoint); err != nil {
		return api.Scope{}, err
	}
	receipt, err := helper.RegisterUsageWorker(ctx, job, claim, handoff, endpoint)
	if err != nil {
		return api.Scope{}, err
	}
	if receipt.SpecSHA256 != handoff.SpecSHA256 || receipt.SpecID != handoff.Spec.ID || receipt.LeaseID != allocation.ID {
		return api.Scope{}, serviceError(api.CodeIntegrity, "usage helper changed the original sealed job")
	}
	prepared, err := helper.PrepareUsageWorker(ctx, job, claim)
	if err != nil {
		return api.Scope{}, err
	}
	binding, err := store.BindUsageWorker(ctx, scope, claim, prepared)
	if err != nil {
		return api.Scope{}, err
	}
	open := func(ctx context.Context) error {
		permit, err := s.deps.Authenticator.BindLaunch(ctx, binding)
		if err != nil {
			return err
		}
		cause := *claim.Record.Effect.Context
		cause.Kind, cause.Actor = api.InternalHelperOpen, scope.Actor
		process, err := helper.OpenUsageWorker(ctx, job, claim, api.HelperOpenRequest{Cause: cause, Prepared: prepared, Permit: permit, OperationID: job.Lease.OperationID, EffectID: job.Lease.EffectID})
		if err == nil && (process.ID != job.LaunchID || process.Target != job.Lease.Target || process.ContainmentID != allocation.ContainmentID || process.Generation != prepared.ProcessGeneration) {
			return serviceError(api.CodeIntegrity, "usage helper changed its consumed native process")
		}
		return err
	}
	if err := helper.WithWorkerLaunch(ctx, prepared, open); err != nil {
		return api.Scope{}, err
	}
	select {
	case real := <-session.input:
		if real.Connection == nil || real.Frame == nil {
			return api.Scope{}, serviceError(api.CodeUnauthenticated, "usage input lost its real native frame")
		}
		return real, nil
	case <-ctx.Done():
		return api.Scope{}, ctx.Err()
	}
}

func (s *Server) RunUsage(ctx context.Context, id api.ID) (secrets.UsageCommandResult, error) {
	s.mu.RLock()
	var session *usageSession
	for _, candidate := range s.usageJobs {
		if candidate.job.ID == id {
			session = candidate
			break
		}
	}
	s.mu.RUnlock()
	if session == nil {
		return secrets.UsageCommandResult{}, serviceError(api.CodePrerequisite, "usage stage has no actual native conversation")
	}
	session.inputRelease.Do(func() { close(session.inputGo) })
	select {
	case actual := <-session.result:
		return actual, nil
	case <-ctx.Done():
		return secrets.UsageCommandResult{}, ctx.Err()
	}
}

// FinishUsage releases the original result handler only after the broker has
// finished validating and retaining its evidence. The native producer remains
// alive throughout all peer/frame/provenance rechecks.
func (s *Server) FinishUsage(ctx context.Context, lease api.ID) error {
	s.mu.RLock()
	session := s.usageJobs[lease]
	s.mu.RUnlock()
	if session == nil {
		return serviceError(api.CodePrerequisite, "usage completion lost its original conversation")
	}
	session.inputRelease.Do(func() { close(session.inputGo) })
	session.resultRelease.Do(func() { close(session.resultGo) })
	session.retireOnce.Do(func() { s.retireUsage(session) })
	select {
	case <-session.retired:
		return session.retireErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) usageInputFrame(ctx context.Context, scope api.Scope) error {
	if ctx.Value(usageOwnerKey{}) == true {
		return nil
	}
	s.mu.RLock()
	session := s.usageJobs[scope.Connection.Binding().WorkerLeaseID]
	s.mu.RUnlock()
	if session == nil {
		return nil
	}
	session.inputOnce.Do(func() { session.input <- scope })
	select {
	case <-session.inputGo:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) usageResultFrame(ctx context.Context, scope api.Scope, submission api.WorkerResultSubmission) error {
	if ctx.Value(usageOwnerKey{}) == true {
		return nil
	}
	s.mu.RLock()
	session := s.usageJobs[scope.Connection.Binding().WorkerLeaseID]
	s.mu.RUnlock()
	if session == nil {
		return nil
	}
	if submission.LeaseID != session.job.Lease.ID || submission.InputSHA256 != session.job.Lease.Input.SHA256 {
		return serviceError(api.CodeIntegrity, "usage result frame belongs to another actual job")
	}
	var output secrets.UsageCommandResult
	if err := api.DecodeObject(submission.Result, &output); err != nil {
		return err
	}
	output.Scope = scope
	session.resultOnce.Do(func() { session.result <- output })
	select {
	case <-session.resultGo:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// UsageOwnsEffect makes the durable usage coordinator exclusive. A generic
// outbox scan cannot race it by claiming or completing this same native job.
func retainedUsage(ctx context.Context, store api.StateStore, scope api.Scope, effect api.Effect) (bool, error) {
	if effect.Worker == nil || effect.Worker.Kind != "usage" {
		return false, nil
	}
	owner, ok := store.(interface {
		UsageOwnsEffect(context.Context, api.Scope, api.Effect) (bool, error)
	})
	if !ok {
		return false, serviceError(api.CodePrerequisite, "usage outbox owner is missing")
	}
	return owner.UsageOwnsEffect(ctx, scope, effect)
}

func (s *Server) retireUsage(session *usageSession) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		session.retireErr = serviceError(api.CodeCancelled, "usage service closed before native retirement")
		close(session.retired)
		return
	}
	s.workers.Add(1)
	helper, ok := s.runtime.Helper.(usageHelper)
	s.mu.Unlock()
	go func() {
		defer s.workers.Done()
		defer close(session.retired)
		ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
		defer cancel()
		if !ok {
			session.retireErr = serviceError(api.CodePrerequisite, "usage retirement helper disappeared")
		} else {
			session.retireErr = s.completeUsage(ctx, session, helper)
		}
		if session.retireErr != nil {
			s.recordFault(session.retireErr)
		}
	}()
}

func (s *Server) completeUsage(ctx context.Context, session *usageSession, helper usageHelper) error {
	for {
		observation, err := helper.ObserveUsageWorker(ctx, session.job, session.claim)
		if err != nil {
			return err
		}
		if observation.Handle.ID != session.job.LaunchID || observation.Handle.Target != session.job.Lease.Target {
			return serviceError(api.CodeIntegrity, "usage retirement observed another process")
		}
		if observation.State == "exited" {
			if observation.Survivors == nil || *observation.Survivors != 0 || observation.ExitCode == nil && observation.Signal == nil {
				return serviceError(api.CodeContainmentUnknown, "usage retirement has no measured exit and zero survivors")
			}
			if err := helper.CollectUsageWorker(ctx, session.job, session.claim); err != nil {
				return err
			}
			scope, err := s.controlScope()
			if err != nil {
				return err
			}
			owner, ok := s.deps.Store.(interface {
				RecordUsageRetirement(context.Context, api.Scope, api.ID, api.ProcessObservation) error
			})
			if !ok {
				return serviceError(api.CodePrerequisite, "usage retirement writer disappeared")
			}
			if err := owner.RecordUsageRetirement(ctx, scope, session.job.ID, observation); err != nil {
				return err
			}
			if err := s.stopWorkerEndpoint(ctx, session.job.Lease.ID); err != nil {
				return err
			}
			s.mu.Lock()
			delete(s.usageJobs, session.job.Lease.ID)
			s.mu.Unlock()
			return nil
		}
		if observation.State != "running" {
			return serviceError(api.CodeContainmentUnknown, "usage process state is unknown")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
