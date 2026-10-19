package service

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type archiveStore interface {
	archivejob.Control
	ArchiveWorkerID(context.Context, api.Scope, api.EffectLease) (api.ID, error)
	ArchiveHandoff(context.Context, api.Scope, api.EffectLease, api.HelperLease, api.InstalledBinding) (api.PreparedSpecHandoff, error)
	BindArchiveWorker(context.Context, api.Scope, api.EffectLease, api.PreparedLaunch) (api.LaunchBindingRequest, error)
	RecordArchiveProcess(context.Context, api.Scope, api.EffectLease, api.ProcessHandle) error
	CompleteArchive(context.Context, api.Scope, api.EffectLease, api.ProcessObservation) (api.Commit, error)
	ArchiveOutcome(context.Context, api.Scope, api.ID) (api.EffectOutcome, error)
}

// Administrator owns these native operations. Every method reconciles the
// same durable job/claim; it cannot allocate another worker after a lost reply.
type archiveHelper interface {
	ArchiveWorkerLease(context.Context, archivejob.Job, api.EffectLease) (api.HelperLease, error)
	RegisterArchiveWorker(context.Context, archivejob.Job, api.EffectLease, api.PreparedSpecHandoff, api.InstalledBinding) (api.PreparedSpecReceipt, error)
	PrepareArchiveWorker(context.Context, archivejob.Job, api.EffectLease) (api.PreparedLaunch, error)
	OpenArchiveWorker(context.Context, archivejob.Job, api.EffectLease, api.HelperOpenRequest) (api.ProcessHandle, error)
	ObserveArchiveWorker(context.Context, archivejob.Job, api.EffectLease) (api.ProcessObservation, error)
}

func (s *Server) runArchive(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.EffectOutcome, error) {
	store, ok := s.deps.Store.(archiveStore)
	if !ok {
		return api.EffectOutcome{}, api.NotImplemented("lb-v2-service", "durable archive worker store")
	}
	s.mu.RLock()
	helper, ok := s.runtime.Helper.(archiveHelper)
	s.mu.RUnlock()
	if !ok {
		return api.EffectOutcome{}, api.NotImplemented("lb-v2-admin", "protected archive worker allocation, gate and observation")
	}
	allocationStore, ok := s.deps.Store.(archiveRetirementStore)
	if !ok {
		return api.EffectOutcome{}, api.NotImplemented("lb-v2-service", "durable archive allocation and measured retirement")
	}
	if _, ok := helper.(archivejob.RetirementHelper); !ok {
		return api.EffectOutcome{}, api.NotImplemented("lb-v2-admin", "archive stop/reap/release retirement")
	}
	job, err := store.ArchiveJob(ctx, scope, lease.Record.Effect.OperationID)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	workerDeadline, err := time.Parse(time.RFC3339Nano, string(job.Lease.ExpiresAt))
	if err != nil || !s.deps.Clock.Now().Before(workerDeadline) {
		observation, retireErr := s.retireArchive(ctx, scope, lease)
		if retireErr != nil {
			return api.EffectOutcome{}, retireErr
		}
		return api.EffectOutcome{Observation: observation}, serviceError(api.CodeDeadline, "archive worker budget expired; native retirement was measured")
	}
	recovery, err := allocationStore.ArchiveRecovery(ctx, scope, lease)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	if recovery.Retirement != nil {
		if recovery.Retirement.Boot != nil {
			return api.EffectOutcome{}, serviceError(api.CodeContainmentUnknown, "original archive retired after a measured host reboot; its exit status is unavailable")
		}
		if recovery.Retirement.Release == nil {
			return api.EffectOutcome{}, serviceError(api.CodePrerequisite, "original archive was natively aborted before execution")
		}
		observation := recovery.Retirement.Release.Quiescence
		if observation.ExitCode == nil || *observation.ExitCode != 0 || observation.Signal != nil {
			return api.EffectOutcome{Observation: &observation}, serviceError(api.CodeContainmentUnknown, "original archive retired with a measured failed worker")
		}
		if _, err := store.CompleteArchive(ctx, scope, lease, observation); err != nil {
			return api.EffectOutcome{Observation: &observation}, err
		}
		return store.ArchiveOutcome(ctx, scope, job.Intent.OperationID)
	}
	if err := allocationStore.BeginArchiveAllocation(ctx, scope, lease); err != nil {
		return api.EffectOutcome{}, err
	}
	allocation, err := helper.ArchiveWorkerLease(ctx, job, lease)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	if err := allocationStore.RecordArchiveAllocation(ctx, scope, lease, allocation); err != nil {
		return api.EffectOutcome{}, err
	}
	workerID, err := store.ArchiveWorkerID(ctx, scope, lease)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	endpoint := s.deps.Binding
	endpoint.Class, endpoint.LaunchID, endpoint.WorkerLeaseID, endpoint.Target = api.EndpointWorker, workerID, job.Lease.ID, &job.Lease.Target
	endpoint.Socket, endpoint.EndpointGeneration = "/runtime/laneboss-worker.sock", allocation.EndpointGeneration
	endpoint.MappedServiceUID, endpoint.MappedServiceGID, err = wire.NamespaceServiceIDs()
	if err != nil {
		return api.EffectOutcome{}, err
	}
	handoff, err := store.ArchiveHandoff(ctx, scope, lease, allocation, endpoint)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	if err := s.startWorkerEndpoint(ctx, job.Lease.ID, endpoint); err != nil {
		return api.EffectOutcome{}, err
	}
	registered, err := helper.RegisterArchiveWorker(ctx, job, lease, handoff, endpoint)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	if registered.SpecID != handoff.Spec.ID || registered.SpecSHA256 != handoff.SpecSHA256 || registered.Config != scope.Config || registered.Target != job.Lease.Target || registered.LeaseID != allocation.ID || registered.RuntimeManifest != job.Lease.RuntimeManifest || registered.OperationID != job.Lease.OperationID {
		return api.EffectOutcome{}, serviceError(api.CodeIntegrity, "archive helper registration changed its sealed worker")
	}
	prepared, err := helper.PrepareArchiveWorker(ctx, job, lease)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	binding, err := store.BindArchiveWorker(ctx, scope, lease, prepared)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	var process api.ProcessHandle
	if recovery.Handoff {
		if native, ok := helper.(interface {
			ReconcileArchiveWorker(context.Context, archivejob.Job, api.EffectLease) (api.LaunchReconciliation, error)
		}); ok {
			actual, err := native.ReconcileArchiveWorker(ctx, job, lease)
			if err != nil {
				return api.EffectOutcome{}, err
			}
			if actual.Prepared == nil || *actual.Prepared != prepared {
				return api.EffectOutcome{}, serviceError(api.CodeIntegrity, "archive recovery changed its prepared native gate")
			}
			if actual.GateState == "opened" {
				want := api.ProcessHandle{ID: binding.Record.ID, Target: binding.Record.Target, ContainmentID: binding.Record.ContainmentID, Generation: binding.Record.ProcessGeneration}
				permit := actual.ConsumedPermit
				if actual.Process == nil || *actual.Process != want || actual.Observation.Handle != want || permit == nil ||
					permit.LaunchID != binding.Record.ID || permit.PreparedID != prepared.ID || permit.RecordSHA256 != binding.Identity.RecordSHA256 || permit.CommittedSeq != binding.Identity.CommittedSeq ||
					recovery.Process.ID != "" && recovery.Process != want {
					return api.EffectOutcome{}, serviceError(api.CodeIntegrity, "archive recovery changed its consumed identity permit or process")
				}
				process = want
			} else if actual.GateState != "prepared" || actual.Observation.State != "prepared" || actual.Process != nil || actual.ConsumedPermit != nil || recovery.Process.ID != "" {
				return api.EffectOutcome{}, serviceError(api.CodeContainmentUnknown, "archive gate is not known unopened or already consumed")
			}
		}
	}
	open := func(ctx context.Context) error {
		permit, err := s.deps.Authenticator.BindLaunch(ctx, binding)
		if err != nil {
			return err
		}
		if permit.LaunchID != binding.Record.ID || permit.PreparedID != prepared.ID || permit.RecordSHA256 != binding.Identity.RecordSHA256 || permit.CommittedSeq != binding.Identity.CommittedSeq {
			return serviceError(api.CodeIntegrity, "archive permit differs from its actual identity commit")
		}
		cause := *lease.Record.Effect.Context
		cause.Kind, cause.Actor = api.InternalHelperOpen, scope.Actor
		process, err = helper.OpenArchiveWorker(ctx, job, lease, api.HelperOpenRequest{Cause: cause, Prepared: prepared, Permit: permit, OperationID: job.Lease.OperationID, EffectID: job.Lease.EffectID})
		return err
	}
	// An already opened gate above has its measured consumed permit. Only a
	// known unopened gate may request a new permit and native release.
	if process.ID == "" {
		if native, ok := helper.(interface {
			WithWorkerLaunch(context.Context, api.PreparedLaunch, func(context.Context) error) error
		}); ok {
			err = native.WithWorkerLaunch(ctx, prepared, open)
		} else {
			err = open(ctx)
		}
		if err != nil {
			return api.EffectOutcome{}, err
		}
	}
	if err := store.RecordArchiveProcess(ctx, scope, lease, process); err != nil {
		return api.EffectOutcome{}, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
	if err != nil {
		return api.EffectOutcome{}, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, deadline.Sub(s.deps.Clock.Now()))
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var lastObservation *api.ProcessObservation
	for {
		observation, err := s.observeArchive(waitCtx, helper, job, lease)
		if err != nil {
			return api.EffectOutcome{Observation: lastObservation}, err
		}
		if observation.Handle != process {
			return api.EffectOutcome{}, serviceError(api.CodeIntegrity, "archive observed another native worker")
		}
		lastObservation = &observation
		if observation.State == "exited" {
			if observation.Signal != nil || observation.ExitCode != nil && *observation.ExitCode != 0 {
				return api.EffectOutcome{Observation: &observation}, serviceError(api.CodeContainmentUnknown, "archive worker measured a nonzero exit or signal; preserve its workspace and inspect the retained observation")
			}
			retired, err := s.retireArchive(ctx, scope, lease)
			if err != nil || retired == nil {
				if err == nil {
					err = serviceError(api.CodeContainmentUnknown, "archive execution lacks its measured retired process")
				}
				return api.EffectOutcome{Observation: &observation}, err
			}
			observation = *retired
			if _, err := store.CompleteArchive(waitCtx, scope, lease, observation); err != nil {
				return api.EffectOutcome{Observation: &observation}, err
			}
			return store.ArchiveOutcome(waitCtx, scope, job.Intent.OperationID)
		}
		if observation.State != "running" {
			return api.EffectOutcome{Observation: &observation}, serviceError(api.CodeContainmentUnknown, "archive worker state is unknown")
		}
		select {
		case <-waitCtx.Done():
			return api.EffectOutcome{Observation: lastObservation}, contextError(waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (s *Server) observeArchive(ctx context.Context, helper archiveHelper, job archivejob.Job, lease api.EffectLease) (api.ProcessObservation, error) {
	finish, err := s.workerTurn(ctx, job.Lease.ID, "archive_observe")
	if err != nil {
		return api.ProcessObservation{}, err
	}
	defer finish()
	return helper.ObserveArchiveWorker(ctx, job, lease)
}

type cleanupStore interface {
	api.CleanupObjectStore
	CleanupReadbacks(api.Scope) api.CleanupReadbacks
}

func (s *Server) runCleanup(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.EffectOutcome, error) {
	store, ok := s.deps.Store.(cleanupStore)
	if !ok {
		return api.EffectOutcome{}, api.NotImplemented("lb-v2-service", "owned object inventory and independent cleanup completion")
	}
	s.mu.RLock()
	worker, ok := s.runtime.Worker.(api.CleanupDataWorker)
	s.mu.RUnlock()
	if !ok {
		return api.EffectOutcome{}, api.NotImplemented("lb-v2-grants", "authenticated CleanupDataWorker.CollectCleanup orchestration")
	}
	job, err := store.BeginCleanup(ctx, scope, lease)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	inventory, err := store.CleanupInventory(ctx, scope, job)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	receipt, err := worker.CollectCleanup(ctx, job)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	retained, err := store.CleanupReceipt(ctx, scope, receipt.ID)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	if !reflect.DeepEqual(retained, receipt) {
		return api.EffectOutcome{}, serviceError(api.CodeIntegrity, "collector returned an unretained or changed cleanup receipt")
	}
	verified, err := api.VerifyCleanup(ctx, store.CleanupReadbacks(scope), job, inventory, retained, s.deps.Clock)
	if err != nil {
		return api.EffectOutcome{}, err
	}
	if _, err := store.CompleteCleanup(ctx, scope, job, verified); err != nil {
		return api.EffectOutcome{}, err
	}
	return api.EffectOutcome{EffectID: lease.Record.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "succeeded", Output: &retained.Manifest}, nil
}
