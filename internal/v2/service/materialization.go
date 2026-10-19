package service

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// These private ports compose the single authoritative writer and the actual
// administrator helper. Neither side accepts public paths, argv or principals.
type materializationStore interface {
	api.WorkerIdentityStore
	api.WorkerBootstrap
	DataStage(context.Context, api.Scope, api.ID) (api.LaunchDataStage, error)
	SealDataStage(context.Context, api.Scope, api.ID, api.StorageProjection, api.HelperLease) (api.LaunchDataStage, error)
	RecordDataClaim(context.Context, api.Scope, api.ID, api.EffectLease) (api.LaunchDataStage, error)
	DataHandoff(context.Context, api.Scope, api.ID, api.InstalledBinding) (api.PreparedSpecHandoff, error)
	BindDataWorker(context.Context, api.Scope, api.ID, api.PreparedLaunch) (api.LaunchBindingRequest, error)
	RecordDataProcess(context.Context, api.Scope, api.ID, api.ProcessHandle) (api.LaunchDataStage, error)
	DataReceipt(context.Context, api.Scope, api.ID) (api.WorkerResultReceipt, error)
	DataResult(context.Context, api.Scope, api.ID) (api.LaunchDataResult, error)
	CompleteMaterialization(context.Context, api.Scope, api.ID, api.LaunchDataResult) (api.Commit, error)
	WorkerObject(context.Context, api.Scope, api.BlobReadRequest) (api.BlobChunk, error)
}

type materializationHelper interface {
	api.LaunchDataStorage
	DataWorkerLease(context.Context, api.StorageProjectionRequest) (api.HelperLease, error)
	RegisterDataWorker(context.Context, api.StorageProjectionRequest, api.PreparedSpecHandoff, api.InstalledBinding) (api.PreparedSpecReceipt, error)
	PrepareDataWorker(context.Context, api.StorageProjectionRequest) (api.PreparedLaunch, error)
	OpenDataWorker(context.Context, api.StorageProjectionRequest, api.HelperOpenRequest) (api.ProcessHandle, error)
	ObserveDataWorker(context.Context, api.StorageProjectionRequest) (api.ProcessObservation, error)
	MeasureDataWorker(context.Context, api.StorageProjectionRequest, api.WorkerResultReceipt) (api.LaunchDataResult, error)
}

func (s *Server) materializationPorts() (materializationStore, materializationHelper, error) {
	if _, err := s.controlScope(); err != nil {
		return nil, nil, err
	}
	store, ok := s.deps.Store.(materializationStore)
	if !ok {
		return nil, nil, serviceError(api.CodePrerequisite, "materialization requires the single store's durable worker ports")
	}
	s.mu.RLock()
	helper, ok := s.runtime.Helper.(materializationHelper)
	s.mu.RUnlock()
	if !ok {
		return nil, nil, api.NotImplemented("lb-v2-admin", "protected materialization worker control")
	}
	return store, helper, nil
}

func projectionRequest(stage api.LaunchDataStage, claims ...api.LaunchClaim) api.StorageProjectionRequest {
	var claim api.LaunchClaim
	if len(claims) == 1 {
		claim = claims[0]
	}
	return api.StorageProjectionRequest{StageID: stage.ID, ReservationID: stage.Reservation.ID, AgentLeaseID: stage.AgentLeaseID, WorkerLeaseID: stage.Worker.ID, Claim: claim}
}

func (s *Server) MaterializationStage(ctx context.Context, request api.LaunchDataRequest) (result api.LaunchDataStage, resultErr error) {
	check := "materialization_context"
	defer func() { api.ObserveHelperReason(ctx, resultErr, check) }()
	if err := ctx.Err(); err != nil {
		return api.LaunchDataStage{}, contextError(err)
	}
	store, helper, err := s.materializationPorts()
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	claim := request.Claim
	check = "materialization_parent"
	scope := api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: claim.ClaimantID}, Source: "worker"}
	parent, err := s.deps.Store.Effect(ctx, scope, claim.EffectID)
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	if parent.Outcome != nil {
		return api.LaunchDataStage{}, serviceError(api.CodeConflict, "launch input lookup has no current original stage claim")
	}
	if claim.ReservationID != request.ReservationID {
		return api.LaunchDataStage{}, serviceError(api.CodeConflict, "materialization planning selector names another reservation")
	}
	if err := api.CheckPlanningClaim(parent, claim, s.options.Config, s.deps.Clock.Now()); err != nil {
		return api.LaunchDataStage{}, err
	}
	plan, err := s.deps.Store.LaunchPlan(ctx, scope, request.ReservationID)
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	if err := api.ValidateLaunchPlanRecord(plan); err != nil {
		return api.LaunchDataStage{}, err
	}
	scope = api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: parent.ClaimantID}, Source: "worker", PolicyGeneration: plan.Reservation.PolicyGeneration}
	stage, err := s.deps.Store.LaunchDataStage(ctx, scope, request)
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	if stage.Process.ID != "" {
		if err := api.ValidateLaunchDataStage(stage, request); err != nil {
			return api.LaunchDataStage{}, err
		}
		return stage, nil // Historical launch-time stage is never a new open.
	}
	// Serialize preparation only. Contenders reload the retained store record;
	// no in-memory ID or completed-flight flag confers execution authority.
	key := "materialization:" + string(stage.ID)
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return api.LaunchDataStage{}, contextError(context.Canceled)
		}
		if s.flights == nil {
			s.flights = make(map[string]chan struct{})
		}
		if done := s.flights[key]; done != nil {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return api.LaunchDataStage{}, contextError(ctx.Err())
			case <-done:
			}
			stage, err = s.deps.Store.LaunchDataStage(ctx, scope, request)
			if err != nil {
				return api.LaunchDataStage{}, err
			}
			if stage.Process.ID != "" {
				return stage, api.ValidateLaunchDataStage(stage, request)
			}
			continue
		}
		s.flights[key] = make(chan struct{})
		s.mu.Unlock()
		break
	}
	defer func() { s.mu.Lock(); close(s.flights[key]); delete(s.flights, key); s.mu.Unlock() }()
	q := projectionRequest(stage, request.Claim)
	check = "materialization_storage"
	opened, err := helper.OpenLaunchDataStorage(ctx, q)
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	check = "materialization_allocation"
	allocation, err := helper.DataWorkerLease(ctx, q)
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	check = "materialization_seal"
	stage, err = store.SealDataStage(ctx, scope, stage.ID, opened, allocation)
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	if stage.Claim.Record.Effect.ID == stage.ParentEffectID {
		check = "materialization_claim"
		current, err := s.deps.Store.Effect(ctx, scope, stage.Worker.EffectID)
		if err != nil {
			return api.LaunchDataStage{}, err
		}
		var claim api.EffectLease
		if current.ClaimID != "" {
			// A crash after claim but before recording may recover exactly that
			// claim. An expired/foreign claim never permits a replacement launch.
			if current.ClaimantID != scope.Actor.ID || current.Outcome != nil {
				return api.LaunchDataStage{}, serviceError(api.CodeConflict, "materialization child already belongs to another claim")
			}
			claim = api.EffectLease{Record: current, ClaimID: current.ClaimID, ExpiresAt: current.ClaimExpiresAt}
		} else {
			claim, err = s.deps.Store.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: current.Effect.ID, ExpectedGeneration: current.Generation, ClaimantID: scope.Actor.ID, Deadline: stage.Worker.ExpiresAt})
			if err != nil {
				return api.LaunchDataStage{}, err
			}
		}
		stage, err = store.RecordDataClaim(ctx, scope, stage.ID, claim)
		if err != nil {
			return api.LaunchDataStage{}, err
		}
	}
	endpoint := s.deps.Binding
	endpoint.Class, endpoint.LaunchID, endpoint.Target, endpoint.WorkerLeaseID = api.EndpointWorker, stage.WorkerLaunchID, &stage.Reservation.Target, stage.Worker.ID
	endpoint.Socket, endpoint.EndpointGeneration = "/runtime/laneboss-worker.sock", allocation.EndpointGeneration
	endpoint.MappedServiceUID, endpoint.MappedServiceGID, err = wire.NamespaceServiceIDs()
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	check = "materialization_handoff"
	handoff, err := store.DataHandoff(ctx, scope, stage.ID, endpoint)
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	check = "materialization_endpoint"
	if err := s.startDataEndpoint(ctx, stage, endpoint); err != nil {
		return api.LaunchDataStage{}, err
	}
	check = "materialization_register"
	receipt, err := helper.RegisterDataWorker(ctx, q, handoff, endpoint)
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	if receipt.SpecID != handoff.Spec.ID || receipt.SpecSHA256 != handoff.SpecSHA256 || receipt.Config != stage.Reservation.Config || receipt.Target != stage.Reservation.Target || receipt.LeaseID != allocation.ID || receipt.RuntimeManifest != stage.Worker.RuntimeManifest || receipt.OperationID != stage.Reservation.OperationID {
		return api.LaunchDataStage{}, serviceError(api.CodeIntegrity, "materialization helper registration changed its sealed spec")
	}
	check = "materialization_prepare"
	prepared, err := helper.PrepareDataWorker(ctx, q)
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	check = "materialization_bind"
	binding, err := store.BindDataWorker(ctx, scope, stage.ID, prepared)
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	var process api.ProcessHandle
	check = "materialization_open"
	open := func(ctx context.Context) error {
		permit, err := s.deps.Authenticator.BindLaunch(ctx, binding)
		if err != nil {
			return err
		}
		if permit.LaunchID != binding.Record.ID || permit.PreparedID != prepared.ID || permit.RecordSHA256 != binding.Identity.RecordSHA256 || permit.CommittedSeq != binding.Identity.CommittedSeq {
			return serviceError(api.CodeIntegrity, "materialization permit differs from its actual identity commit")
		}
		cause := *stage.Claim.Record.Effect.Context
		cause.Kind = api.InternalHelperOpen
		process, err = helper.OpenDataWorker(ctx, q, api.HelperOpenRequest{Cause: cause, Prepared: prepared, Permit: permit, OperationID: stage.Reservation.OperationID, EffectID: stage.Worker.EffectID})
		return err
	}
	if native, ok := helper.(interface {
		WithWorkerLaunch(context.Context, api.PreparedLaunch, func(context.Context) error) error
	}); ok {
		err = native.WithWorkerLaunch(ctx, prepared, open)
	} else {
		err = open(ctx)
	}
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	check = "materialization_process"
	stage, err = store.RecordDataProcess(ctx, scope, stage.ID, process)
	if err != nil {
		return api.LaunchDataStage{}, err
	}
	return stage, api.ValidateLaunchDataStage(stage, request)
}

func (s *Server) AwaitMaterialization(ctx context.Context, id api.ID) (result api.LaunchDataResult, resultErr error) {
	check := "materialization_context"
	defer func() {
		resultErr = materializationError(ctx, resultErr)
		api.ObserveHelperReason(ctx, resultErr, check)
	}()
	if err := ctx.Err(); err != nil {
		return api.LaunchDataResult{}, contextError(err)
	}
	if !wire.ValidID(string(id)) {
		return api.LaunchDataResult{}, wire.Invalid("invalid materialization stage selector")
	}
	store, helper, err := s.materializationPorts()
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	scope, err := s.controlScope()
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	stage, err := store.DataStage(ctx, scope, id)
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	if err := api.ValidateLaunchDataStage(stage, api.LaunchDataRequest{ReservationID: stage.Reservation.ID, GrantSetID: stage.Reservation.GrantSetID, LeaseID: stage.AgentLeaseID}); err != nil {
		return api.LaunchDataResult{}, err
	}
	scope.Actor.ID = stage.Claim.Record.ClaimantID
	check = "materialization_result"
	// Replays read the already committed measurement without observing or
	// opening another process. New waits share the original fixed deadline.
	if result, err := store.DataResult(ctx, scope, id); err == nil {
		return result, api.ValidateLaunchDataResult(stage, result)
	} else if !missingData(err) {
		return api.LaunchDataResult{}, err
	}
	check = "materialization_deadline"
	deadline, err := time.Parse(time.RFC3339Nano, string(stage.Claim.ExpiresAt))
	if err != nil {
		return api.LaunchDataResult{}, serviceError(api.CodeIntegrity, "materialization claim has no fixed expiry")
	}
	deadline = minTime(deadline, s.deps.Clock.Now().Add(time.Duration(min(stage.Plan.Budget.WallMS, int64(60000)))*time.Millisecond))
	remaining := deadline.Sub(s.deps.Clock.Now())
	if remaining <= 0 {
		return api.LaunchDataResult{}, serviceError(api.CodeDeadline, "materialization fixed deadline expired")
	}
	waitCtx, cancel := context.WithTimeout(ctx, remaining)
	defer func() {
		// Normalize before our own cleanup cancels the wait context.
		resultErr = materializationError(waitCtx, resultErr)
		cancel()
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		check = "materialization_wait"
		if err := waitCtx.Err(); err != nil {
			return api.LaunchDataResult{}, contextError(err)
		}
		if result, err := store.DataResult(waitCtx, scope, id); err == nil {
			return result, api.ValidateLaunchDataResult(stage, result)
		} else if !missingData(err) {
			return api.LaunchDataResult{}, err
		}
		check = "materialization_child_claim"
		current, err := s.deps.Store.Effect(waitCtx, scope, stage.Worker.EffectID)
		if err != nil {
			return api.LaunchDataResult{}, err
		}
		if current.Outcome != nil && current.Outcome.Error != nil {
			return api.LaunchDataResult{}, current.Outcome.Error
		}
		if current.ClaimID != stage.Claim.ClaimID || current.Generation != stage.Claim.Record.Generation || current.ClaimantID != scope.Actor.ID || !reflect.DeepEqual(current.Effect, stage.Claim.Record.Effect) {
			return api.LaunchDataResult{}, serviceError(api.CodeConflict, "materialization wait lost its original child claim")
		}
		claim, err := api.ReloadPlanningClaim(waitCtx, s.deps.Store, scope, stage.Reservation.ID, stage.ParentEffectID, s.deps.Clock.Now())
		if err != nil {
			return api.LaunchDataResult{}, err
		}
		q := projectionRequest(stage, claim)
		check = "materialization_process"
		observation, err := helper.ObserveDataWorker(waitCtx, q)
		if err != nil {
			return api.LaunchDataResult{}, err
		}
		if observation.Handle != stage.Process {
			return api.LaunchDataResult{}, serviceError(api.CodeIntegrity, "materialization observed another process")
		}
		if observation.State == "exited" {
			check = "materialization_exit_status"
			if observation.ExitCode != nil && *observation.ExitCode != 0 {
				check = "materialization_exit_code"
			}
			if observation.Signal != nil {
				check = "materialization_signal"
			}
			if observation.Survivors == nil || *observation.Survivors != 0 {
				check = "materialization_survivors"
			}
			if observation.ExitCode == nil || *observation.ExitCode != 0 || observation.Signal != nil || observation.Survivors == nil || *observation.Survivors != 0 {
				return api.LaunchDataResult{}, serviceError(api.CodeContainmentUnknown, "materialization did not measure successful zero-survivor exit")
			}
			check = "materialization_receipt"
			receipt, err := store.DataReceipt(waitCtx, scope, id)
			if err != nil {
				return api.LaunchDataResult{}, err
			}
			check = "materialization_result"
			measured, err := helper.MeasureDataWorker(waitCtx, q, receipt)
			if err != nil {
				return api.LaunchDataResult{}, err
			}
			if measured.ResultReceipt != receipt {
				return api.LaunchDataResult{}, serviceError(api.CodeIntegrity, "materialization measurement changed the actual worker receipt")
			}
			if err := api.ValidateLaunchDataResult(stage, measured); err != nil {
				return api.LaunchDataResult{}, err
			}
			if _, err := store.CompleteMaterialization(waitCtx, scope, id, measured); err != nil {
				return api.LaunchDataResult{}, err
			}
			return store.DataResult(waitCtx, scope, id)
		}
		if observation.State != "running" {
			return api.LaunchDataResult{}, serviceError(api.CodeContainmentUnknown, "materialization process state is unknown")
		}
		if polling, _ := ctx.Value(materializationPollKey{}).(bool); polling {
			check = "materialization_wait"
			return api.LaunchDataResult{}, &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-service", Retryable: true,
				Message: materializationWaitMessage, Instead: "Keep driving the original materialization stage under the same live planning attempt."}
		}
		select {
		case <-waitCtx.Done():
			return api.LaunchDataResult{}, contextError(waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func missingData(err error) bool {
	var typed *api.Error
	return errors.As(err, &typed) && typed.Code == api.CodeNotFound
}

func (s *Server) workerScope(ctx context.Context, transport api.Scope, operation api.WorkerOperation, params any) (api.Scope, error) {
	started := time.Now()
	scope, err := s.captureScope(ctx, transport)
	elapsed := time.Since(started)
	s.journalWorkerTiming("scope_capture", elapsed)
	if cost, ok := ctx.Value(workerCostKey{}).(*workerCost); ok {
		cost.scope += elapsed
	}
	if err != nil {
		return api.Scope{}, err
	}
	// Authorization uses the actual private frame. Scope/target/principal
	// labels in a caller-supplied Scope are never trusted.
	var request api.Request
	if err := api.DecodeObject(transport.Frame.Bytes(), &request); err != nil {
		return api.Scope{}, err
	}
	if request.Method != api.Method(operation) || request.Config != scope.Config || request.Proof != nil {
		return api.Scope{}, serviceError(api.CodeForbidden, "worker frame differs from its fixed operation")
	}
	digest, err := api.RequestDigest(request)
	if request.Protocol != api.Protocol || request.Schema != api.SchemaVersion || !wire.ValidID(string(request.RequestID)) || len(request.RequestID) < 22 || !wire.ValidID(string(request.IdempotencyKey)) || len(request.IdempotencyKey) < 22 || err != nil || digest != request.RequestSHA256 {
		return api.Scope{}, serviceError(api.CodeInvalid, "worker frame has invalid protocol, identity or digest")
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return api.Scope{}, err
	}
	if !wire.SameJSON(raw, request.Params) {
		return api.Scope{}, serviceError(api.CodeIntegrity, "worker parameters differ from their authenticated frame")
	}
	scope.Request = request
	started = time.Now()
	err = s.deps.Authenticator.Authorize(ctx, scope, request)
	elapsed = time.Since(started)
	s.journalWorkerTiming("scope_authorize", elapsed)
	if cost, ok := ctx.Value(workerCostKey{}).(*workerCost); ok {
		cost.authorize += elapsed
	}
	if err != nil {
		return api.Scope{}, err
	}
	return scope, nil
}

func (s *Server) WorkerInput(ctx context.Context, transport api.Scope, request api.WorkerInputRequest) (api.WorkerJobInput, error) {
	scope, err := s.workerScope(ctx, transport, api.WorkerInputRead, request)
	if err != nil {
		return api.WorkerJobInput{}, err
	}
	if err := s.usageInputFrame(ctx, scope); err != nil {
		return api.WorkerJobInput{}, err
	}
	store, ok := s.deps.Store.(api.WorkerBootstrap)
	if !ok {
		return api.WorkerJobInput{}, serviceError(api.CodePrerequisite, "worker input store is unavailable")
	}
	return store.WorkerInput(ctx, scope, request)
}

func (s *Server) WorkerResult(ctx context.Context, transport api.Scope, request api.WorkerResultSubmission) (api.WorkerResultReceipt, error) {
	started := time.Now()
	scope, err := s.workerScope(ctx, transport, api.WorkerResultAppend, request)
	s.journalWorkerTiming("result_scope", time.Since(started))
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	if err := s.usageResultFrame(ctx, scope, request); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	store, ok := s.deps.Store.(api.WorkerBootstrap)
	if !ok {
		return api.WorkerResultReceipt{}, serviceError(api.CodePrerequisite, "worker result store is unavailable")
	}
	started = time.Now()
	receipt, err := store.WorkerResult(ctx, scope, request)
	s.journalWorkerTiming("result_store", time.Since(started))
	return receipt, err
}
