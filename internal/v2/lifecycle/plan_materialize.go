package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// The fixed dataworker and service outbox own the child stage and its claim.
// A planner never guesses that ID, claims it as itself, or copies data as the
// service UID. Store absence with a retained DataStageID is an incomplete job.
func (execution *planExecution) materialize(ctx context.Context, inputs api.LaunchInputs, allocation api.HelperLease) (api.LaunchData, error) {
	s, r := execution.service, execution.record.Reservation
	request := api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: inputs.Grants.ID, LeaseID: allocation.ID, Claim: api.PlanningClaim(r.ID, execution.lease)}
	if err := execution.checkClaim(ctx); err != nil {
		return api.LaunchData{}, err
	}
	if err := execution.currentPolicy(ctx); err != nil {
		return api.LaunchData{}, err
	}
	stage, err := s.deps.Store.LaunchDataStage(ctx, execution.scope, request)
	if err == nil {
		if stage.Process.ID != "" {
			if err := api.ValidateLaunchDataStage(stage, request); err != nil {
				return api.LaunchData{}, failure(err)
			}
			child, err := s.deps.Store.Effect(ctx, execution.scope, stage.Worker.EffectID)
			if err != nil {
				return api.LaunchData{}, failure(err)
			}
			if child.Outcome != nil || execution.record.Plan != nil {
				return execution.materializedData(ctx, request, stage, inputs, allocation)
			}
			// An opened child without a measured result still belongs to its
			// original service stage. Drive its await/measurement path below;
			// the generic Worker reconciler deliberately does not execute it.
		}
		if stage.ID == "" || stage.Reservation.ID != r.ID || stage.AgentLeaseID != allocation.ID {
			return api.LaunchData{}, integrity("materialization preparation differs from its reserved job")
		}
	} else if !notFound(err) || execution.record.DataStageID != "" {
		return api.LaunchData{}, failure(err)
	}
	if absent(s.deps.Worker) {
		return api.LaunchData{}, api.NotImplemented("lb-v2-grants", "DataWorker.MaterializeLaunch")
	}
	data, err := s.deps.Worker.MaterializeLaunch(ctx, request)
	if err != nil {
		var temporary *api.Error
		if errors.As(err, &temporary) && temporary != nil && temporary.Code == api.CodeUnavailable && temporary.Retryable {
			// A wait can be joined with a failed read-view close or store read.
			// Keep every cause so the reconciler retries only a pure wait.
			return api.LaunchData{}, err
		}
		return api.LaunchData{}, failure(err)
	}
	if err := execution.checkClaim(ctx); err != nil {
		return api.LaunchData{}, err
	}
	stage, err = s.deps.Store.LaunchDataStage(ctx, execution.scope, request)
	if err != nil {
		return api.LaunchData{}, failure(err)
	}
	retained, err := execution.materializedData(ctx, request, stage, inputs, allocation)
	if err != nil {
		return api.LaunchData{}, err
	}
	if !reflect.DeepEqual(retained, data) {
		return api.LaunchData{}, integrity("dataworker result differs from its retained child completion")
	}
	return retained, nil
}

func (execution *planExecution) materializedData(ctx context.Context, request api.LaunchDataRequest, stage api.LaunchDataStage,
	inputs api.LaunchInputs, allocation api.HelperLease) (api.LaunchData, error) {
	s, r := execution.service, execution.record.Reservation
	if err := api.ValidateLaunchDataStage(stage, request); err != nil {
		return api.LaunchData{}, failure(err)
	}
	worker, err := s.deps.Store.WorkerLease(ctx, execution.scope, stage.Worker.ID)
	if err != nil {
		return api.LaunchData{}, failure(err)
	}
	wantWorker := stage.Worker
	if worker.Generation < stage.Worker.Generation || worker.Generation > stage.Worker.Generation+1 {
		return api.LaunchData{}, integrity("materialization worker revision is not its retained job")
	}
	wantWorker.Generation = worker.Generation
	if !reflect.DeepEqual(worker, wantWorker) {
		return api.LaunchData{}, integrity("materialization lost its retained worker lease mapping")
	}
	principal, err := s.deps.Store.Launch(ctx, stage.WorkerLaunchID)
	if err != nil {
		return api.LaunchData{}, failure(err)
	}
	if principal.Kind != "worker" || principal.Actor.Kind != "worker" || principal.Actor.Level != 0 || principal.Actor.Role != "" || principal.Revoked ||
		principal.ID != worker.ConsumedBy || principal.Target != worker.Target || principal.GrantSetID != worker.GrantSetID || principal.Config != r.Config ||
		principal.ContainmentID != stage.Process.ContainmentID || principal.ProcessGeneration != stage.Process.Generation || principal.HostUID == 0 || principal.HostUID == allocation.UID {
		return api.LaunchData{}, integrity("materialization did not retain its own confined worker principal")
	}
	if !reflect.DeepEqual(stage.Reservation, r) || !reflect.DeepEqual(stage.Inputs, inputs) || stage.AgentLeaseID != allocation.ID ||
		stage.ParentEffectID != execution.lease.Record.Effect.ID || stage.Claim.Record.Effect.ID == execution.lease.Record.Effect.ID ||
		execution.record.DataStageID != "" && execution.record.DataStageID != stage.ID {
		return api.LaunchData{}, integrity("materialization stage differs from its original parent reservation")
	}
	budget, ceiling := stage.Plan.Budget, execution.input.budget
	if !validBudget(budget) || budget.Currency != ceiling.Currency || budget.WallMS > ceiling.WallMS || budget.CPUSeconds > ceiling.CPUSeconds ||
		budget.MemoryBytes > ceiling.MemoryBytes || budget.Processes > ceiling.Processes || budget.DiskBytes > ceiling.DiskBytes || budget.SpendMicros > ceiling.SpendMicros {
		return api.LaunchData{}, integrity("materialization worker exceeds its remaining task budget")
	}
	raw, err := s.readBlob(ctx, execution.scope, inputs.Sources.Runtime.Manifest)
	if err != nil {
		return api.LaunchData{}, err
	}
	var runtime api.RuntimeManifest
	if api.DecodeObject(raw, &runtime) != nil || stage.Plan.Executable != runtime.Artifact {
		return api.LaunchData{}, integrity("materialization stage changed its installed worker executable")
	}
	if _, err := s.readBlob(ctx, execution.scope, stage.Worker.Input); err != nil {
		return api.LaunchData{}, err
	}
	current, err := s.deps.Store.LaunchPlan(ctx, execution.scope, r.ID)
	if err != nil {
		return api.LaunchData{}, failure(err)
	}
	if current.DataStageID != stage.ID || !reflect.DeepEqual(current.Reservation, r) || current.Inputs == nil || !reflect.DeepEqual(*current.Inputs, inputs) ||
		current.Generation < execution.record.Generation || current.Phase != execution.record.Phase || !reflect.DeepEqual(current.Plan, execution.record.Plan) {
		return api.LaunchData{}, integrity("materialization stage has no exact retained plan journal")
	}
	execution.record = current
	record, err := s.deps.Store.Effect(ctx, execution.scope, stage.Worker.EffectID)
	if err != nil {
		return api.LaunchData{}, failure(err)
	}
	if effectRecord(record) != nil || !reflect.DeepEqual(record.Effect, stage.Claim.Record.Effect) {
		return api.LaunchData{}, integrity("materialization completion changed its original child effect")
	}
	if record.Outcome != nil && effectCompletion(record, stage.Claim) != nil {
		return api.LaunchData{}, integrity("materialization completion lost its retained claim")
	}
	if record.Outcome != nil && record.Outcome.Error != nil {
		return api.LaunchData{}, record.Outcome.Error
	}
	if record.State != api.EffectCompleted || record.Outcome == nil || record.Outcome.Status != "succeeded" || record.Outcome.EffectID != stage.Worker.EffectID ||
		record.Outcome.Output == nil || record.Outcome.Output.Class != "worker_result" || record.Outcome.Observation == nil {
		return api.LaunchData{}, problem(api.CodeContainmentUnknown, "materialization child has no measured completion", "Await the original service-owned child stage without claiming or replacing it.")
	}
	observation := *record.Outcome.Observation
	if observation.Handle != stage.Process || observation.State != "exited" || observation.ExitCode == nil || *observation.ExitCode != 0 ||
		observation.Survivors == nil || *observation.Survivors != 0 || !validTime(observation.ObservedAt) {
		return api.LaunchData{}, integrity("materialization completion has no correlated terminal zero observation")
	}
	meta, err := s.deps.Store.ObjectMetadata(ctx, execution.scope, record.Outcome.Output.ID)
	if err != nil {
		return api.LaunchData{}, failure(err)
	}
	if meta.SourceOperationID != r.OperationID || meta.Origin != "worker" && meta.Origin != "service" {
		return api.LaunchData{}, integrity("materialization completion has foreign worker provenance")
	}
	if meta.Origin == "worker" && meta.ACL.Owner != principal.Actor {
		return api.LaunchData{}, integrity("materialization output belongs to a foreign worker principal")
	}
	output, err := s.readBlob(ctx, execution.scope, *record.Outcome.Output)
	if err != nil {
		return api.LaunchData{}, err
	}
	var data api.LaunchData
	if api.DecodeObject(output, &data) != nil {
		return api.LaunchData{}, integrity("materialization output is not exact LaunchData")
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return api.LaunchData{}, integrity("cannot encode materialization output")
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		return api.LaunchData{}, failure(err)
	}
	if !bytes.Equal(output, canonical) {
		return api.LaunchData{}, integrity("materialization output is not its acknowledged JCS bytes")
	}
	if err := execution.validateData(data, inputs, allocation); err != nil {
		return api.LaunchData{}, err
	}
	if _, err := s.readBlob(ctx, execution.scope, data.Materialization.Manifest); err != nil {
		return api.LaunchData{}, err
	}
	resolver, ok := s.deps.Sources.(api.LaunchStorageResolver)
	if !ok || absent(resolver) {
		return api.LaunchData{}, api.NotImplemented("lb-v2-admin", "LaunchStorageResolver.ResolveLaunchStorage")
	}
	storage, err := resolver.ResolveLaunchStorage(ctx, request)
	if err != nil {
		return api.LaunchData{}, failure(err)
	}
	if storage != stage.Storage.Storage {
		return api.LaunchData{}, integrity("materialization returned storage differs from its retained opened projection")
	}
	return data, nil
}
