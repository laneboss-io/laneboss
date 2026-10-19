package codex

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// A sourced reservation is earlier than argv construction. Only an actual
// completed child stage or an already validated sealed plan supplies its data.
func (s *Service) materializedLaunch(ctx context.Context, record api.LaunchPlanRecord, parent api.EffectRecord, storage api.LaunchStorage) error {
	if record.Phase == "planned" || record.Phase == "spec_retained" {
		return nil // ValidateLaunchPlanRecord already validated the complete plan.
	}
	if !id(record.DataStageID) {
		return problem(api.CodePrerequisite, "Codex launch has no retained materialization stage")
	}
	r := record.Reservation
	stage, err := s.deps.Store.LaunchDataStage(ctx, s.deps.ReadScope, api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: storage.LeaseID})
	if err != nil {
		return dependencyError(err)
	}
	if err := api.ValidateLaunchDataStage(stage, api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: storage.LeaseID}); err != nil {
		return dependencyError(err)
	}
	if stage.ID != record.DataStageID || stage.ParentEffectID != parent.Effect.ID ||
		!reflect.DeepEqual(stage.Reservation, r) || !reflect.DeepEqual(stage.Inputs, *record.Inputs) || stage.Storage.Storage != storage {
		return problem(api.CodeIntegrity, "Codex materialization differs from the retained planning stage")
	}
	child, err := s.deps.Store.Effect(ctx, s.deps.ReadScope, stage.Worker.EffectID)
	if err != nil {
		return dependencyError(err)
	}
	if child.State != api.EffectCompleted || child.Outcome == nil || child.Outcome.Status != "succeeded" || child.Outcome.Error != nil ||
		child.Outcome.EffectID != child.Effect.ID || !reflect.DeepEqual(child.Effect, stage.Claim.Record.Effect) {
		return problem(api.CodeConflict, "Codex materialization child has not succeeded")
	}
	if s.deps.Materialization == nil {
		return api.NotImplemented("lb-v2-service", "service.AwaitMaterialization")
	}
	result, err := s.deps.Materialization.AwaitMaterialization(ctx, stage.ID)
	if err != nil {
		return dependencyError(err)
	}
	if err := api.ValidateLaunchDataResult(stage, result); err != nil {
		return dependencyError(err)
	}
	if child.Outcome.Output == nil || *child.Outcome.Output != result.ResultReceipt.Result ||
		child.Outcome.Observation == nil || !reflect.DeepEqual(*child.Outcome.Observation, result.Observation) {
		return problem(api.CodeIntegrity, "Codex materialization completion differs from measured output")
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, s.deps.ReadScope, result.ResultReceipt.Result.ID)
	if err != nil {
		return dependencyError(err)
	}
	if metadata.Origin != "service" || metadata.SourceOperationID != r.OperationID || metadata.ACL.Config != r.Config || metadata.ACL.LifeID != r.Target.LifeID {
		return problem(api.CodeIntegrity, "Codex materialization output has foreign provenance")
	}
	data, err := s.readBlob(ctx, result.ResultReceipt.Result)
	if err != nil {
		return err
	}
	var committed api.LaunchData
	if decode(data, &committed) != nil || !reflect.DeepEqual(committed, result.Data) {
		return problem(api.CodeIntegrity, "Codex materialization result differs from committed data")
	}
	return nil
}
