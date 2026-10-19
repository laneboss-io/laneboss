package dataworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func (s *Service) initialMaterialization(ctx context.Context, state *lstate.State, request api.LaunchDataRequest) (api.LaunchData, error) {
	var zero api.LaunchData
	if missing(s.deps.Controls) {
		return zero, api.NotImplemented("lb-v2-service", "materialization control binding")
	}
	stage, err := s.deps.Controls.MaterializationStage(ctx, request)
	if err != nil {
		return zero, err
	}
	if err := api.ValidateLaunchDataStage(stage, request); err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(stage.Reservation, state.Record.Reservation) || !reflect.DeepEqual(stage.Inputs, *state.Record.Inputs) {
		return zero, lstate.Error(api.CodeConflict, "materialization stage differs from the sourced reservation and allocation")
	}
	if err := launchStorage(request, stage.Reservation, stage.Storage.Storage); err != nil {
		return zero, err
	}
	runtimeBytes, err := state.Read(ctx, stage.Worker.RuntimeManifest)
	if err != nil {
		return zero, err
	}
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(runtimeBytes, &runtime); err != nil {
		return zero, err
	}
	if runtime.Schema != "laneboss.runtime.v2" || stage.Plan.Executable != runtime.Artifact {
		return zero, lstate.Error(api.CodeForbidden, "materialization executable differs from the installed artifact")
	}
	opened, err := s.deps.Helper.OpenLaunchDataStorage(ctx, api.StorageProjectionRequest{StageID: stage.ID,
		ReservationID: request.ReservationID, AgentLeaseID: request.LeaseID, WorkerLeaseID: stage.Worker.ID, Claim: request.Claim})
	if err != nil {
		return zero, err
	}
	if opened != stage.Storage {
		return zero, lstate.Error(api.CodeIntegrity, "materialization opened storage differs from the held helper projection")
	}
	expected, err := materializationGrantShape(stage.Reservation, stage.Inputs, stage.Grants.ID, stage.Grants.Data[0].ID, stage.Grants.ExpiresAt)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(expected, stage.Grants) {
		return zero, lstate.Error(api.CodeForbidden, "materialization worker grants differ from the exact narrow source set")
	}
	jobExpiry, err := manifest.Time(stage.Grants.ExpiresAt)
	if err != nil {
		return zero, err
	}
	leaseExpiry, err := manifest.Time(stage.Worker.ExpiresAt)
	if err != nil {
		return zero, err
	}
	if jobExpiry.After(leaseExpiry) {
		return zero, lstate.Error(api.CodeForbidden, "materialization grants outlive their fixed worker lease")
	}
	copies, err := api.ValidateDataCopyProjections(stage.Inputs, stage.Storage)
	if err != nil {
		return zero, err
	}
	for _, copy := range copies {
		raw, err := state.Read(ctx, copy.Source)
		if err != nil {
			return zero, err
		}
		var source api.ObjectManifest
		if err := api.DecodeObject(raw, &source); err != nil {
			return zero, err
		}
		selected, file, err := manifest.CopySelection(source, copy.Grant.RelativePath)
		if err != nil {
			return zero, err
		}
		if file != copy.File || !reflect.DeepEqual(selected, copy.Manifest) {
			return zero, lstate.Error(api.CodeForbidden, "copy projection changed its pinned source selection")
		}
	}
	fresh, err := lstate.Load(ctx, s.deps.Store, s.deps.Config, state.Scope, stage.Reservation.ID)
	if err != nil {
		return zero, err
	}
	if fresh.Record.DataStageID != stage.ID || !reflect.DeepEqual(fresh.Record.Reservation, stage.Reservation) || !reflect.DeepEqual(fresh.Record.Inputs, &stage.Inputs) {
		return zero, errors.Join(lstate.Error(api.CodeIntegrity, "materialization stage is not retained by its planning reservation"), fresh.Close())
	}
	retained, err := s.deps.Store.LaunchDataStage(ctx, fresh.Scope, request)
	if err != nil {
		return zero, errors.Join(err, fresh.Close())
	}
	if !reflect.DeepEqual(retained, stage) {
		return zero, errors.Join(lstate.Error(api.CodeConflict, "materialization control differs from the store's original stage"), fresh.Close())
	}
	raw, err := fresh.Read(ctx, stage.Worker.Input)
	if err != nil {
		return zero, errors.Join(err, fresh.Close())
	}
	var input MaterializationInput
	if err := api.DecodeObject(raw, &input); err != nil {
		return zero, errors.Join(err, fresh.Close())
	}
	if err := validateMaterializationInput(input, stage); err != nil {
		return zero, errors.Join(err, fresh.Close())
	}
	if err := fresh.Close(); err != nil {
		return zero, err
	}
	result, err := s.deps.Controls.AwaitMaterialization(ctx, stage.ID)
	if err != nil {
		return zero, err
	}
	if err := api.ValidateLaunchDataResult(stage, result); err != nil {
		return zero, err
	}
	latest, err := lstate.Load(ctx, s.deps.Store, s.deps.Config, state.Scope, stage.Reservation.ID)
	if err != nil {
		return zero, err
	}
	data, verifyErr := s.readMaterializationResult(ctx, latest, stage, input, result)
	if err := errors.Join(verifyErr, latest.Close()); err != nil {
		return zero, err
	}
	return data, nil
}

func (s *Service) readMaterializationResult(ctx context.Context, state *lstate.State, stage api.LaunchDataStage, input MaterializationInput, result api.LaunchDataResult) (api.LaunchData, error) {
	var zero api.LaunchData
	if state.Record.DataStageID != stage.ID || !reflect.DeepEqual(state.Record.Reservation, stage.Reservation) || !reflect.DeepEqual(state.Record.Inputs, &stage.Inputs) {
		return zero, lstate.Error(api.CodeConflict, "materialization reservation changed before result read-back")
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, state.Scope, result.ResultReceipt.Result.ID)
	if err != nil {
		return zero, err
	}
	worker, err := s.deps.Store.Launch(ctx, stage.WorkerLaunchID)
	if err != nil {
		return zero, err
	}
	if worker.ID != stage.WorkerLaunchID || worker.Kind != "worker" || worker.Actor.Kind != "worker" || worker.Actor.Level != 0 || worker.Actor.Role != "" ||
		worker.Config != stage.Reservation.Config || worker.Target != stage.Worker.Target || worker.GrantSetID != stage.Grants.ID || worker.GrantsSHA256 != stage.Grants.SHA256 ||
		metadata.Ref != result.ResultReceipt.Result || metadata.SourceOperationID != stage.Reservation.OperationID ||
		metadata.Origin != "service" && metadata.Origin != "worker" || metadata.ACL.Config != state.Scope.Config || metadata.ACL.Audience != "private" || metadata.ACL.Generation == 0 || len(metadata.ACL.Participants) != 0 ||
		metadata.ACL.Owner != worker.Actor && (metadata.ACL.Owner.Kind != "service" || !manifest.ValidID(metadata.ACL.Owner.ID)) {
		return zero, lstate.Error(api.CodeIntegrity, "materialization acknowledgement lacks its retained worker and private operation provenance")
	}
	acknowledged, err := state.Read(ctx, result.ResultReceipt.Result)
	if err != nil {
		return zero, err
	}
	encoded, err := json.Marshal(result.Data)
	if err != nil {
		return zero, err
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(acknowledged, canonical) {
		return zero, lstate.Error(api.CodeIntegrity, "materialization result differs from its exact acknowledged JCS bytes")
	}
	if result.Data.Workspace.Snapshot != input.Output || result.Manifest != input.Output {
		return zero, lstate.Error(api.CodeIntegrity, "materialization changed its sealed output manifest")
	}
	raw, err := state.Read(ctx, result.Manifest)
	if err != nil {
		return zero, err
	}
	if manifest.Hash(raw) != result.ReadBackSHA256 {
		return zero, lstate.Error(api.CodeIntegrity, "materialization actual manifest read-back differs from its measurement")
	}
	var snapshot api.ObjectManifest
	if err := api.DecodeObject(raw, &snapshot); err != nil {
		return zero, err
	}
	if err := manifest.Object(snapshot); err != nil {
		return zero, err
	}
	if err := s.launchOutputs(ctx, state, result.Data, stage.Inputs.Grants); err != nil {
		return zero, err
	}
	claim, err := api.ReloadPlanningClaim(ctx, s.deps.Store, state.Scope, stage.Reservation.ID, stage.ParentEffectID, s.deps.Clock.Now())
	if err != nil {
		return zero, err
	}
	opened, err := s.deps.Helper.OpenLaunchDataStorage(ctx, api.StorageProjectionRequest{StageID: stage.ID,
		ReservationID: stage.Reservation.ID, AgentLeaseID: stage.AgentLeaseID, WorkerLeaseID: stage.Worker.ID, Claim: claim})
	if err != nil {
		return zero, err
	}
	if opened != stage.Storage {
		return zero, lstate.Error(api.CodeConflict, "materialization storage changed during result read-back")
	}
	// The worker temporarily owns the held destination roots. Ordinary agent
	// storage resolution must run only after the measured child has returned
	// them; it remains the unchanged final owner/mode/inode guard.
	storage, err := s.deps.Helper.ResolveLaunchStorage(ctx, api.LaunchDataRequest{ReservationID: stage.Reservation.ID,
		GrantSetID: stage.Reservation.GrantSetID, LeaseID: stage.AgentLeaseID, Claim: claim})
	if err != nil {
		return zero, err
	}
	if err := launchStorage(api.LaunchDataRequest{LeaseID: stage.AgentLeaseID}, stage.Reservation, storage); err != nil {
		return zero, err
	}
	if storage != stage.Storage.Storage {
		return zero, lstate.Error(api.CodeIntegrity, "materialization returned storage differs from its original allocated binding")
	}
	resolver, err := grants.New(grants.Dependencies{Config: s.deps.Config, Store: s.deps.Store, Worker: s, Clock: s.deps.Clock})
	if err != nil {
		return zero, err
	}
	current, err := resolver.Resolve(ctx, state.Scope, api.GrantResolveRequest{ReservationID: stage.Reservation.ID})
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(current, stage.Inputs.Grants) {
		return zero, lstate.Error(api.CodeConflict, "materialization grants changed during its child job")
	}
	sources, err := s.deps.Helper.ResolveLaunchSources(ctx, api.LaunchSourceRequest{ReservationID: stage.Reservation.ID, GrantSetID: stage.Reservation.GrantSetID, Claim: claim})
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(sources, stage.Inputs.Sources) {
		return zero, lstate.Error(api.CodeConflict, "materialization source enrollment changed during its child job")
	}
	return result.Data, nil
}
