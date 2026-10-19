package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type launchStageResult struct {
	Schema string          `json:"schema"`
	Input  api.Digest      `json:"input"`
	Value  json.RawMessage `json:"value,omitempty"`
	Error  *api.Error      `json:"error,omitempty"`
}

// This process-local marker distinguishes an immutable failed stage from a
// still-running port. It retains the original refusal and adds no wire state.
type retainedLaunchStageFailure struct {
	stage string
	cause *api.Error
}

func (e *retainedLaunchStageFailure) Error() string                { return e.cause.Error() }
func (e *retainedLaunchStageFailure) Unwrap() error                { return e.cause }
func (e *retainedLaunchStageFailure) RetainedLaunchStage() string  { return e.stage }
func (e *retainedLaunchStageFailure) MarshalJSON() ([]byte, error) { return json.Marshal(e.cause) }

// An absent result after a persisted start is an uncertain external outcome.
// It never licenses a second credential acquisition, producer or private home.
func launchStage[T any](ctx context.Context, execution *planExecution, name string, input any,
	call func() (T, error)) (T, error) {
	var zero T
	encoded, err := json.Marshal(input)
	if err != nil {
		return zero, integrity("cannot encode launch stage input")
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		return zero, failure(err)
	}
	digest := digestOfBytes(canonical)
	outputID := launchObjectID(execution.record.Reservation.ID, "result-"+name)
	metadata, err := execution.service.deps.Store.ObjectMetadata(ctx, execution.scope, outputID)
	if err == nil {
		if metadata.Origin != "service" || metadata.SourceOperationID != execution.record.Reservation.OperationID || metadata.Ref.Class != "manifest" {
			return zero, integrity("launch stage output has foreign provenance")
		}
		bytes, err := execution.service.readBlob(ctx, execution.scope, metadata.Ref)
		if err != nil {
			return zero, err
		}
		var result launchStageResult
		if api.DecodeObject(bytes, &result) != nil || result.Schema != "laneboss.launch-stage.v2" || result.Input != digest {
			return zero, integrity("launch stage retry changed its retained inputs")
		}
		if result.Error != nil {
			if name == "capture" {
				api.ObserveHelperReason(ctx, result.Error, "capture_retained_failure")
				return zero, &retainedLaunchStageFailure{stage: name, cause: result.Error}
			}
			return zero, result.Error
		}
		if api.DecodeObject(result.Value, &zero) != nil {
			return zero, integrity("launch stage has no exact retained outcome")
		}
		return zero, nil
	}
	if !notFound(err) {
		return zero, failure(err)
	}
	_, err = execution.service.deps.Store.ObjectMetadata(ctx, execution.scope, launchObjectID(execution.record.Reservation.ID, "input-"+name))
	if err == nil {
		return zero, problem(api.CodeContainmentUnknown, "launch stage has an unacknowledged outcome",
			"Reconcile its original stage and retained resources; do not invoke a replacement.")
	}
	if !notFound(err) {
		return zero, failure(err)
	}
	if _, err := execution.retainBytes(ctx, "input-"+name, "manifest", canonical); err != nil {
		return zero, err
	}
	if err := execution.currentPolicy(ctx); err != nil {
		return zero, err
	}
	if err := execution.checkClaim(ctx); err != nil {
		return zero, err
	}
	result, err := call()
	if err != nil {
		typed := planError(err)
		if _, retainErr := execution.retain(ctx, "result-"+name, "manifest", launchStageResult{
			Schema: "laneboss.launch-stage.v2", Input: digest, Error: typed}); retainErr != nil {
			return zero, errors.Join(typed, retainErr)
		}
		return zero, typed
	}
	value, err := json.Marshal(result)
	if err != nil {
		return zero, integrity("cannot retain launch stage outcome")
	}
	if _, err := execution.retain(ctx, "result-"+name, "manifest", launchStageResult{
		Schema: "laneboss.launch-stage.v2", Input: digest, Value: value}); err != nil {
		return zero, err
	}
	return result, nil
}

func (execution *planExecution) childEffect(ctx context.Context, effect api.Effect) (api.EffectRecord, error) {
	if err := execution.checkClaim(ctx); err != nil {
		return api.EffectRecord{}, err
	}
	current, err := execution.service.deps.Store.Effect(ctx, execution.scope, effect.ID)
	created := notFound(err)
	if created {
		if err := execution.transact(ctx, api.StateWrites{}, []api.Effect{effect}, nil, nil); err != nil {
			return api.EffectRecord{}, err
		}
		current, err = execution.service.deps.Store.Effect(ctx, execution.scope, effect.ID)
	}
	if err != nil {
		return api.EffectRecord{}, failure(err)
	}
	if !reflect.DeepEqual(current.Effect, effect) {
		return api.EffectRecord{}, integrity("launch stage effect changed its recorded input")
	}
	if effectRecord(current) != nil || created && (current.State != api.EffectPending || current.Generation != 1) {
		return api.EffectRecord{}, integrity("launch stage state differs from its retained outcome")
	}
	return current, nil
}

func (execution *planExecution) claimChild(ctx context.Context, record api.EffectRecord) (api.EffectLease, error) {
	if effectRecord(record) != nil || record.State != api.EffectPending && record.State != api.EffectClaimed {
		return api.EffectLease{}, integrity("launch stage is not pending or claimed")
	}
	if record.State == api.EffectClaimed {
		expires, err := time.Parse(time.RFC3339Nano, string(record.ClaimExpiresAt))
		if !validID(record.ClaimID) || err != nil {
			return api.EffectLease{}, problem(api.CodeConflict, "launch stage is claimed by another executor", "Reconcile its original durable claim.")
		}
		if execution.service.deps.Clock.Now().Before(expires) {
			if record.ClaimantID != execution.scope.Actor.ID {
				return api.EffectLease{}, problem(api.CodeConflict, "launch stage is claimed by another executor", "Reconcile its original durable claim.")
			}
			return api.EffectLease{Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt}, nil
		}
	}
	lease, err := execution.service.deps.Store.ClaimEffect(ctx, execution.scope, api.EffectClaimRequest{
		EffectID: record.Effect.ID, ExpectedGeneration: record.Generation, ClaimantID: execution.scope.Actor.ID,
		Deadline: execution.lease.ExpiresAt})
	if err != nil {
		return api.EffectLease{}, failure(err)
	}
	current, err := execution.service.deps.Store.Effect(ctx, execution.scope, record.Effect.ID)
	if err != nil {
		return api.EffectLease{}, failure(err)
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
	if effectRecord(current) != nil || !validID(lease.ClaimID) || !reflect.DeepEqual(current, lease.Record) ||
		!reflect.DeepEqual(current.Effect, record.Effect) || current.Generation <= record.Generation ||
		current.ClaimID != lease.ClaimID || current.ClaimantID != execution.scope.Actor.ID || current.ClaimExpiresAt != lease.ExpiresAt ||
		current.State != api.EffectClaimed || parseErr != nil || !execution.service.deps.Clock.Now().Before(expires) {
		return api.EffectLease{}, problem(api.CodeConflict, "launch stage claim is not current", "Claim and reconcile the same retained effect.")
	}
	return lease, nil
}

func (execution *planExecution) completeChild(ctx context.Context, lease api.EffectLease, outcome api.EffectOutcome) error {
	if effectRecord(lease.Record) != nil || !api.EffectLeaseClaimed(lease) || !validID(lease.ClaimID) ||
		lease.Record.ClaimID != lease.ClaimID || lease.Record.ClaimantID != execution.scope.Actor.ID || lease.Record.ClaimExpiresAt != lease.ExpiresAt {
		return integrity("launch stage completion requires its original claimed lease")
	}
	if err := execution.checkClaim(ctx); err != nil {
		return err
	}
	outcome.EffectID, outcome.ClaimID, outcome.ExpectedGeneration = lease.Record.Effect.ID, lease.ClaimID, lease.Record.Generation
	if outcome.Status == "" {
		outcome.Status = "succeeded"
	}
	expectedState := api.EffectCompleted
	if outcome.Status == "failed" {
		expectedState = api.EffectFailed
	} else if outcome.Status != "succeeded" {
		return integrity("launch stage has an invalid outcome status")
	}
	if outcome.Status == "failed" && outcome.Error == nil || outcome.Status == "succeeded" && outcome.Error != nil {
		return integrity("launch stage outcome status differs from its error")
	}
	_, err := execution.service.deps.Store.CompleteEffect(ctx, execution.scope, outcome)
	if err != nil {
		return failure(err)
	}
	completed, err := execution.service.deps.Store.Effect(ctx, execution.scope, outcome.EffectID)
	if err != nil {
		return failure(err)
	}
	if effectCompletion(completed, lease) != nil || completed.State != expectedState || !reflect.DeepEqual(completed.Effect, lease.Record.Effect) || completed.Outcome == nil ||
		!reflect.DeepEqual(*completed.Outcome, outcome) || completed.Generation <= lease.Record.Generation {
		return integrity("launch stage completion did not retain its actual outcome")
	}
	return nil
}

func (execution *planExecution) failChild(ctx context.Context, lease api.EffectLease, err error) error {
	typed := planError(err)
	if transientPlan(err) {
		return typed
	}
	if retention := execution.completeChild(ctx, lease, api.EffectOutcome{Status: "failed", Error: typed}); retention != nil {
		return errors.Join(typed, retention)
	}
	return typed
}

func (execution *planExecution) allocate(ctx context.Context, inputs api.LaunchInputs) (api.HelperLease, error) {
	r := execution.record.Reservation
	cause := execution.cause(api.InternalHelperAllocate, "allocate")
	cause.EffectID = launchObjectID(r.ID, "allocate-effect")
	request := api.HelperLeaseRequest{ReservationID: r.ID, Cause: cause, Config: r.Config, LifeID: r.Target.LifeID,
		Backend: inputs.Sources.Runtime.Backend, Budget: execution.input.budget, RuntimeManifestID: inputs.Sources.Runtime.Manifest.ID}
	effect := api.Effect{ID: cause.EffectID, OperationID: r.OperationID, Context: &cause, HelperAllocate: &request}
	record, err := execution.childEffect(ctx, effect)
	if err != nil {
		return api.HelperLease{}, err
	}
	if record.Outcome != nil {
		if record.Outcome.EffectID != record.Effect.ID || record.Outcome.Status != "succeeded" || record.Outcome.HelperLease == nil || record.Outcome.Error != nil {
			if record.Outcome.Error != nil {
				return api.HelperLease{}, record.Outcome.Error
			}
			return api.HelperLease{}, problem(api.CodeContainmentUnknown, "helper allocation has no measured outcome", "Reconcile its original allocation journal.")
		}
		allocated := *record.Outcome.HelperLease
		if !validID(allocated.ID) || allocated.UID == 0 || allocated.GID == 0 || !validID(allocated.ContainmentID) || !validGeneration(allocated.EndpointGeneration) {
			return api.HelperLease{}, integrity("retained allocation lost its measured ownership")
		}
		return allocated, nil
	}
	lease, err := execution.claimChild(ctx, record)
	if err != nil {
		return api.HelperLease{}, err
	}
	// The retained child effect keeps the stable causal author.  The request
	// sent to the helper carries this attempt's live claimant so the admin
	// boundary cannot rebind a stale allocation call after reclaim.
	request.Cause.Actor = execution.scope.Actor
	helper, ok := execution.service.deps.Sources.(api.Helper)
	if !ok || absent(helper) {
		return api.HelperLease{}, execution.failChild(ctx, lease, api.NotImplemented("lb-v2-admin", "installed Helper.Allocate"))
	}
	allocated, err := helper.Allocate(api.WithEffectLease(ctx, lease), request)
	if err != nil {
		return api.HelperLease{}, execution.failChild(ctx, lease, err)
	}
	if !validID(allocated.ID) || allocated.UID == 0 || allocated.GID == 0 || !validID(allocated.ContainmentID) || !validGeneration(allocated.EndpointGeneration) {
		return api.HelperLease{}, integrity("helper allocation returned no measured ownership")
	}
	if err := execution.completeChild(ctx, lease, api.EffectOutcome{HelperLease: &allocated}); err != nil {
		return api.HelperLease{}, err
	}
	return allocated, nil
}

func (execution *planExecution) validateData(data api.LaunchData, inputs api.LaunchInputs, allocation api.HelperLease) error {
	r := execution.record.Reservation
	if data.ReservationID != r.ID || data.Target != r.Target || data.LeaseID != allocation.ID || data.Source != inputs.Sources.Project ||
		data.Workspace.LogicalCWD != "/work/main" || data.Workspace.Branch != "lane/"+string(r.Target.LifeID) ||
		!validID(data.Workspace.ID) || data.Workspace.ProjectID != data.Source.ProjectID || data.Workspace.Base != data.Source.Base ||
		!validBlob(data.Workspace.Snapshot) || data.Workspace.Snapshot.Class != "manifest" ||
		data.Home.LifeID != r.Target.LifeID || !validID(data.Home.RootID) || data.Home.RootID == data.Workspace.ID ||
		!validGeneration(data.Home.Generation) || !validID(data.Home.Home.ID) || !validID(data.Home.Home.HistoryID) ||
		data.Home.Home.WorkspaceID != data.Workspace.ID {
		return integrity("materialization returned foreign ownership or a caller path")
	}
	directory := data.Home.Home.VendorDirectory
	if directory == "" || path.IsAbs(directory) || path.Clean(directory) != directory || directory == "." ||
		directory == ".." || strings.HasPrefix(directory, "../") || strings.ContainsRune(directory, 0) {
		return integrity("materialization returned an escaping private home")
	}
	if data.Materialization.GrantSetID != inputs.Grants.ID || !validBlob(data.Materialization.Manifest) ||
		data.Materialization.Manifest.Class != "manifest" {
		return integrity("materialization lost its granted source receipt")
	}
	main := 0
	for _, object := range data.Materialization.Objects {
		if object.GrantID == data.Source.GrantID && object.WorkspaceID == data.Workspace.ID &&
			object.SourceIdentity != "" && object.DestinationIdentity != "" && object.SnapshotSHA256 == data.Workspace.Snapshot.SHA256 {
			main++
		}
	}
	if main != 1 {
		return integrity("materialization has no unique measured main workspace")
	}
	if r.Loop != nil && execution.input.previous == nil {
		return integrity("loop launch has no retained previous binding")
	}
	if execution.input.previous != nil {
		previous := execution.input.previous.Recovery
		if loop := r.Loop; loop != nil {
			if data.Home.RootID != previous.Home.RootID || data.Home.Home != previous.Home.Home || data.Home.Generation < previous.Home.Generation ||
				data.Workspace.ID != previous.Home.Home.WorkspaceID {
				return integrity("loop launch replaced its retained home or workspace")
			}
		} else if data.Home != previous.Home || data.Workspace.ID != previous.Home.Home.WorkspaceID {
			return integrity("retained launch replaced its private home or workspace")
		}
	}
	return nil
}
