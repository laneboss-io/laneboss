//go:build linux

package store_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	datafx "laneboss.io/laneboss/internal/v2/store/matfx"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func requireDataError(t *testing.T, err error, code api.ErrorCode, message string) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code || typed.Message != message {
		t.Fatal("materialization control reached an unrelated refusal", err)
	}
}

func TestDataStagePins(t *testing.T) {
	d := datafx.NewData(t)
	f, ctx := d.F, context.Background()
	plan, err := f.State.LaunchPlan(ctx, f.Execution, f.Reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.DataStageID != d.Stage.ID || plan.Generation != f.Record.Generation+1 {
		t.Fatal("data stage was not committed against its plan CAS")
	}
	again, err := f.State.LaunchDataStage(ctx, f.Execution, d.Request)
	if err != nil || !reflect.DeepEqual(again, d.Stage) {
		t.Fatal("data stage replay allocated another job", err)
	}
	changed := d.Request
	changed.GrantSetID = fx.ID(t)
	if _, err := f.State.LaunchDataStage(ctx, f.Execution, changed); err == nil {
		t.Fatal("data stage accepted drifted grant selector")
	} else {
		requireDataError(t, err, api.CodeConflict, "materialization selector differs from the sourced reservation")
	}
}

func TestWorkerInputOwnJob(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	input, err := d.F.State.WorkerInput(context.Background(), d.Worker, api.WorkerInputRequest{LeaseID: d.Stage.Worker.ID})
	if err != nil {
		t.Fatal(err)
	}
	if fx.Digest(input.Bytes) != d.Stage.Worker.Input.SHA256 || int64(len(input.Bytes)) != input.Input.Bytes {
		t.Fatal("worker input did not retain its actual bytes")
	}
	if _, err := d.F.State.WorkerInput(context.Background(), d.Worker, api.WorkerInputRequest{LeaseID: fx.ID(t)}); err == nil {
		t.Fatal("worker input read another job selector")
	} else {
		requireDataError(t, err, api.CodeForbidden, "worker cannot read another job input")
	}
	input.Bytes[0] ^= 1
	again, err := d.F.State.WorkerInput(context.Background(), d.Worker, api.WorkerInputRequest{LeaseID: d.Stage.Worker.ID})
	if err != nil || bytes.Equal(again.Bytes, input.Bytes) {
		t.Fatal("worker input returned mutable shared storage", err)
	}
	if _, err := d.F.State.WorkerObject(context.Background(), d.Worker, api.BlobReadRequest{ObjectID: d.F.Start.Task.ID, Limit: 1}); err == nil {
		t.Fatal("worker object read escaped its sealed inputs")
	}
}

func TestWorkerPrincipalPins(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	facts, err := d.Worker.Connection.Peer().Facts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.F.State.WorkerBinding(context.Background(), d.Endpoint, facts)
	if err != nil || p.StageID != d.Stage.ID || p.Lease != d.Stage.Worker {
		t.Fatal("worker principal did not resolve its retained job", err)
	}
	facts.ProcessGeneration = "old-boot:other-process"
	if _, err := d.F.State.WorkerBinding(context.Background(), d.Endpoint, facts); err == nil {
		t.Fatal("worker principal accepted another native boot")
	} else {
		requireDataError(t, err, api.CodeContainmentUnknown, "worker native generation differs from the retained boot")
	}
}

func TestDataStageGrantDrift(t *testing.T) {
	d := datafx.NewData(t)
	f := d.F
	grant := d.Stage.Inputs.Grants
	grant.Generation++
	grant.Revoked = true
	cause := f.Intent(t, api.InternalLifecycleEffect)
	if _, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Grants: []api.GrantSet{grant}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.LaunchDataStage(context.Background(), f.Execution, d.Request); err == nil {
		t.Fatal("data stage accepted changed issued grants")
	} else {
		requireDataError(t, err, api.CodeForbidden, "launch grants changed, expired or revoked")
	}
}

func TestWorkerResultMeasurement(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	data, _ := d.Result(t)
	data.Materialization.Objects[0].SourceIdentity = "changed-source-inode"
	raw, err := api.CanonicalJSON(fx.JSON(t, data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.F.State.WorkerResult(context.Background(), d.Worker, d.Submission(raw)); err == nil {
		t.Fatal("worker result accepted a changed source measurement")
	} else {
		requireDataError(t, err, api.CodeIntegrity, "worker result changed the opened source or destination measurement")
	}
}

func TestWorkerResultOwnJob(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	_, raw := d.Result(t)
	request := d.Submission(raw)
	request.LeaseID = fx.ID(t)
	if _, err := d.F.State.WorkerResult(context.Background(), d.Worker, request); err == nil {
		t.Fatal("worker result submitted another job selector")
	} else {
		requireDataError(t, err, api.CodeForbidden, "worker cannot submit another job result")
	}
}

func TestWorkerResultReplay(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	f, ctx := d.F, context.Background()
	_, raw := d.Result(t)
	request := d.Submission(raw)
	first, err := f.State.WorkerResult(ctx, d.Worker, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Result.SHA256 != fx.Digest(raw) || first.Result.Bytes != int64(len(raw)) || first.CommittedSeq == 0 {
		t.Fatal("worker result receipt does not measure actual bytes")
	}
	before, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: f.Reservation.Target.LifeID, Run: f.Reservation.Target.Run})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.State.WorkerResult(ctx, d.Worker, request)
	if err != nil || replay != first {
		t.Fatal("worker result replay did not return the same receipt", err)
	}
	after, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: f.Reservation.Target.LifeID, Run: f.Reservation.Target.Run})
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("worker result replay appended another event", err)
	}
	request.Result = append(append([]byte{}, raw...), '\n')
	if _, err := f.State.WorkerResult(ctx, d.Worker, request); err == nil {
		t.Fatal("worker result replay accepted changed exact bytes")
	} else {
		requireDataError(t, err, api.CodeIdempotencyConflict, "worker result retry changed its exact bytes or input")
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	replay, err = f.State.WorkerResult(ctx, d.Worker, d.Submission(raw))
	if err != nil || replay != first {
		t.Fatal("worker result restart lost its original receipt", err)
	}
}

func TestDataResultNeedsMeasurement(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	f, ctx := d.F, context.Background()
	data, raw := d.Result(t)
	receipt, err := f.State.WorkerResult(ctx, d.Worker, d.Submission(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.DataResult(ctx, f.Execution, d.Stage.ID); err == nil {
		t.Fatal("worker acknowledgement became a measured completion")
	}
	zero, survivors := 0, uint64(0)
	observation := api.ProcessObservation{Handle: d.Stage.Process, State: "exited", ExitCode: &zero, Survivors: &survivors, PromptStatus: "completed", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	result := api.LaunchDataResult{StageID: d.Stage.ID, WorkerLeaseID: d.Stage.Worker.ID, EffectID: d.Stage.Worker.EffectID, OperationID: f.Reservation.OperationID, InputSHA256: d.Stage.Worker.Input.SHA256, Data: data, Manifest: data.Materialization.Manifest, ReadBackSHA256: data.Materialization.Manifest.SHA256, Observation: observation, ResultReceipt: receipt}
	bad := result
	bad.ReadBackSHA256 = fx.Digest([]byte("foreign readback"))
	if _, err := f.State.CompleteMaterialization(ctx, f.Execution, d.Stage.ID, bad); err == nil {
		t.Fatal("data completion accepted unmeasured readback")
	}
	first, err := f.State.CompleteMaterialization(ctx, f.Execution, d.Stage.ID, result)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.State.CompleteMaterialization(ctx, f.Execution, d.Stage.ID, result)
	if err != nil || !replay.Replayed || replay.LastSeq != first.LastSeq {
		t.Fatal("data completion did not commit once", err)
	}
	actual, err := f.State.DataResult(ctx, f.Execution, d.Stage.ID)
	if err != nil || !reflect.DeepEqual(actual, result) {
		t.Fatal("data completion lost its actual measured result", err)
	}
}
