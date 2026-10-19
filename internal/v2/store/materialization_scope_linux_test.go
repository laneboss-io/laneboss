//go:build linux

package store_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	datafx "laneboss.io/laneboss/internal/v2/store/matfx"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func dataFrameScope(t *testing.T, d *fx.DataFixture, method api.Method, params any) api.Scope {
	t.Helper()
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: d.F.Deps.Config,
		Method: method, RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, params)}
	var err error
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	scope := d.Worker
	scope.Request, scope.Frame = request, &fx.Frame{Raw: fx.JSON(t, request)}
	return scope
}

func requireDataScopeRefusal(t *testing.T, err error) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeForbidden ||
		typed.Message != "materialization workers must use dedicated job operations" {
		t.Fatal("generic data scope did not reach the dedicated-operation gate", err)
	}
}

// The fixture retains real stage/input/identity/result records with variable
// bytes. Native identity remains an explicit component double. These canaries
// target the store boundary directly, without claiming socket reachability.
func TestDataGenericScope(t *testing.T) {
	t.Run("non_worker", func(t *testing.T) {
		d := datafx.NewData(t)
		d.Open(t)
		ctx := context.Background()
		inputScope := dataFrameScope(t, d, api.Method(api.WorkerInputRead), api.WorkerInputRequest{LeaseID: d.Stage.Worker.ID})
		input, err := d.F.State.WorkerInput(ctx, inputScope, api.WorkerInputRequest{LeaseID: d.Stage.Worker.ID})
		if err != nil || input.Input != d.Stage.Worker.Input || fx.Digest(input.Bytes) != input.Input.SHA256 {
			t.Fatal("dedicated worker input control failed", err)
		}
		query := api.BlobReadRequest{ObjectID: d.Stage.Inputs.Sources.Project.Object.ID, Limit: api.MaxChunkBytes}
		objectScope := dataFrameScope(t, d, api.Method(api.WorkerObjectRead), query)
		chunk, err := d.F.State.WorkerObject(ctx, objectScope, query)
		if err != nil || fx.Digest(chunk.Data) != d.Stage.Inputs.Sources.Project.Object.SHA256 {
			t.Fatal("dedicated worker object control failed", err)
		}
		policy, err := d.F.State.Policy(ctx, d.F.Execution)
		if err != nil || policy.Generation == 0 {
			t.Fatal("protected policy control failed", err)
		}
		scope := dataFrameScope(t, d, "policy.get", api.PolicyGetRequest{LifeID: d.Stage.Reservation.Target.LifeID})
		actual, err := d.F.State.Policy(ctx, scope)
		if err == nil {
			if !reflect.DeepEqual(actual, policy) {
				t.Fatal("generic policy canary returned unrelated bytes")
			}
			t.Fatal("materialize worker entered generic policy read")
		}
		requireDataScopeRefusal(t, err)
		if !reflect.ValueOf(actual).IsZero() {
			t.Fatal("refused generic policy read returned data")
		}
	})
	t.Run("result_append", func(t *testing.T) {
		d := datafx.NewData(t)
		d.Open(t)
		ctx := context.Background()
		_, raw := d.Result(t)
		submission := d.Submission(raw)
		scope := dataFrameScope(t, d, api.Method(api.WorkerResultAppend), submission)
		// BeginRead reaches generic scope without the public Methods shape
		// gate. Restoring the original input.read shortcut must acquire a
		// real view here, not fail for an unknown public result method.
		view, err := d.F.State.BeginRead(ctx, scope)
		if view != nil {
			snapshot := view.Snapshot()
			if closeErr := view.Close(); closeErr != nil {
				t.Fatal("generic result canary could not close its view", closeErr)
			}
			if snapshot.Config != d.F.Deps.Config || snapshot.ID == "" {
				t.Fatal("generic result canary returned an unrelated snapshot")
			}
		}
		if err == nil {
			t.Fatal("materialize result entered generic read scope")
		}
		requireDataScopeRefusal(t, err)
		if view != nil {
			t.Fatal("refused generic result scope returned a view")
		}
		commit, err := d.F.State.Transact(ctx, api.Transaction{Scope: scope})
		requireDataScopeRefusal(t, err)
		if !reflect.ValueOf(commit).IsZero() {
			t.Fatal("refused generic result transaction returned a commit")
		}
		receipt, err := d.F.State.WorkerResult(ctx, scope, submission)
		if err != nil || receipt.Result.SHA256 != fx.Digest(raw) || receipt.Result.Bytes != int64(len(raw)) || receipt.CommittedSeq == 0 {
			t.Fatal("dedicated worker result control failed", err)
		}
		replay, err := d.F.State.WorkerResult(ctx, scope, submission)
		if err != nil || replay != receipt {
			t.Fatal("dedicated worker result replay control failed", err)
		}
	})
}
