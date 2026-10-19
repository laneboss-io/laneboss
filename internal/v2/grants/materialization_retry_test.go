package grants_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
)

// Native ownership is an explicit component boundary here. The real worker
// copies and hashes actual files; a result is available only after that work.
// The root companion measures the agent/worker UID handoff itself.
type borrowedStorageHelper struct {
	*materializationHelper
	resolves int
	fault    string
}

func (h *borrowedStorageHelper) ResolveLaunchStorage(ctx context.Context, request api.LaunchDataRequest) (api.LaunchStorage, error) {
	h.resolves++
	if h.f.result.ResultReceipt.StageID == "" {
		return api.LaunchStorage{}, &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-admin", Message: "private storage parent is not exclusively helper-owned"}
	}
	storage, err := h.launchJournal.ResolveLaunchStorage(ctx, request)
	if err != nil {
		return storage, err
	}
	if h.fault == "guard" {
		return api.LaunchStorage{}, &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-admin", Message: "component final storage ownership changed"}
	}
	if h.fault == "binding" {
		storage.WorkspaceID = "foreign-workspace"
	}
	return storage, nil
}

func TestMaterializationBorrowedStorageRetry(t *testing.T) {
	for _, fault := range []string{"", "guard", "binding"} {
		t.Run("case-"+fault, func(t *testing.T) {
			f := newMaterializationFixture(t)
			helper := &borrowedStorageHelper{materializationHelper: &materializationHelper{launchJournal: f.helper, f: f}, fault: fault}
			worker, err := dataworker.New(dataworker.Dependencies{Config: f.scope.Config, Controls: f, Store: f, Helper: helper, Launcher: &launchProbe{}, Clock: launchClock{}})
			if err != nil {
				t.Fatal(err)
			}
			stage := launchCopy(t, f.stage)
			deferred := &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-admin", Message: "component data_prepare is not ready"}
			f.stageErr = deferred
			if _, err := worker.MaterializeLaunch(context.Background(), f.request); !errors.Is(err, deferred) || helper.resolves != 0 {
				t.Fatal("materialization resolved agent-owned storage before resuming its borrowed stage", err)
			}
			f.stageErr = nil
			data, err := worker.MaterializeLaunch(context.Background(), f.request)
			if helper.resolves != 1 || f.resultCalls != 1 || f.awaitCalls != 1 || !reflect.DeepEqual(f.stage, stage) {
				t.Fatal("materialization replaced its stage or skipped final agent ownership verification", err)
			}
			if fault == "" {
				if err != nil || !reflect.DeepEqual(data, f.result.Data) {
					t.Fatal("original materialization retry did not complete its actual copy", err)
				}
			} else {
				var refusal *api.Error
				if !errors.As(err, &refusal) || refusal.Code != api.CodeIntegrity || !reflect.DeepEqual(data, api.LaunchData{}) {
					t.Fatal("materialization bypassed its final storage guard", err)
				}
			}
		})
	}
}
