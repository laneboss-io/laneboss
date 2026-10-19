package migration

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type reviewMeasuredStore struct {
	*memStore
	change func(*api.QuiescenceReceipt)
}

func (store reviewMeasuredStore) MigrationQuiescence(ctx context.Context, scope api.Scope) (api.QuiescenceReceipt, error) {
	measured, err := store.memStore.MigrationQuiescence(ctx, scope)
	if store.change != nil {
		store.change(&measured)
	}
	return measured, err
}
func TestReviewQuiescence(t *testing.T) {
	cases := map[string]func(*api.QuiescenceReceipt){
		"config":            func(q *api.QuiescenceReceipt) { q.Freeze.Config = "foreign" },
		"id":                func(q *api.QuiescenceReceipt) { q.ID = "" },
		"freeze":            func(q *api.QuiescenceReceipt) { q.Freeze.ID = "" },
		"epoch":             func(q *api.QuiescenceReceipt) { q.Freeze.DispatchEpoch = 0 },
		"unknown-processes": func(q *api.QuiescenceReceipt) { q.Observations = nil },
		"unknown-effects":   func(q *api.QuiescenceReceipt) { q.PendingEffectIDs = nil },
		"pending":           func(q *api.QuiescenceReceipt) { q.PendingEffectIDs = []api.ID{"pending"} },
		"capture":           func(q *api.QuiescenceReceipt) { q.PendingCaptureBytes = 1 },
		"timestamp":         func(q *api.QuiescenceReceipt) { q.ObservedAt = "invalid" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			service, state, scope, request := reviewRollback(t)
			service.deps.Store = reviewMeasuredStore{memStore: state, change: change}
			_, err := service.ExecuteRollback(context.Background(), scope, request)
			reviewError(t, err, api.CodeConflict, "rollback.quiescence", "unmeasured rollback quiescence was accepted")
		})
	}
	t.Run("stale", func(t *testing.T) {
		service, state, scope, request := reviewRollback(t)
		service.deps.Store = reviewMeasuredStore{memStore: state, change: func(q *api.QuiescenceReceipt) { q.ObservedAt = "2000-01-01T00:00:00Z" }}
		_, err := service.ExecuteRollback(context.Background(), scope, request)
		reviewError(t, err, api.CodeConflict, "rollback.quiescence observation is stale", "stale rollback measurement was accepted")
	})
}

func TestReviewRole(t *testing.T) {
	service, _, scope, options := reviewRelaunch(t)
	if _, err := service.PrepareRelaunch(context.Background(), scope, options); err != nil {
		t.Fatal(err)
	}
	options.Role = "--role"
	_, err := service.PrepareRelaunch(context.Background(), scope, options)
	reviewError(t, err, api.CodeInvalid, "relaunch role", "invalid relaunch role was accepted")
}
