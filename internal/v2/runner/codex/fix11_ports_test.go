package codex

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	storeport "laneboss.io/laneboss/internal/v2/store"
)

type dataStageOwnerPort struct {
	*memoryStore
	actual *storeport.Service
}

func (p dataStageOwnerPort) LaunchDataStage(ctx context.Context, scope api.Scope, request api.LaunchDataRequest) (api.LaunchDataStage, error) {
	return p.actual.LaunchDataStage(ctx, scope, request)
}

type usageWorkerOwnerPort struct {
	*memoryStore
	actual *storeport.Service
}

func (p usageWorkerOwnerPort) WorkerBinding(ctx context.Context, endpoint api.InstalledBinding, peer api.PeerFacts) (api.WorkerPrincipal, error) {
	return p.actual.WorkerBinding(ctx, endpoint, peer)
}

func TestDataOwnerRefusal(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.service.Start(ctx, f.request); err != nil {
		t.Fatal(err)
	}
	r := f.currentPlan().Reservation
	actual := &storeport.Service{}
	_, expected := actual.LaunchDataStage(ctx, f.service.deps.ReadScope, api.LaunchDataRequest{ReservationID: r.ID,
		GrantSetID: r.GrantSetID, LeaseID: f.store.effects[f.service.deps.AllocationEffectID].Outcome.HelperLease.ID})
	if expected == nil {
		t.Fatal("data stage owner unexpectedly available without installation")
	}
	f.service.deps.Store = dataStageOwnerPort{f.store, actual}
	plan, err := f.service.Start(ctx, f.request)
	if !reflect.DeepEqual(err, expected) || !reflect.DeepEqual(plan, api.RunnerPlan{}) {
		t.Fatal("data stage owner's refusal was not preserved", err)
	}
}

func TestUsageWorkerRefusal(t *testing.T) {
	f := newFixture(t)
	f.quotaProof()
	record, exit := f.endCapture([]byte("{\"type\":\"turn.failed\",\"error\":{\"code\":\"synthetic_quota\"}}\n"), 1)
	var native usageNative
	if err := f.store.retainedInternal(f.store.usage[record.Target].Native, &native); err != nil {
		t.Fatal(err)
	}
	actual := &storeport.Service{}
	_, expected := actual.WorkerBinding(context.Background(), native.Endpoint, native.Peer)
	if expected == nil {
		t.Fatal("usage worker owner unexpectedly available without installation")
	}
	f.service.deps.Store = usageWorkerOwnerPort{f.store, actual}
	signal, err := f.service.LimitFromCapture(context.Background(), record, exit)
	if !reflect.DeepEqual(err, expected) || signal != nil {
		t.Fatal("usage worker owner's refusal was not preserved", err)
	}
}
