package lifecycle

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestArchiveOwnScope(t *testing.T) {
	for _, mode := range []string{"own", "another_actor", "another_request"} {
		t.Run(mode, func(t *testing.T) {
			f := newTerminalFixture(t)
			ctx := context.Background()
			request := api.ArchiveRequest{Target: f.target, ExpectedGeneration: f.child.Generation}
			scope := f.fixture.scope("lane.archive", request, f.parent)
			receipt, err := f.service.pendingMutation(ctx, scope)
			if err != nil {
				t.Fatal(err)
			}
			end := f.store.events[len(f.store.events)-1]
			intent := ArchiveIntent{Request: request, OperationID: receipt.Operation.ID, EndEventID: end.ID, EndSeq: end.Seq, CancellationEpoch: f.child.CancellationEpoch}
			job, err := f.store.ReserveArchive(ctx, scope, intent)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.service.archiveJob(ctx, scope, f.store, f.child, intent, job); err != nil {
				t.Fatal("archive lost its own operation scope control", err)
			}
			if mode == "own" {
				return
			}
			effect := f.store.effects[job.Lease.EffectID]
			cause := *effect.Effect.Context
			if mode == "another_actor" {
				cause.RequestedBy.ID = launchIDForTest()
			} else {
				cause.CauseRequestID = launchIDForTest()
			}
			effect.Effect.Context = &cause
			f.store.effects[job.Lease.EffectID] = effect
			err = f.service.archiveJob(ctx, scope, f.store, f.child, intent, job)
			typed, ok := err.(*api.Error)
			if !ok || typed.Code != api.CodeIntegrity || typed.Message != "archive has no exact durable worker effect" {
				t.Fatal("archive borrowed another actor or request's worker scope", err)
			}
		})
	}
}
