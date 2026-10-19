//go:build linux

package store_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	datafx "laneboss.io/laneboss/internal/v2/store/matfx"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type materializationClock struct{ offset time.Duration }

func (c *materializationClock) Now() time.Time { return time.Now().Add(c.offset) }

func TestMaterializationReclaimKeepsStage(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "reserved", true: "completed"}[completed], func(t *testing.T) {
			clock := &materializationClock{}
			d := datafx.NewData(t, fx.DataOptions{Clock: clock, ParentTTL: time.Minute})
			f, ctx, old := d.F, context.Background(), d.F.Claim
			if completed {
				d.Open(t)
				data, raw := d.Result(t)
				receipt, err := f.State.WorkerResult(ctx, d.Worker, d.Submission(raw))
				if err != nil {
					t.Fatal(err)
				}
				zero, survivors := 0, uint64(0)
				result := api.LaunchDataResult{StageID: d.Stage.ID, WorkerLeaseID: d.Stage.Worker.ID, EffectID: d.Stage.Worker.EffectID,
					OperationID: f.Reservation.OperationID, InputSHA256: d.Stage.Worker.Input.SHA256, Data: data,
					Manifest: data.Materialization.Manifest, ReadBackSHA256: data.Materialization.Manifest.SHA256, ResultReceipt: receipt,
					Observation: api.ProcessObservation{Handle: d.Stage.Process, State: "exited", ExitCode: &zero, Survivors: &survivors,
						PromptStatus: "completed", ObservedAt: api.Timestamp(clock.Now().UTC().Format(time.RFC3339Nano))}}
				if _, err := f.State.CompleteMaterialization(ctx, f.Execution, d.Stage.ID, result); err != nil {
					t.Fatal(err)
				}
			}
			before, err := f.State.DataStage(ctx, f.Execution, d.Stage.ID)
			if err != nil {
				t.Fatal(err)
			}
			if before.ParentClaim != api.StablePlanningPin(f.Reservation.ID, old.Record.Effect.ID) {
				t.Fatal("stage persisted volatile parent attempt ownership")
			}
			clock.offset += 2 * time.Minute
			freshScope := f.Execution
			freshScope.Actor.ID = fx.ID(t)
			fresh, err := f.State.ClaimEffect(ctx, freshScope, api.EffectClaimRequest{EffectID: old.Record.Effect.ID,
				ExpectedGeneration: old.Record.Generation, ClaimantID: freshScope.Actor.ID,
				Deadline: api.Timestamp(clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
			if err != nil || fresh.ClaimID == old.ClaimID || fresh.Record.Generation <= old.Record.Generation {
				t.Fatal("actual parent reclaim failed", err)
			}
			request := d.Request
			request.Claim = api.PlanningClaim(f.Reservation.ID, fresh)
			again, err := f.State.LaunchDataStage(ctx, freshScope, request)
			if err != nil || !reflect.DeepEqual(again, before) {
				t.Fatal("fresh parent attempt replaced or refused its retained stage", err)
			}
			if _, err := f.State.LaunchDataStage(ctx, freshScope, d.Request); err == nil {
				t.Fatal("stale supplied parent claim was accepted")
			}
			foreign := request
			foreign.Claim.EffectID = fx.ID(t)
			if _, err := f.State.LaunchDataStage(ctx, freshScope, foreign); err == nil {
				t.Fatal("another effect could select the retained stage")
			}
			if completed {
				measurement, err := f.State.DataResult(ctx, freshScope, d.Stage.ID)
				if err != nil || measurement.StageID != before.ID || measurement.Data.Home != before.Storage.Storage.Home {
					t.Fatal("reclaimed parent lost the actual completed measurement", err)
				}
			}
			if err := f.State.Close(); err != nil {
				t.Fatal(err)
			}
			f.State, err = store.New(f.Deps)
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := f.State.LaunchDataStage(ctx, freshScope, request)
			if err != nil || !reflect.DeepEqual(restarted, before) {
				t.Fatal("restart lost stable stage identity under the new claim", err)
			}
			if !completed {
				sealed, err := f.State.SealDataStage(ctx, freshScope, d.Stage.ID, d.Projection, d.Allocation)
				if err != nil || sealed.ID != before.ID || sealed.ParentEffectID != before.ParentEffectID {
					t.Fatal("reclaimed preparation could not seal its original stage", err)
				}
				child, err := f.State.Effect(ctx, freshScope, sealed.Worker.EffectID)
				if err != nil || child.Effect.Context == nil || child.Effect.Context.Actor != old.Record.Effect.Context.Actor {
					t.Fatal("data child replaced its immutable allocation author with a new claimant", err)
				}
			}
		})
	}
}
