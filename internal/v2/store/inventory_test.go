//go:build linux

package store_test

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestInventoryAfterCollection(t *testing.T) {
	f := fx.Ready(t, true)
	parentID := f.Reservation.ID
	f.Child(t)
	collect := f.Cleanup(t, func(ctx context.Context, scope api.Scope, principal api.WorkerPrincipal) (api.WorkerResultReceipt, error) {
		return dataworker.RunArchive(ctx, dataworker.ArchiveJob{Principal: principal, Scope: scope, Bootstrap: f.State,
			Read: func(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
				return f.State.WorkerObject(ctx, scope, q)
			}, Sink: f.State, Clock: f.Deps.Clock})
	})
	before, err := f.State.LaunchInventory(context.Background())
	if err != nil || len(before) != 2 {
		t.Fatal("ended but uncleaned launch left recovery inventory", err)
	}
	receipt := collect()
	if len(receipt.Objects) == 0 || receipt.Workspace.After.WorktreeState != "absent" || !f.Lane.Cleaned {
		t.Fatal("fixture did not collect its real store and workspace")
	}
	after, err := f.State.LaunchInventory(context.Background())
	if err != nil || len(after) != 1 || after[0].Reservation.ID != parentID {
		t.Fatal("collected launch remains in recovery inventory", err)
	}
	// Historical reads remain available; only recovery inventory is retired.
	record, err := f.State.LaunchPlan(context.Background(), f.Execution, f.Reservation.ID)
	if err != nil || record.Reservation.ID != f.Reservation.ID {
		t.Fatal("collection erased the historical launch", err)
	}
	page, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: f.Lane.LifeID, Run: f.Lane.Run})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range page.Events {
		if event.Kind == "lane.cleaned" {
			found = true
		}
	}
	if !found {
		t.Fatal("collection has no committed cleaned event")
	}
	verified, err := f.State.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
	if err != nil || !verified.OK {
		t.Fatal("collected fixture verification failed", verified.Problems, err)
	}
	// A reservation without a bound lane is uncertain, not collected.
	pending := fx.NewIn(t, f.State, f.Deps)
	f.State = pending.State
	pending.Reserve(t)
	active, err := f.State.LaunchInventory(context.Background())
	if err != nil || len(active) != 2 {
		t.Fatal("uncertain reservation left recovery inventory", err)
	}
	found = false
	for _, record := range active {
		if record.Reservation.ID == pending.Reservation.ID {
			found = record.Phase == "reserved" && record.Plan == nil
		}
	}
	if !found {
		t.Fatal("recovery inventory lost the actual unbound reservation")
	}
}
