//go:build linux

package store_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestItem3SchedulerCannotBorrowLanc801(t *testing.T) {
	f := fx.ControlledChild(t)
	ctx := context.Background()
	before, err := f.State.LaunchInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	selector := &api.LoopTurnSelector{Target: f.Reservation.Target, SettingEventID: fx.ID(t), SettingSeq: 1,
		SettingOperationID: fx.ID(t), EndEventID: fx.ID(t), EndSeq: 2, ExpectedGeneration: f.Lane.Generation,
		CancellationEpoch: f.Lane.CancellationEpoch, PreviousLaunchID: f.Lane.LaunchID}
	// A copied internal/lane label has no private scheduler producer binding.
	// This is a refusal control, not an automatic-loop execution result.
	for _, scope := range []api.Scope{f.Human, f.Execution, {Config: f.Deps.Config, Actor: api.Actor{Kind: "scheduler", ID: fx.ID(t)}, PolicyGeneration: 1}} {
		if _, err := f.State.ReserveLaunch(ctx, scope, api.LaunchReservationRequest{Loop: selector}); err == nil {
			t.Fatal("automatic loop borrowed lane, service or scheduler-label authority")
		}
	}
	if _, err := api.BindSchedulerScope(ctx, nil, time.Now()); err == nil {
		t.Fatal("missing installed scheduler producer became authenticated authority")
	} else {
		launchCode(t, err, api.CodeNotImplemented)
	}
	after, err := f.State.LaunchInventory(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("refused scheduler input changed the actual reserved launches", err)
	}
}
