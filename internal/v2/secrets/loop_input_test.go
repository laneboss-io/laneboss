//go:build linux

package secrets

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// This models a scheduler only for input selection. Native authentication is
// measured by the service root canary, and no credential material is acquired.
type loopPeer struct{ stamp api.InstalledScheduler }

func (p *loopPeer) VerifyScheduler(ctx context.Context) (api.InstalledScheduler, error) {
	return p.stamp, ctx.Err()
}

func loopCredential(t *testing.T) (*fx.Fixture, credentialLaunch) {
	t.Helper()
	ctx := context.Background()
	f := fx.ControlledChild(t)
	f.Opened(t)
	f.Ended(t)
	setting := api.LoopRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation, Enabled: true, IdleMessage: &f.Lane.Task, BackoffMS: 1}
	f.Admit(t, "lane.loop", setting)
	next := f.Lane
	next.Generation++
	event := f.Event(t, "lane.loop", setting)
	event.Actor, event.RequestedBy, event.OperationID, event.RequestID = f.Human.Actor, f.Human.Actor, "", f.Human.Request.RequestID
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Human, RawRequest: f.Raw,
		Compare: []api.Compare{{Kind: api.CompareLane, ID: next.LifeID, Generation: f.Lane.Generation}},
		Writes:  api.StateWrites{Lanes: []api.Lane{next}}, Events: []api.Event{event},
		Reply: &api.RPCReply{Result: fx.JSON(t, api.Operation{ID: f.Receipt.Operation.ID, Status: "succeeded", LifeID: next.LifeID, Run: next.Run})}}); err != nil {
		t.Fatal(err)
	}
	f.Lane = next
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: next.LifeID, Run: next.Run})
	if err != nil {
		t.Fatal(err)
	}
	pick := api.LoopTurnSelector{Target: f.Reservation.Target, ExpectedGeneration: next.Generation, PreviousLaunchID: next.LaunchID, CancellationEpoch: next.CancellationEpoch}
	for _, row := range page.Events {
		if row.Kind == "lane.loop" {
			pick.SettingEventID, pick.SettingSeq, pick.SettingOperationID = row.ID, row.Seq, row.OperationID
		}
		if row.Kind == "lane.ended" {
			pick.EndEventID, pick.EndSeq = row.ID, row.Seq
		}
	}
	p := &loopPeer{stamp: api.InstalledScheduler{Config: f.Deps.Config, Actor: api.Actor{Kind: "scheduler", ID: fx.ID(t)}, CapabilityID: fx.ID(t),
		CapabilityGeneration: 1, InstallationGeneration: 1, BootID: "credential-loop", PolicyGeneration: 1, ExpiresAt: fx.Expiry()}}
	scope, err := api.BindSchedulerScope(ctx, p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.State.ReserveLaunch(ctx, scope, api.LaunchReservationRequest{Loop: &pick})
	if err != nil {
		t.Fatal(err)
	}
	return f, credentialLaunch{record: api.LaunchPlanRecord{Reservation: r}}
}

func TestLoopOriginal(t *testing.T) {
	f, launch := loopCredential(t)
	s := &Service{deps: Dependencies{Config: f.Deps.Config, Store: f.State, ServiceScope: f.Execution, Clock: f.Deps.Clock}}
	ctx := context.Background()
	before, err := f.State.LaunchInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.launchOriginal(ctx, &launch); err != nil {
		t.Fatal("loop credentials could not select the canonical private input", err)
	}
	if launch.profile != f.Lane.ProfileGrantID || launch.model != f.Lane.Model {
		t.Fatal("loop credentials replaced the retained profile or model")
	}
	after, err := f.State.LaunchInventory(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("credential input read changed the launch inventory", err)
	}
	lane := f.Lane
	lane.Generation++
	f.Replace(t, "lane", lane.LifeID, lane.Generation, lane)
	s.deps.Store = f.State
	if err := s.launchOriginal(ctx, &launch); !hasCode(err, api.CodeConflict) {
		t.Fatal("loop credentials did not reject the stale retained life", err)
	}
}
