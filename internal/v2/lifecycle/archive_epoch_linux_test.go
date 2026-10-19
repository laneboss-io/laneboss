//go:build linux

package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type epochWriterNative struct {
	archivejob.Native
	state *store.Service
	fence *archivejob.EpochFence
}

func (n *epochWriterNative) FreezeArchive(ctx context.Context, intent archivejob.Intent, _ api.Lane) (archivejob.Snapshot, error) {
	writer, ok := any(n.state).(interface {
		ReadArchiveEpochFence(context.Context, archivejob.Intent) (*archivejob.EpochFence, error)
	})
	if !ok {
		return archivejob.Snapshot{}, api.NotImplemented("lb-v2-service", "committed archive epoch handoff")
	}
	fence, err := writer.ReadArchiveEpochFence(ctx, intent)
	if err != nil {
		return archivejob.Snapshot{}, err
	}
	n.fence = fence
	return archivejob.Snapshot{}, &api.Error{Code: api.CodePrerequisite, Owner: "component-native", Message: "component stops after measuring the real writer epoch handoff"}
}

func TestArchiveEpochWriter(t *testing.T) {
	stopEndedJournal(t, 1, func(f *fx.Fixture, stopped api.Operation) {
		ctx := context.Background()
		lane, err := f.State.Lane(ctx, f.Execution, f.Reservation.Target)
		if err != nil || stopped.Stop == nil || lane.CancellationEpoch != f.Reservation.CancellationEpoch {
			t.Fatal("terminal stop changed its original cancellation epoch", err)
		}
		before := lane
		lane.State, lane.Generation, lane.CancellationEpoch = "abandoned", lane.Generation+1, lane.CancellationEpoch+1
		cause := f.Intent(t, api.InternalLifecycleEffect)
		cause.ID, cause.CauseOperationID, cause.CauseRequestID = fx.ID(t), fx.ID(t), fx.ID(t)
		decision := f.Event(t, "lane.state", api.StateEvent{From: before.State, To: lane.State, Generation: lane.Generation})
		decision.OperationID, decision.RequestID = cause.CauseOperationID, cause.CauseRequestID
		if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
			Writes: api.StateWrites{Lanes: []api.Lane{lane}}, Events: []api.Event{decision},
			Compare: []api.Compare{{Kind: api.CompareLane, ID: lane.LifeID, Generation: before.Generation}},
			Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: before.CancellationEpoch}}}}); err != nil {
			t.Fatal("cannot commit the terminal decision's real writer epoch", err)
		}
		native := &epochWriterNative{}
		f.Deps.ArchiveNative = native
		if err := f.State.Close(); err != nil {
			t.Fatal(err)
		}
		f.State, err = store.New(f.Deps)
		if err != nil {
			t.Fatal("terminal decision did not survive actual writer reopen", err)
		}
		native.state = f.State
		caller := f.Human
		request := api.ArchiveRequest{Target: f.Reservation.Target, ExpectedGeneration: lane.Generation}
		caller.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: "lane.archive",
			RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, request)}
		caller.Request.RequestSHA256, err = api.RequestDigest(caller.Request)
		if err != nil {
			t.Fatal(err)
		}
		caller.Frame = &fx.Frame{Raw: fx.JSON(t, caller.Request)}
		owned, retire := f.State.TrackMutation(ctx)
		defer retire()
		reservation, won, err := f.State.ReserveMutation(owned, api.RequestReservation{Scope: caller, RawRequest: caller.Frame.Bytes(), Deadline: fx.Expiry()})
		if err != nil || !won {
			t.Fatal("cannot reserve actual archive after terminal stop", err)
		}
		intent := archivejob.Intent{OperationID: reservation.Operation.ID, Request: request, CancellationEpoch: lane.CancellationEpoch,
			EndEventID: stopped.Stop.EndEventID, EndSeq: stopped.Stop.EndSequence}
		_, err = f.State.ReserveArchive(owned, caller, intent)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || typed.Owner != "component-native" || native.fence == nil {
			t.Fatal("actual archive reservation did not reach its fenced writer handoff", err)
		}
		writer, ok := any(f.State).(interface {
			ReadArchiveEpochFence(context.Context, archivejob.Intent) (*archivejob.EpochFence, error)
		})
		if !ok {
			t.Fatal("archive writer lacks the committed epoch handoff")
		}
		fence, err := writer.ReadArchiveEpochFence(ctx, intent)
		if err != nil || fence == nil || fence.Intent != intent || fence.LaunchEpoch != before.CancellationEpoch ||
			fence.Decision.ID != decision.ID || !reflect.DeepEqual(fence.End, stopped.Stop.End) || archivejob.ValidateEpochFence(*fence) != nil {
			t.Fatal("archive writer did not hand off its actual committed terminal epoch", err)
		}
		for _, field := range []string{"epoch", "generation", "end", "run"} {
			changed := intent
			switch field {
			case "epoch":
				changed.CancellationEpoch++
			case "generation":
				changed.Request.ExpectedGeneration++
			case "end":
				changed.EndEventID = fx.ID(t)
			case "run":
				changed.Request.Target.Run++
			}
			if result, err := writer.ReadArchiveEpochFence(ctx, changed); err == nil || result != nil {
				t.Error("archive writer handed off a changed retained fence", field)
			}
		}
		// A deliberate current-projection corruption probes the live reader;
		// restore the exact bytes before any subsequent verification/reopen.
		db, err := sql.Open("sqlite", filepath.Join(f.Deps.Directory, "state.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var original []byte
		if err := db.QueryRow("SELECT data FROM projections WHERE kind='lane' AND id=?", string(lane.LifeID)).Scan(&original); err != nil {
			t.Fatal(err)
		}
		lane.CancellationEpoch++
		if _, err := db.Exec("UPDATE projections SET data=? WHERE kind='lane' AND id=?", fx.JSON(t, lane), string(lane.LifeID)); err != nil {
			t.Fatal(err)
		}
		if result, err := writer.ReadArchiveEpochFence(ctx, intent); err == nil || result != nil {
			t.Error("archive writer handed off a stale current epoch")
		}
		lane.CancellationEpoch--
		if _, err := db.Exec("UPDATE projections SET data=? WHERE kind='lane' AND id=?", original, string(lane.LifeID)); err != nil {
			t.Fatal(err)
		}
		t.Logf("writer archive epoch: launch=%d terminal_stop=%d abandoned=%d; exact end/decision handed off", f.Reservation.CancellationEpoch, before.CancellationEpoch, lane.CancellationEpoch)
	})
}
