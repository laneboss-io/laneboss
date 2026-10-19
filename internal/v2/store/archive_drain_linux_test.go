//go:build linux

package store

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// lateCapture commits one capture.appended range for the archived run after its committed end, written by the
// release drain's own appendDrainedRange. drained derives the object as CommitCaptureDrain does; committed also writes
// the run's capture_drain receipt in the same transaction.
func lateCapture(t *testing.T, f *archFixture, drained, committed bool) {
	t.Helper()
	ctx := context.Background()
	s, r := f.s, f.record
	target := r.Job.Intent.Request.Target
	stream := api.CaptureStreamBinding{ID: testID(t), Stream: "stdout"}
	binding := api.CaptureBinding{ID: testID(t), Config: f.deps.Config, Target: target, LaunchID: r.Lane.LaunchID, OperationID: r.Job.Intent.OperationID,
		RequestID: r.Request.RequestID, RequestedBy: r.Scope.Actor, ProducerID: testID(t), Streams: []api.CaptureStreamBinding{stream}}
	state := api.CaptureState{Binding: binding, Generation: 1, Positions: []api.CapturePosition{{StreamID: stream.ID}}}
	plan := api.LaunchPlanRecord{Reservation: api.LaunchReservation{RootLifeID: target.LifeID, StarterChain: []api.ID{}}}
	data := []byte("serve-fixture stdout line\n")
	key := testID(t)
	if drained {
		key = api.ID(hash([]byte("capture-drain-object:" + string(binding.ID) + ":" + string(stream.ID) + ":" + strconv.FormatInt(0, 10))))
	}
	now := archStamp()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ref, err := s.retain(ctx, tx, f.executor, api.ObjectWrite{ObjectKey: key, Class: "capture", Bytes: data, SHA256: api.Digest(hash(data)), Origin: "service",
		ACL: api.ObjectACL{Config: binding.Config, Owner: api.Actor{Kind: "worker", ID: binding.ProducerID}, LifeID: target.LifeID, Audience: "owner", Generation: 1}}, binding.OperationID, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := appendDrainedRange(ctx, tx, &state, plan, 0, &ref, now); err != nil {
		t.Fatal(err)
	}
	if err := appendDrainedRange(ctx, tx, &state, plan, 0, nil, now); err != nil {
		t.Fatal(err)
	}
	if committed {
		receipt := api.CaptureDrainReceipt{EffectID: testID(t), LeaseID: testID(t), SnapshotSHA256: testDigest(data), State: state}
		if err := put(ctx, tx, "capture_drain", binding.ID, 1, receipt); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// R2-1 (lb-v2-premortem round 2): the HelperRelease drain commits the run's unacknowledged spool after lane.ended
// (store/capture_drain.go), and the archive fence counted those capture.appended events as a changed source.
func TestArchiveFenceReleaseDrain(t *testing.T) {
	for _, shape := range []string{"drained", "live", "uncommitted"} {
		t.Run(shape, func(t *testing.T) {
			f := newFreshArch(t)
			lateCapture(t, f, shape != "live", shape != "uncommitted")
			_, err := f.s.sealArchive(context.Background(), f.record)
			if shape == "drained" {
				if err != nil {
					t.Fatal("archive fence refused the capture its release drain committed after the end", err)
				}
				return
			}
			// Any other late range (a live append, or drain-shaped bytes without the run's committed drain) still changes the source.
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeConflict || typed.Message != "archive source changed after its committed end" {
				t.Fatal("archive fence admitted a late capture its release drain did not commit", err)
			}
		})
	}
}
