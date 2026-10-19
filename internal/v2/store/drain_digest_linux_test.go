//go:build linux

package store_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// drainRelease retains and claims the run's real HelperRelease effect and pins an outside spool snapshot of data.
func drainRelease(t *testing.T, f *fx.Fixture, data [][]byte) (api.EffectLease, api.CaptureDrainSnapshot) {
	t.Helper()
	ctx := context.Background()
	cause := f.Intent(t, api.InternalHelperRelease)
	cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
	release := api.HelperReleaseRequest{Cause: cause, LeaseID: f.Plan.Lease.ID, Observation: f.Observation(t, "exited").Observation}
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, HelperRelease: &release}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: effect.Context, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal("release effect was not retained", err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal("release effect was not claimed", err)
	}
	zero, exit := uint64(0), 0
	producer := api.ProcessObservation{Handle: api.ProcessHandle{ID: f.Plan.Capture.ProducerID, Target: f.Reservation.Target, ContainmentID: fx.ID(t), Generation: f.Plan.Capture.ProducerGeneration},
		State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "not_written", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	snapshot := api.CaptureDrainSnapshot{Release: release, Binding: f.Plan.Capture, Producer: producer, SpoolIdentity: string(fx.ID(t))}
	for i, stream := range f.Plan.Capture.Streams {
		snapshot.Streams = append(snapshot.Streams, api.CaptureDrainStream{StreamID: stream.ID, PipeID: stream.PipeID, Bytes: int64(len(data[i])), SHA256: fx.Digest(data[i]), EOF: true})
	}
	return claim, snapshot
}

// R2-3 (lb-v2-premortem round 2): the service allows and logs a drained stream whose digest differs from the
// measured spool (service/capture_drain.go, owner R181-R192); the store commits those same bytes and logs the same check.
func TestDrainDigestAllowed(t *testing.T) {
	for _, shape := range []string{"digest", "length"} {
		t.Run(shape, func(t *testing.T) {
			f := fx.Ready(t, true)
			ctx := context.Background()
			data := [][]byte{bytes.Repeat([]byte(fx.ID(t)), 300), []byte("stderr " + string(fx.ID(t)))}
			claim, snapshot := drainRelease(t, f, data)
			writer, ok := any(f.State).(api.CaptureDrainStore)
			if !ok {
				t.Fatal("real store has no release capture drain")
			}
			allowed := store.CaptureAllowed(t)
			if shape == "length" {
				// A length differing from the measured spool stays refused: it bounds the committed ranges.
				data[1] = append(data[1], '!')
				_, err := writer.CommitCaptureDrain(ctx, f.Execution, claim, snapshot, data)
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || len(allowed()) != 0 {
					t.Fatal("drain with a length other than the measured spool was not refused", err, allowed())
				}
				return
			}
			data[0][0] ^= 1
			receipt, err := writer.CommitCaptureDrain(ctx, f.Execution, claim, snapshot, data)
			if err != nil || !slices.Equal(allowed(), []string{"capture_drain_digest"}) {
				t.Fatal("drain whose digest differs from the measured spool was not allowed and logged", err, allowed())
			}
			if err := api.ValidateCaptureDrainReceipt(snapshot, receipt); err != nil {
				t.Fatal(err)
			}
			for i, p := range receipt.State.Positions {
				if !p.EOF || p.NextOffset != int64(len(data[i])) {
					t.Fatal("allowed drain acknowledged other ranges than the drained bytes")
				}
			}
		})
	}
}
