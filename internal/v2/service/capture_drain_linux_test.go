//go:build linux

package service

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Only the native helper is a component fixture here. The writer, retained
// launch/capture projections, release claim and reconciler are real.
type drainHelperFixture struct {
	api.HelperControl
	snapshot    api.CaptureDrainSnapshot
	data        [][]byte
	ack         *api.CaptureDrainReceipt
	failAck     bool
	containment api.ID
}

func (h *drainHelperFixture) CaptureDrains(_ context.Context, r api.HelperReleaseRequest) ([]api.CaptureDrainSnapshot, error) {
	if !reflect.DeepEqual(r, h.snapshot.Release) {
		return nil, serviceError(api.CodeForbidden, "foreign release")
	}
	return []api.CaptureDrainSnapshot{h.snapshot}, nil
}
func (h *drainHelperFixture) ReadCaptureDrain(_ context.Context, r api.HelperReleaseRequest, pin api.CaptureDrainSnapshot, stream api.ID, offset int64) (api.BlobChunk, error) {
	if !reflect.DeepEqual(r, h.snapshot.Release) || !reflect.DeepEqual(pin, h.snapshot) {
		return api.BlobChunk{}, serviceError(api.CodeConflict, "changed snapshot")
	}
	for i, s := range pin.Streams {
		if s.StreamID == stream && offset >= 0 && offset < int64(len(h.data[i])) {
			end := min(offset+api.MaxChunkBytes, int64(len(h.data[i])))
			data := append([]byte{}, h.data[i][offset:end]...)
			return api.BlobChunk{ObjectID: stream, Offset: offset, Data: data, SHA256: fx.Digest(data)}, nil
		}
	}
	return api.BlobChunk{}, serviceError(api.CodeInvalid, "foreign range")
}
func (h *drainHelperFixture) AcknowledgeCaptureDrain(_ context.Context, _ api.HelperReleaseRequest, _ api.CaptureDrainSnapshot, receipt api.CaptureDrainReceipt) error {
	if h.failAck {
		h.failAck = false
		return serviceError(api.CodeUnavailable, "acknowledgement transport interrupted")
	}
	h.ack = &receipt
	return nil
}
func (h *drainHelperFixture) Release(_ context.Context, r api.HelperReleaseRequest) (api.ReleaseReceipt, error) {
	if h.ack == nil {
		return api.ReleaseReceipt{}, serviceError(api.CodeContainmentUnknown, "capture spool and EOF have no authenticated service drain acknowledgement")
	}
	zero := uint64(0)
	return api.ReleaseReceipt{ID: r.Cause.ID, LeaseID: r.LeaseID, ContainmentID: r.Observation.Handle.ContainmentID, Backend: "linux-bwrap-landlock", OperationID: r.Cause.CauseOperationID, EffectID: r.Cause.EffectID, Quiescence: r.Observation, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: r.Observation.ObservedAt}, nil
}

func (h *drainHelperFixture) CaptureAbortDrains(_ context.Context, r api.HelperAbortRequest) ([]api.CaptureDrainSnapshot, error) {
	if h.snapshot.Abort == nil || *h.snapshot.Abort != r {
		return nil, serviceError(api.CodeForbidden, "foreign capture abort")
	}
	return []api.CaptureDrainSnapshot{h.snapshot}, nil
}
func (h *drainHelperFixture) ReadAbortCaptureDrain(ctx context.Context, _ api.HelperAbortRequest, pin api.CaptureDrainSnapshot, stream api.ID, offset int64) (api.BlobChunk, error) {
	return h.ReadCaptureDrain(ctx, api.HelperReleaseRequest{}, pin, stream, offset)
}
func (h *drainHelperFixture) AcknowledgeAbortCaptureDrain(ctx context.Context, _ api.HelperAbortRequest, pin api.CaptureDrainSnapshot, receipt api.CaptureDrainReceipt) error {
	return h.AcknowledgeCaptureDrain(ctx, api.HelperReleaseRequest{}, pin, receipt)
}
func (h *drainHelperFixture) AbortGate(_ context.Context, r api.HelperAbortRequest) (api.AbortReceipt, error) {
	if h.ack == nil {
		return api.AbortReceipt{}, serviceError(api.CodeContainmentUnknown, "unopened allocation capture lacks its service drain acknowledgement")
	}
	zero := uint64(0)
	now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	return api.AbortReceipt{ID: r.Cause.ID, LeaseID: r.LeaseID, PreparedID: r.PreparedID, ObservedAt: now, Quiescence: api.ProcessObservation{Handle: api.ProcessHandle{Target: r.Cause.Target, ContainmentID: h.containment}, State: "not_started", Survivors: &zero, PromptStatus: "not_written", ObservedAt: now}}, nil
}

func TestCaptureDrainAbort(t *testing.T) {
	f, _, helper := captureDrainFixture(t)
	cause := helper.snapshot.Release.Cause
	cause.ID, cause.EffectID, cause.Kind = fx.ID(t), fx.ID(t), api.InternalHelperAbort
	request := api.HelperAbortRequest{Cause: cause, LeaseID: f.Plan.Lease.ID, PreparedID: f.Prepared.ID, SpecSHA256: f.Record.Handoff.SpecSHA256, OperationID: cause.CauseOperationID, EffectID: cause.EffectID}
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, HelperAbort: &request}
	claim := claimControl(t, f, effect)
	helper.snapshot.Release, helper.snapshot.Abort = api.HelperReleaseRequest{}, &request
	host := launchServer(t, f)
	host.runtime.Helper = helper
	outcome, err := host.runEffect(context.Background(), f.Execution, claim)
	if err != nil || outcome.Abort == nil || helper.ack == nil {
		t.Fatal("nonexecuting abort did not drain its retained outside capture", err)
	}
	if outcome.Abort.AgentExecuted || outcome.Abort.Quiescence.State != "not_started" || outcome.Abort.Quiescence.ExitCode != nil {
		t.Fatal("capture abort invented an executed agent exit")
	}
	if _, err := f.State.CompleteEffect(context.Background(), f.Execution, outcome); err != nil {
		t.Fatal("capture abort did not complete its real retained effect", err)
	}
}

func captureDrainFixture(t *testing.T) (*fx.Fixture, api.EffectLease, *drainHelperFixture) {
	t.Helper()
	f := fx.Ready(t, true)
	ended := f.Observation(t, "exited").Observation
	cause := f.Intent(t, api.InternalHelperRelease)
	cause.ID, cause.EffectID = fx.ID(t), fx.ID(t)
	release := api.HelperReleaseRequest{Cause: cause, LeaseID: f.Plan.Lease.ID, Observation: ended}
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, HelperRelease: &release}
	claim := claimControl(t, f, effect)
	return f, claim, runDrainHelper(t, f, release)
}

func runDrainHelper(t *testing.T, f *fx.Fixture, release api.HelperReleaseRequest) *drainHelperFixture {
	t.Helper()
	zero, exit := uint64(0), 0
	producer := api.ProcessObservation{Handle: api.ProcessHandle{ID: f.Plan.Capture.ProducerID, Target: f.Reservation.Target, ContainmentID: fx.ID(t), Generation: f.Plan.Capture.ProducerGeneration}, State: "exited", ExitCode: &exit, Survivors: &zero, PromptStatus: "not_written", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	h := &drainHelperFixture{containment: f.Plan.Lease.ContainmentID, snapshot: api.CaptureDrainSnapshot{Release: release, Binding: f.Plan.Capture, Producer: producer, SpoolIdentity: string(fx.ID(t))}, data: [][]byte{bytes.Repeat([]byte(fx.ID(t)), 3000), []byte("stderr " + string(fx.ID(t)))}}
	for i, stream := range f.Plan.Capture.Streams {
		h.snapshot.Streams = append(h.snapshot.Streams, api.CaptureDrainStream{StreamID: stream.ID, PipeID: stream.PipeID, Bytes: int64(len(h.data[i])), SHA256: fx.Digest(h.data[i]), EOF: true})
	}
	return h
}

func TestCaptureDrainRelease(t *testing.T) {
	f, claim, helper := captureDrainFixture(t)
	ctx := context.Background()
	host := launchServer(t, f)
	host.runtime.Helper = helper
	// A lost acknowledgement leaves the same committed capture available to
	// the next attempt, without a second capture.closed or primary range.
	helper.failAck = true
	_, err := host.runEffect(ctx, f.Execution, claim)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeUnavailable {
		t.Fatal("release did not reach authenticated capture acknowledgement", err)
	}
	reader, ok := any(f.State).(api.CaptureDrainStore)
	if !ok {
		t.Fatal("real store has no retained release capture acknowledgement")
	}
	first, err := reader.CaptureDrainReceipt(ctx, f.Execution, claim, helper.snapshot.Binding.ID)
	if err != nil || first.State.LastSeq == 0 {
		t.Fatal("lost helper reply discarded committed capture", err)
	}
	old := claim
	f.Claim = claim
	f.ExpireClaim(t)
	claim, err = f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: old.Record.Effect.ID, ExpectedGeneration: old.Record.Generation, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil || claim.Record.Generation <= old.Record.Generation {
		t.Fatal("release did not reclaim the original retained effect", err)
	}
	host.deps.Store = f.State
	reader = f.State
	if _, err := reader.CommitCaptureDrain(ctx, f.Execution, old, helper.snapshot, helper.data); err == nil {
		t.Fatal("superseded attempt replayed a committed acknowledgement")
	}
	value, err := host.runEffect(ctx, f.Execution, claim)
	if err != nil || value.Release == nil || helper.ack == nil || !reflect.DeepEqual(*helper.ack, first) {
		t.Fatal("retained capture did not resume the release stage", err)
	}
	for i, p := range helper.ack.State.Positions {
		if !p.EOF || p.NextOffset != int64(len(helper.data[i])) {
			t.Fatal("release acknowledged different pipe ranges")
		}
	}
	if _, err := f.State.CompleteEffect(ctx, f.Execution, value); err != nil {
		t.Fatal("measured release did not reach durable completion", err)
	}
	actual, err := f.State.Effect(ctx, f.Execution, claim.Record.Effect.ID)
	if err != nil || actual.State != api.EffectCompleted {
		t.Fatal("release remained pending", err)
	}
	if _, err := reader.CommitCaptureDrain(ctx, f.Execution, claim, helper.snapshot, helper.data); err == nil {
		t.Fatal("completed claim authorized another drain")
	}
	verification, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
	if err != nil || !verification.OK {
		t.Fatal("drained primary ranges and EOF did not verify after restart", err)
	}
}

func TestCaptureDrainControls(t *testing.T) {
	for _, mode := range []string{"foreign", "stale", "expired", "missing-eof", "changed-bytes", "changed-pin", "public", "missing-binding", "missing-helper", "prefix", "new-epoch"} {
		t.Run(mode, func(t *testing.T) {
			f, claim, helper := captureDrainFixture(t)
			writer, ok := any(f.State).(api.CaptureDrainStore)
			if !ok {
				t.Fatal("real store has no retained release capture acknowledgement")
			}
			ctx, scope := context.Background(), f.Execution
			original, err := f.State.CaptureState(ctx, scope, helper.snapshot.Binding.ID)
			if err != nil {
				t.Fatal(err)
			}
			pin := helper.snapshot
			switch mode {
			case "foreign":
				pin.Binding.HelperLeaseID = fx.ID(t)
			case "stale":
				claim.ClaimID = fx.ID(t)
			case "expired":
				f.Claim = claim
				f.ExpireClaim(t)
				writer = f.State
			case "missing-eof":
				pin.Streams = append([]api.CaptureDrainStream{}, pin.Streams...)
				pin.Streams[0].EOF = false
			case "changed-bytes":
				// Owner R181-R192: a drained digest other than the measured spool's is allowed and logged by the service and the
				// store alike (store/drain_digest_linux_test.go reads the store's journaled check).
				helper.data[0][0] ^= 1
				if _, err := writer.CommitCaptureDrain(ctx, scope, claim, pin, helper.data); err != nil {
					t.Fatal("drain refused bytes whose digest differs from the measured spool", err)
				}
				return
			case "changed-pin":
				pin.SpoolIdentity = string(fx.ID(t))
				if _, err := writer.CommitCaptureDrain(ctx, scope, claim, helper.snapshot, helper.data); err != nil {
					t.Fatal(err)
				}
			case "public":
				scope = f.Human
			case "missing-binding":
				pin.Binding.ID = fx.ID(t)
			case "missing-helper":
				host := launchServer(t, f)
				host.runtime.Helper = nil
				if err := host.DrainReleaseCaptures(api.WithEffectLease(ctx, claim), pin.Release); err == nil {
					t.Fatal("missing native drain helper granted release")
				}
				return
			case "prefix", "new-epoch":
				prefix := helper.data[0][:137]
				ref := f.CaptureData(t, prefix)
				appendRequest := f.AppendRequest(t, &ref, false)
				if _, err := f.State.AppendCapture(ctx, f.Worker, appendRequest); err != nil {
					t.Fatal("authenticated prefix control failed", err)
				}
				if mode == "new-epoch" {
					lane, err := f.State.Lane(ctx, scope, pin.Binding.Target)
					if err != nil {
						t.Fatal(err)
					}
					before := lane.Generation
					stop := f.Intent(t, api.InternalHelperStop)
					lane.Generation++
					lane.CancellationEpoch++
					if _, err := f.State.Transact(ctx, api.Transaction{Scope: scope, Internal: &stop, Compare: []api.Compare{{Kind: api.CompareLane, ID: lane.LifeID, Generation: before}}, Writes: api.StateWrites{Lanes: []api.Lane{lane}}}); err != nil {
						t.Fatal("actual cancellation transition failed", err)
					}
					if _, err := writer.CommitCaptureDrain(ctx, scope, claim, pin, helper.data); err == nil {
						t.Fatal("old release epoch authorized capture drain")
					}
					if _, err := f.State.AppendCapture(ctx, f.Worker, appendRequest); err == nil {
						t.Fatal("old producer epoch authorized capture replay")
					}
					cause := pin.Release.Cause
					cause.ID, cause.EffectID, cause.CancellationEpoch = fx.ID(t), fx.ID(t), lane.CancellationEpoch
					pin.Release.Cause = cause
					effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, HelperRelease: &pin.Release}
					claim = claimControl(t, f, effect)
				}
				receipt, err := writer.CommitCaptureDrain(ctx, scope, claim, pin, helper.data)
				if err != nil {
					t.Fatal("retained drain did not preserve its acknowledged prefix under current authority", err)
				}
				if err := api.ValidateCaptureDrainReceipt(pin, receipt); err != nil {
					t.Fatal(err)
				}
				verification, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"})
				if err != nil || !verification.OK {
					t.Fatal("prefix or current-epoch drain changed capture history", err)
				}
				return
			}
			if _, err := writer.CommitCaptureDrain(ctx, scope, claim, pin, helper.data); err == nil {
				t.Fatal("drain accepted " + mode)
			}
			if mode != "changed-pin" {
				after, err := f.State.CaptureState(ctx, f.Execution, helper.snapshot.Binding.ID)
				if err != nil || !reflect.DeepEqual(after, original) {
					t.Fatal("refused drain mutated capture", err)
				}
			}
		})
	}
}
