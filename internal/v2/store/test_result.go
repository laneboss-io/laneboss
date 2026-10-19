package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/testjob"
)

func validateTestOutput(r reviewRecord, raw []byte) error {
	var result testjob.Result
	if r.Test == nil || api.DecodeObject(raw, &result) != nil || !sameDataBytes(raw, result) || result.Schema != "laneboss.test-result.v2" {
		return fault(api.CodeIntegrity, "TestChild output is not its exact native test result")
	}
	c, input := result.Check, r.Test
	if c.Schema != "laneboss.check.v2" || c.Name != input.Name || c.Target != input.Subject.Target || c.EndSeq != input.Subject.EndSeq ||
		c.SnapshotSHA256 != input.Subject.Snapshot.SHA256 || c.WorkerLeaseID != r.Job.Lease.ID || c.OperationID != r.Job.Intent.OperationID || c.ExitCode < 0 || c.ExitCode > 255 ||
		len(result.Stdout)+len(result.Stderr) > api.MaxFrameBytes/2 {
		return fault(api.CodeIntegrity, "TestChild result changed its worker, frozen subject or bounded output")
	}
	if !wire.ValidID(string(result.StdoutPipeID)) || !wire.ValidID(string(result.StderrPipeID)) || result.StdoutPipeID == result.StderrPipeID {
		return fault(api.CodeIntegrity, "TestChild result lost its actual distinct output pipe identities")
	}
	return nil
}

func (s *Service) testObject(ctx context.Context, db queryer, r reviewRecord, request api.BlobReadRequest) (api.BlobChunk, error) {
	refs := map[api.ID]api.BlobRef{r.Test.Request.Candidate.ID: r.Test.Request.Candidate, r.Test.Request.TestPlan.ID: r.Test.Request.TestPlan}
	meta, raw, err := objectRow(ctx, db, r.Test.Request.Candidate.ID)
	if err != nil {
		return api.BlobChunk{}, err
	}
	var tree api.ObjectManifest
	if meta.Ref != r.Test.Request.Candidate || api.DecodeObject(raw, &tree) != nil || manifest.Object(tree) != nil {
		return api.BlobChunk{}, fault(api.CodeIntegrity, "TestChild candidate changed its retained tree")
	}
	for _, entry := range tree.Entries {
		for _, ref := range manifest.ContentRefs(entry) {
			refs[ref.ID] = ref
		}
	}
	ref, ok := refs[request.ObjectID]
	if !ok {
		return api.BlobChunk{}, fault(api.CodeNotFound, "object is outside the exact TestChild candidate and plan")
	}
	meta, raw, err = objectRow(ctx, db, ref.ID)
	if err != nil {
		return api.BlobChunk{}, err
	}
	if meta.Ref != ref || request.Offset < 0 || request.Offset > int64(len(raw)) || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
		return api.BlobChunk{}, fault(api.CodeIntegrity, "TestChild object changed its sealed range")
	}
	part := append([]byte{}, raw[request.Offset:min(int64(len(raw)), request.Offset+int64(request.Limit))]...)
	return api.BlobChunk{ObjectID: ref.ID, Offset: request.Offset, Data: part, SHA256: api.Digest(hash(part))}, nil
}

// The authenticated worker returns the actual child's captured stdout/stderr.
// Retain those bytes and EOFs with the real worker process/operation identity;
// no externally uploaded verdict can enter this path.
func (s *Service) retainTestOutput(ctx context.Context, tx *sql.Tx, r reviewRecord) error {
	var result testjob.Result
	if err := api.DecodeObject(r.Ack.Submission.Result, &result); err != nil {
		return err
	}
	appendEvent := func(kind api.EventKind, value any) error {
		e, err := s.reviewEvent(r, kind, value)
		if err != nil {
			return err
		}
		_, err = appendPrivateEvent(ctx, tx, e, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
		return err
	}
	id := api.ID("test-capture-" + hash([]byte(r.Job.ID)))
	boot, _, found := strings.Cut(r.Process.Generation, ":")
	if !found || boot == "" {
		return fault(api.CodeContainmentUnknown, "TestChild capture lost its native boot")
	}
	binding := api.CaptureBinding{ID: id, ReservationID: r.Job.ID, Config: s.deps.Config, Target: r.Job.Lease.Target, OperationID: r.Job.Intent.OperationID, RequestID: r.Request.RequestID,
		RequestedBy: r.Scope.Actor, LaunchID: r.WorkerLaunchID, HelperLeaseID: r.Allocation.ID, WorkerLeaseID: r.Job.Lease.ID, EffectID: r.Job.Lease.EffectID,
		ProducerID: r.WorkerActor.ID, ProducerGeneration: r.Process.Generation, BootID: boot, Supervisor: &r.Job.Plan.Executable, Generation: 1, Status: "registered", Streams: []api.CaptureStreamBinding{
			{ID: id + "-out", Stream: "stdout", PipeID: result.StdoutPipeID}, {ID: id + "-err", Stream: "stderr", PipeID: result.StderrPipeID}}}
	if err := api.ValidateCaptureBinding(binding); err != nil {
		return err
	}
	event, err := s.reviewEvent(r, "capture.bound", binding)
	if err != nil {
		return err
	}
	seq, err := appendPrivateEvent(ctx, tx, event, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return err
	}
	state := api.CaptureState{Binding: binding, Generation: 1, LastSeq: seq, Positions: []api.CapturePosition{{StreamID: binding.Streams[0].ID}, {StreamID: binding.Streams[1].ID}}}
	for i, raw := range [][]byte{result.Stdout, result.Stderr} {
		stream := binding.Streams[i]
		for offset := 0; offset < len(raw); {
			end := min(offset+api.MaxChunkBytes, len(raw))
			ref, err := s.reviewBytes(ctx, tx, r, "capture", raw[offset:end])
			if err != nil {
				return err
			}
			if err := appendEvent("blob.committed", ref); err != nil {
				return err
			}
			recordID, err := wire.NewID()
			if err != nil {
				return err
			}
			record := api.CaptureRecord{ID: recordID, BindingID: id, Target: r.Job.Lease.Target, Stream: stream.Stream, Offset: int64(offset), Data: ref,
				Primary: true, Coverage: "partial", ObservedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))}
			event, err := s.reviewEvent(r, "capture.appended", record)
			if err != nil {
				return err
			}
			event.ID, event.Actor = recordID, r.WorkerActor
			seq, err := appendPrivateEvent(ctx, tx, event, record.ObservedAt)
			if err != nil {
				return err
			}
			state.Positions[i].NextOffset, state.Generation, state.LastSeq = int64(end), state.Generation+1, seq
			offset = end
		}
		event, err := s.reviewEvent(r, "capture.closed", nil)
		if err != nil {
			return err
		}
		var head api.Sequence
		if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&head); err != nil {
			return err
		}
		receipt := api.CaptureAppendReceipt{BindingID: id, RecordID: event.ID, StreamID: stream.ID, Offset: int64(len(raw)), NextOffset: int64(len(raw)), EOF: true, Generation: state.Generation + 1, LastSeq: head + 1}
		event.Payload, err = json.Marshal(receipt)
		if err != nil {
			return err
		}
		event.Actor = r.WorkerActor
		seq, err := appendPrivateEvent(ctx, tx, event, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
		if err != nil {
			return err
		}
		state.Positions[i].EOF, state.Generation, state.LastSeq = true, state.Generation+1, seq
	}
	if err := put(ctx, tx, "capture_state", id, state.Generation, state); err != nil {
		return err
	}
	raw, err := canonicalValue(result.Check)
	if err != nil {
		return err
	}
	ref, err := s.reviewBytes(ctx, tx, r, "check", raw)
	if err != nil {
		return err
	}
	if err := appendEvent("blob.committed", ref); err != nil {
		return err
	}
	if r.Retirement == nil || r.Retirement.Release == nil {
		return fault(api.CodeContainmentUnknown, "TestChild has no native helper release")
	}
	if err := appendEvent("helper.released", *r.Retirement.Release); err != nil {
		return err
	}
	return appendEvent("worker.completed", api.WorkerEvent{WorkerID: r.Job.Lease.ID, Kind: "test", Input: r.Test.Request.TestPlan, Output: &r.Ack.Receipt.Result, Status: "succeeded"})
}

func (s *Service) verifyTestRecord(ctx context.Context, r reviewRecord) error {
	if r.Request.Method != "grants.test-child" || r.Job.Lease.Kind != "test" || r.Job.Plan.Kind != "test" || r.Test.Schema != "laneboss.test-input.v2" ||
		r.Test.Request.Child != r.Job.Lease.Target || r.Test.Plan.Input != r.Test.Request.Candidate {
		return fault(api.CodeIntegrity, "retained TestChild lost its exact request and worker kind")
	}
	meta, raw, err := objectRow(ctx, s.db, r.Job.Lease.Input.ID)
	if err != nil {
		return err
	}
	if meta.Ref != r.Job.Lease.Input || meta.SourceOperationID != r.Job.Intent.OperationID || !sameDataBytes(raw, r.Test) {
		return fault(api.CodeIntegrity, "retained TestChild input changed")
	}
	effect, err := effectRow(ctx, s.db, r.Job.Lease.EffectID)
	if absent(err) {
		// An inert stage may precede atomic proof/effect admission. It has no
		// helper allocation, process or authenticated output authority.
		if r.Allocating || r.Allocation.ID != "" || r.Ack != nil {
			return fault(api.CodeIntegrity, "unadmitted TestChild acquired execution authority")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if effect.Effect.Worker == nil || !sameValue(*effect.Effect.Worker, r.Job.Plan) {
		return fault(api.CodeIntegrity, "TestChild effect differs from its retained plan")
	}
	if r.Ack != nil {
		if err := validateTestOutput(r, r.Ack.Submission.Result); err != nil {
			return err
		}
	}
	if effect.Outcome != nil && effect.Outcome.Status == "failed" {
		if effect.Outcome.Error == nil || r.Retirement == nil || r.Retirement.Release == nil || effect.Outcome.Observation == nil || !sameValue(*effect.Outcome.Observation, r.Retirement.Release.Quiescence) {
			return fault(api.CodeContainmentUnknown, "failed native TestChild lost its original retirement measurement")
		}
		return nil
	}
	if effect.Outcome != nil {
		return s.validateReviewOutcome(ctx, s.db, effect, *effect.Outcome)
	}
	return nil
}
