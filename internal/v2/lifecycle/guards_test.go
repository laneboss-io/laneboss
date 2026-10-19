package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func TestEventSelectionFields(t *testing.T) {
	for _, field := range []string{"config", "life", "run", "origin", "since"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t)
			event := f.ended()
			request := api.EventTailRequest{LifeID: "child", Run: 2}
			scope := f.scope("event.tail", request, f.parent)
			switch field {
			case "config":
				event.Config = "unrelated"
			case "life":
				event.LifeID = "sibling"
			case "run":
				event.Run = 1
			case "origin":
				event.Origin = "observation"
			case "since":
				request.Since = event.Seq
			}
			selected, err := selectedEvent(scope, f.child, request, event)
			if selected || err != nil {
				t.Fatalf("selection leaked %s event: selected=%v err=%v", field, selected, err)
			}
		})
	}
}

func TestSavedSequence(t *testing.T) {
	f := newFixture(t)
	old := f.ended()
	request := api.EventTailRequest{LifeID: "child", Run: 2, Since: old.Seq,
		Follow: true, Until: "lane.ended", DeadlineMS: 500}
	stream, err := f.service.OpenEvents(context.Background(),
		f.scope("event.tail", request, f.parent), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_, err = stream.Next(context.Background())
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeDeadline {
		t.Fatalf("saved sequence did not wait for a new selected end: %v", err)
	}
}

func TestFollowBatchBound(t *testing.T) {
	// This measures an in-process dependency fixture, not twenty real agents.
	f := newFixture(t)
	const count = 20
	f.store.readerCount = count
	lanes := make([]api.Lane, count)
	for i := range lanes {
		lane := f.child
		lane.LifeID = api.ID(fmt.Sprintf("child-%d", i))
		lanes[i] = lane
		f.store.lanes[lane.LifeID] = lane
	}
	type received struct {
		life  api.ID
		frame api.StreamFrame
		end   api.StreamFrame
		at    time.Time
		err   error
	}
	results := make(chan received, count)
	streams := make([]api.EventStream, 0, count)
	defer func() {
		for _, stream := range streams {
			if err := stream.Close(); err != nil {
				t.Errorf("fixture stream close failed: %v", err)
			}
		}
	}()
	for _, lane := range lanes {
		request := api.EventTailRequest{LifeID: lane.LifeID, Run: lane.Run,
			Follow: true, Until: "lane.ended", DeadlineMS: 5000}
		stream, err := f.service.OpenEvents(context.Background(),
			f.scope("event.tail", request, f.parent), request)
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, stream)
		go func(life api.ID, stream api.EventStream) {
			frame, err := stream.Next(context.Background())
			at := time.Now()
			var end api.StreamFrame
			if err == nil {
				end, err = stream.Next(context.Background())
			}
			results <- received{life: life, frame: frame, end: end, at: at, err: err}
		}(lane.LifeID, stream)
	}
	select {
	case <-f.store.readersReady:
	case <-time.After(2 * time.Second):
		t.Fatal("follow batch never subscribed all watchers")
	}
	committed := make(map[api.ID]time.Time, count)
	seqs := make(map[api.ID]api.Sequence, count)
	for _, lane := range lanes {
		observation := f.launcher.observation
		observation.Handle.Target.LifeID = lane.LifeID
		committed[lane.LifeID] = time.Now()
		event := f.addTo(lane, "lane.ended", api.RunEndEvent{LaunchID: "launch",
			Reason: "exit", Observation: observation, BudgetRemaining: f.budget}, "service", f.parent)
		seqs[lane.LifeID] = event.Seq
	}
	// No NotifyCommit call: other service modules can commit through Store.
	// Polling must deliver those commits as well as lifecycle's own wakeups.
	deadline := time.NewTimer(2200 * time.Millisecond)
	defer deadline.Stop()
	seen := map[api.ID]bool{}
	for range count {
		select {
		case got := <-results:
			if got.err != nil || got.frame.Event == nil || got.frame.End || !got.end.End ||
				got.frame.Event.LifeID != got.life || got.frame.Event.Seq != seqs[got.life] || seen[got.life] {
				t.Fatalf("follow batch selected a different run or end: %v", got.err)
			}
			seen[got.life] = true
			if elapsed := got.at.Sub(committed[got.life]); elapsed < 0 || elapsed > 2*time.Second {
				t.Fatalf("follow batch exceeded two seconds: %s", elapsed)
			}
		case <-deadline.C:
			t.Fatal("follow batch missed committed ends")
		}
	}
}

func TestSnapshotFrameBound(t *testing.T) {
	f := newFixture(t)
	first := f.add("capture.gap", api.CaptureGap{Target: f.target, Stream: "stdout",
		Reason: "a bounded snapshot", ObservedAt: "2030-01-02T03:04:05Z"},
		2, "service", f.parent)
	request := api.EventTailRequest{LifeID: "child", Run: 2}
	scope := f.scope("event.tail", request, f.parent)
	small, err := f.service.EventTail(context.Background(), scope, request)
	if err != nil || len(small.Events) != 1 || small.Events[0].ID != first.ID {
		t.Fatalf("bounded snapshot did not return the stored event: %v", err)
	}
	for range 100 {
		f.add("capture.gap", api.CaptureGap{Target: f.target, Stream: "stdout",
			Reason: strings.Repeat("g", 12000), ObservedAt: "2030-01-02T03:04:05Z"},
			2, "service", f.parent)
	}
	page, err := f.service.eventPage(context.Background(), scope, f.child, request)
	if err != nil || len(page.Events) != 101 {
		t.Fatalf("oversized snapshot fixture lost the stored backlog: %v", err)
	}
	encoded, err := json.Marshal(page)
	if err != nil || len(encoded) <= api.MaxFrameBytes || len(encoded) >= 4<<20 {
		t.Fatalf("snapshot fixture did not cross the RPC bound within the queue bound: %v", err)
	}
	_, err = f.service.EventTail(context.Background(), scope, request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeUnavailable ||
		typed.Message != "event snapshot exceeds one frame" {
		t.Fatalf("oversized snapshot crossed the RPC frame bound: %v", err)
	}
	stream, err := f.service.OpenEvents(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	frame, err := stream.Next(context.Background())
	if err != nil || frame.Event == nil || frame.End || frame.Event.ID != first.ID {
		t.Fatalf("bounded incremental stream lost an oversized snapshot's first event: %v", err)
	}
}

func TestTwentySurvivorsRefuse(t *testing.T) {
	f := newFixture(t)
	f.ended()
	survivors := uint64(20)
	f.launcher.observation.Survivors = &survivors
	request := api.ResumeRequest{Target: f.target, ExpectedGeneration: 1,
		Message: f.blob("message", "task", []byte("continue\n")), Budget: f.budget}
	_, err := f.service.LaneResume(context.Background(), f.scope("lane.resume", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict {
		t.Fatalf("survivors crossed the continuation gate: %v", err)
	}
	if len(f.store.transactions) != 0 || f.launcher.prepared.Load() != 0 {
		t.Fatal("survivors produced a new run intent")
	}
}

func TestMissingSurvivorCount(t *testing.T) {
	f := newFixture(t)
	f.ended()
	f.launcher.observation.Survivors = nil
	_, err := f.service.LaneCheck(context.Background(), f.scope("lane.check", f.target, f.parent), f.target)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("missing survivor count was accepted as zero: %v", err)
	}
}

func TestProcessGenerationBound(t *testing.T) {
	f := newFixture(t)
	f.ended()
	record := f.store.launches["launch"]
	record.ProcessGeneration = "reused-generation"
	f.store.launches["launch"] = record
	_, err := f.service.LaneCheck(context.Background(), f.scope("lane.check", f.target, f.parent), f.target)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("process generation drift crossed observation: %v", err)
	}
}

func TestPendingStopIsNotComplete(t *testing.T) {
	f := newFixture(t)
	f.ended()
	lane := f.child
	lane.State = "running"
	f.store.lanes["child"] = lane
	f.store.effectDone = true
	request := api.StopRequest{Target: f.target, ExpectedGeneration: 1,
		Reason: f.blob("reason", "task", []byte("stop\n"))}
	_, err := f.service.LaneStop(context.Background(), f.scope("lane.stop", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("pending stop was promoted to completion: %v", err)
	}
}

func TestFailedIntentDoesNotStop(t *testing.T) {
	f := newFixture(t)
	f.ended()
	lane := f.child
	lane.State = "running"
	f.store.lanes["child"] = lane
	missing := api.NotImplemented("lb-v2-service", "fixture transaction")
	f.store.transactErr = missing
	request := api.StopRequest{Target: f.target, ExpectedGeneration: 1,
		Reason: f.blob("reason", "task", []byte("stop\n"))}
	_, err := f.service.LaneStop(context.Background(), f.scope("lane.stop", request, f.parent), request)
	if err != missing || f.launcher.stopped.Load() != 0 || len(f.store.transactions) != 0 {
		t.Fatalf("failed intent triggered or fabricated a stop: %v", err)
	}
}

func TestReviewedStatePath(t *testing.T) {
	f := newFixture(t)
	f.ended()
	receipt := fixtureReview(f)
	f.add("lane.reviewed", receipt, 2, "service", f.parent)
	for _, state := range []string{"accepted", "merged"} {
		lane := f.store.lanes["child"]
		request := api.MarkRequest{Target: f.target, ExpectedGeneration: lane.Generation, State: state, Review: receipt}
		operation, err := f.service.LaneMark(context.Background(), f.scope("lane.mark", request, f.parent), request)
		if err != nil || operation.Status != "succeeded" || f.store.lanes["child"].State != state {
			t.Fatalf("reviewed state path lost %s: %v", state, err)
		}
	}
	if f.store.lanes["child"].Workspace != f.child.Workspace || f.store.lanes["child"].Session != f.child.Session {
		t.Fatal("marking a decision changed the workspace or session")
	}
	lane := f.store.lanes["child"]
	request := api.MarkRequest{Target: f.target, ExpectedGeneration: lane.Generation, State: "accepted", Review: receipt}
	_, err := f.service.LaneMark(context.Background(), f.scope("lane.mark", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict {
		t.Fatalf("reviewed state path allowed a reverse transition: %v", err)
	}
}

func TestMergeRequiresAcceptance(t *testing.T) {
	f := newFixture(t)
	f.ended()
	receipt := fixtureReview(f)
	f.add("lane.reviewed", receipt, 2, "service", f.parent)
	request := api.MarkRequest{Target: f.target, ExpectedGeneration: 1, State: "merged", Review: receipt}
	_, err := f.service.LaneMark(context.Background(), f.scope("lane.mark", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict {
		t.Fatalf("merge skipped the acceptance decision: %v", err)
	}
}

func TestReviewChangesInvalidate(t *testing.T) {
	f := newFixture(t)
	f.ended()
	receipt := fixtureReview(f)
	f.add("lane.reviewed", receipt, 2, "service", f.parent)
	f.add("capture.gap", api.CaptureGap{Target: f.target, Stream: "vendor",
		Reason: "late capture", ObservedAt: "2030-01-02T03:04:05Z"}, 2, "service", f.parent)
	request := api.MarkRequest{Target: f.target, ExpectedGeneration: 1, State: "accepted", Review: receipt}
	_, err := f.service.LaneMark(context.Background(), f.scope("lane.mark", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeForbidden {
		t.Fatalf("changed capture reused a stale review: %v", err)
	}
}

func TestIncompleteCoverageRefuses(t *testing.T) {
	f := newFixture(t)
	f.ended()
	receipt := fixtureReview(f)
	receipt.Coverage = "incomplete"
	f.add("lane.reviewed", receipt, 2, "service", f.parent)
	request := api.MarkRequest{Target: f.target, ExpectedGeneration: 1, State: "accepted", Review: receipt}
	_, err := f.service.LaneMark(context.Background(), f.scope("lane.mark", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeForbidden {
		t.Fatalf("uncovered service receipt was accepted: %v", err)
	}
}

func fixtureArchiveManifest(f *fixture, id api.ID) api.BlobRef {
	f.t.Helper()
	task := f.blob(api.ID(string(id)+"-task"), "artifact", f.store.blobs[f.child.Task.ID])
	raw, err := json.Marshal(api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "task", Kind: "file", Mode: 0600, Content: &task}}})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.blob(id, "manifest", raw)
}

func fixtureArchive(f *fixture) api.ArchiveReceipt {
	f.t.Helper()
	snapshot := fixtureArchiveManifest(f, "manifest")
	tree, err := archivejob.Manifest(f.store.blobs[snapshot.ID])
	if err != nil {
		f.t.Fatal(err)
	}
	read := func(_ context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
		data, found := f.store.blobs[request.ObjectID]
		if !found || request.Offset < 0 || request.Offset > int64(len(data)) || request.Limit <= 0 {
			return api.BlobChunk{}, launchMissing()
		}
		part := data[request.Offset:min(int64(len(data)), request.Offset+int64(request.Limit))]
		return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: append([]byte{}, part...), SHA256: digestOf(part)}, nil
	}
	var output bytes.Buffer
	if err := archivejob.Write(context.Background(), &output, tree, read, f.budget.DiskBytes); err != nil {
		f.t.Fatal(err)
	}
	part := f.blob("archive-part", "artifact", output.Bytes())
	assembly := api.ObjectAssembly{SHA256: digestOf(output.Bytes()), Bytes: int64(output.Len()), Parts: []api.BlobRef{part}}
	readBack, err := archivejob.ReadBack(context.Background(), assembly, tree, read, f.budget.DiskBytes)
	if err != nil {
		f.t.Fatal(err)
	}
	return api.ArchiveReceipt{ID: "archive", LifeID: f.child.LifeID, StoreID: "store",
		Manifest: snapshot, ArchiveSHA256: assembly.SHA256, ReadBackSHA256: readBack, VerifiedAt: "2030-01-02T03:04:05Z"}
}

func TestArchiveChangesInvalidate(t *testing.T) {
	f := newFixture(t)
	f.ended()
	f.add("archive.verified", fixtureArchive(f), 2, "service", f.parent)
	f.add("capture.gap", api.CaptureGap{Target: f.target, Stream: "vendor",
		Reason: "late capture", ObservedAt: "2030-01-02T03:04:05Z"}, 2, "service", f.parent)
	lane := f.child
	lane.State = "merged"
	f.store.lanes["child"] = lane
	request := api.CleanRequest{Target: f.target, ExpectedGeneration: 1, ArchiveReceiptID: "archive"}
	_, err := f.service.LaneClean(context.Background(), f.scope("lane.clean", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("changed capture reused a stale archive: %v", err)
	}
}

func TestArchiveNeedsEndedRun(t *testing.T) {
	f := newFixture(t)
	f.add("archive.verified", fixtureArchive(f), 2, "service", f.parent)
	f.ended()
	lane := f.child
	lane.State = "merged"
	f.store.lanes["child"] = lane
	request := api.CleanRequest{Target: f.target, ExpectedGeneration: 1, ArchiveReceiptID: "archive"}
	_, err := f.service.LaneClean(context.Background(), f.scope("lane.clean", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("archive from before the run end was reused: %v", err)
	}
}

func TestArchiveReceiptLifeBound(t *testing.T) {
	f := newFixture(t)
	f.ended()
	receipt := fixtureArchive(f)
	receipt.LifeID = "sibling"
	f.add("archive.verified", receipt, 2, "service", f.parent)
	lane := f.child
	lane.State = "merged"
	f.store.lanes["child"] = lane
	request := api.CleanRequest{Target: f.target, ExpectedGeneration: 1, ArchiveReceiptID: "archive"}
	_, err := f.service.LaneClean(context.Background(), f.scope("lane.clean", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("another life's archive receipt was accepted: %v", err)
	}
}

func TestCleanNeedsFinalState(t *testing.T) {
	f := newFixture(t)
	f.ended()
	f.add("archive.verified", fixtureArchive(f), 2, "service", f.parent)
	request := api.CleanRequest{Target: f.target, ExpectedGeneration: 1, ArchiveReceiptID: "archive"}
	_, err := f.service.LaneClean(context.Background(), f.scope("lane.clean", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict {
		t.Fatalf("clean skipped its merged or abandoned decision: %v", err)
	}
}

func TestResumeBudgetDoesNotReset(t *testing.T) {
	f := newFixture(t)
	f.ended()
	request := api.ResumeRequest{Target: f.target, ExpectedGeneration: 1,
		Message: f.blob("message", "task", []byte("continue\n")), Budget: f.budget}
	request.Budget.WallMS++
	_, err := f.service.LaneResume(context.Background(), f.scope("lane.resume", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeBudget {
		t.Fatalf("resume expanded the remaining budget: %v", err)
	}
}

func TestResumeSessionIsRequired(t *testing.T) {
	f := newFixture(t)
	f.ended()
	lane := f.child
	lane.Session.VendorID = ""
	f.store.lanes["child"] = lane
	request := api.ResumeRequest{Target: f.target, ExpectedGeneration: 1,
		Message: f.blob("message", "task", []byte("continue\n")), Budget: f.budget}
	_, err := f.service.LaneResume(context.Background(), f.scope("lane.resume", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodePrerequisite {
		t.Fatalf("resume ignored the missing vendor session: %v", err)
	}
}

func TestRevokedGrantsRefuse(t *testing.T) {
	f := newFixture(t)
	f.ended()
	grants := f.store.grants["grants"]
	grants.Revoked = true
	f.store.grants["grants"] = grants
	request := api.ResumeRequest{Target: f.target, ExpectedGeneration: 1,
		Message: f.blob("message", "task", []byte("continue\n")), Budget: f.budget}
	_, err := f.service.LaneResume(context.Background(), f.scope("lane.resume", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeForbidden {
		t.Fatalf("revoked grants reached continuation planning: %v", err)
	}
}

func TestTurnRequestActor(t *testing.T) {
	f := newFixture(t)
	mail := api.Mail{ID: "mail", Sender: api.Actor{Kind: "lane", ID: "sender-actor",
		LifeID: "sender", Level: 3, Role: "executor"}, RecipientLifeID: "child"}
	request := api.TurnRequest{Target: f.target, ExpectedGeneration: 1,
		MailIDs: []api.ID{mail.ID}, Budget: f.budget}
	scope := f.scope("lane.turn", request, f.parent)
	trigger, err := turnTrigger(request)
	if err != nil {
		t.Fatal(err)
	}
	prompt := f.blob("prompt", "prompt", []byte("screened turn prompt\n"))
	event, err := f.service.event(scope, f.child, "lane.turn", api.TurnEvent{
		Task: f.child.Task, Trigger: trigger, Prompt: prompt, Status: "not_written", MailIDs: trigger.MailIDs}, scope.Actor)
	if err != nil {
		t.Fatal(err)
	}
	if event.Actor != f.parent || event.RequestedBy != f.parent || event.Actor == mail.Sender ||
		event.ParentLifeID != f.child.ParentLifeID || event.StarterEventSeq != f.child.StarterEventSeq {
		t.Fatal("turn envelope borrowed a sender or lost the authentic requester")
	}
	var payload api.TurnEvent
	if err := DecodeRequest(event.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Task != f.child.Task || payload.Trigger.Kind != "mail" || !reflect.DeepEqual(payload.MailIDs, []api.ID{mail.ID}) {
		t.Fatal("turn envelope lost its ordered cause")
	}
	// Mutating the request later cannot rewrite the retained event or trigger.
	request.MailIDs[0] = "other-mail"
	if trigger.MailIDs[0] != mail.ID {
		t.Fatal("turn trigger retained the caller's mutable mail slice")
	}
}

func TestTurnOrderAndIdle(t *testing.T) {
	f := newFixture(t)
	request := api.TurnRequest{Target: f.target, MailIDs: []api.ID{"second", "first"}}
	trigger, err := turnTrigger(request)
	if err != nil || !reflect.DeepEqual(trigger.MailIDs, request.MailIDs) {
		t.Fatalf("turn reordered explicit carried references: %v", err)
	}
	idle := f.blob("idle", "task", []byte("idle payload\n"))
	request.MailIDs, request.IdleMessage = []api.ID{}, &idle
	trigger, err = turnTrigger(request)
	if err != nil || trigger.Kind != "idle" || trigger.MailIDs == nil || trigger.CausingSeqs == nil {
		t.Fatalf("idle trigger lost its explicit payload or array shape: %v", err)
	}
	request.MailIDs = []api.ID{"same", "same"}
	_, err = turnTrigger(request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeInvalid {
		t.Fatalf("turn admitted duplicate carried mail: %v", err)
	}
}

func TestInputDigestIsChecked(t *testing.T) {
	f := newFixture(t)
	ref := f.blob("input", "task", []byte("actual retained input\n"))
	f.store.blobHook = func(chunk api.BlobChunk) (api.BlobChunk, error) {
		chunk.Data = append([]byte{}, chunk.Data...)
		chunk.Data[0] ^= 1
		chunk.SHA256 = digestOf(chunk.Data)
		return chunk, nil
	}
	_, err := f.service.readBlob(context.Background(), f.scope("lane.check", f.target, f.parent), ref)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("input with a different complete digest was consumed: %v", err)
	}
}

func TestInputRangeIsChecked(t *testing.T) {
	f := newFixture(t)
	ref := f.blob("input", "task", []byte("actual retained input\n"))
	f.store.blobHook = func(chunk api.BlobChunk) (api.BlobChunk, error) {
		chunk.Offset++
		return chunk, nil
	}
	_, err := f.service.readBlob(context.Background(), f.scope("lane.check", f.target, f.parent), ref)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("input range with a different offset was consumed: %v", err)
	}
}

func TestEmptyInputMustExist(t *testing.T) {
	f := newFixture(t)
	ref := f.blob("empty", "task", []byte{})
	scope := f.scope("lane.check", f.target, f.parent)
	data, err := f.service.readBlob(context.Background(), scope, ref)
	if err != nil || data == nil || len(data) != 0 {
		t.Fatalf("committed empty input was not readable: %v", err)
	}
	ref.ID = "absent-empty"
	// A backend metadata/content mismatch must not make an absent empty
	// content object successful. The ordinary missing-metadata case is also
	// rejected by the new ObjectMetadata call before any bytes are consumed.
	f.store.metadata[ref.ID] = api.ObjectMetadata{Ref: ref, ACL: api.ObjectACL{Config: "example"}}
	_, err = f.service.readBlob(context.Background(), scope, ref)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeNotFound {
		t.Fatalf("missing empty input bypassed the store lookup: %v", err)
	}
}

func TestInternalContinueRejectsLane(t *testing.T) {
	f := newFixture(t)
	request := fixtureContinuation(f)
	executor := api.Actor{Kind: "lane", ID: "executor", LifeID: f.child.LifeID, Level: f.child.Level, Role: f.child.Role}
	// Exercise the private entry shape so the independent public-method
	// guard does not mask removal of the actor/source authorization gate.
	scope := api.Scope{Config: "example", Actor: executor, Source: "cli", PolicyGeneration: f.store.policy.Generation}
	reads := f.store.operationReads
	_, err := f.service.Continue(context.Background(), scope, request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeForbidden {
		t.Fatalf("lane principal invoked internal continuation: %v", err)
	}
	if f.store.operationReads != reads {
		t.Fatal("lane principal invoked internal continuation before authorization")
	}
}

func TestDirectReviewCannotPass(t *testing.T) {
	f := newFixture(t)
	f.ended()
	receipt := fixtureReview(f)
	f.service.deps.ReviewControl = nil
	request := api.ReviewRequest{Target: f.target, Diff: receipt.Diff, Checks: receipt.Checks,
		RecordInventory: receipt.RecordInventory, RefusalResolution: []api.ID{}}
	read := map[api.ID]bool{}
	f.store.blobHook = func(chunk api.BlobChunk) (api.BlobChunk, error) {
		read[chunk.ObjectID] = true
		return chunk, nil
	}
	actual, err := f.service.LaneReview(context.Background(), f.scope("lane.review", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeNotImplemented ||
		typed.Owner != "lb-v2-service" || !strings.Contains(typed.Message, "installed review subject and worker preparation") ||
		!reflect.ValueOf(actual).IsZero() {
		t.Fatalf("uploaded references became trusted review evidence: %v", err)
	}
	for _, ref := range append([]api.BlobRef{receipt.Diff, receipt.RecordInventory}, receipt.Checks...) {
		if !read[ref.ID] {
			t.Fatal("review did not read every committed evidence object")
		}
	}
	if len(f.store.transactions) != 0 {
		t.Fatal("unverified evidence created a review receipt")
	}
}

func TestObservedEndCannotBeTerminal(t *testing.T) {
	f := newFixture(t)
	event := f.ended()
	var end api.RunEndEvent
	if err := json.Unmarshal(event.Payload, &end); err != nil {
		t.Fatal(err)
	}
	end.Observation.Survivors = nil
	data, err := json.Marshal(end)
	if err != nil {
		t.Fatal(err)
	}
	event.Payload = data
	request := api.EventTailRequest{LifeID: "child", Run: 2, Until: "lane.ended"}
	_, err = selectedEvent(f.scope("event.tail", request, f.parent), f.child, request, event)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("incomplete terminal event could satisfy follow: %v", err)
	}
}
