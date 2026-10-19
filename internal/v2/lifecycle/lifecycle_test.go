package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRequiredDependencies(t *testing.T) {
	service, err := New(Dependencies{})
	requireCode(t, err, api.CodePrerequisite)
	if service != nil {
		t.Fatal("missing dependencies created a usable service")
	}
}

func TestTreeVisibility(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	scope := f.scope("lane.status", f.target, f.parent)
	lane, err := f.service.LaneStatus(ctx, scope, f.target)
	if err != nil || lane.LifeID != f.child.LifeID {
		t.Fatalf("authentic parent cannot read child: %v", err)
	}
	sibling := api.Actor{Kind: "lane", ID: "sibling-actor", LifeID: "sibling", Level: 5, Role: "supervisor"}
	_, err = f.service.LaneStatus(ctx, f.scope("lane.status", f.target, sibling), f.target)
	requireCode(t, err, api.CodeNotFound)
	query := api.ListRequest{Limit: 100}
	page, err := f.service.LaneList(ctx, f.scope("lane.list", query, sibling), query)
	if err != nil || page.Lanes == nil || len(page.Lanes) != 0 {
		t.Fatalf("sibling received an unrelated tree: %v", err)
	}
	page, err = f.service.LaneList(ctx, f.scope("lane.list", query, f.parent), query)
	if err != nil || len(page.Lanes) != 2 {
		t.Fatalf("parent tree listing lost self or child: %v", err)
	}
}

func TestMetadataCannotChangeActor(t *testing.T) {
	f := newFixture(t)
	scope := f.scope("lane.status", f.target, f.parent)
	scope.Request.Method = "lane.start"
	_, err := f.service.LaneStatus(context.Background(), scope, f.target)
	requireCode(t, err, api.CodeUnauthenticated)
	if len(f.identity.actors) != 0 {
		t.Fatal("mismatched dispatcher metadata reached authorization")
	}
	scope = f.scope("lane.status", f.target, f.parent)
	scope.Request.Params = json.RawMessage(`{"life_id":"other","run":2}`)
	_, err = f.service.LaneStatus(context.Background(), scope, f.target)
	requireCode(t, err, api.CodeIntegrity)
}

func TestStoreStubIsNotSuccess(t *testing.T) {
	f := newFixture(t)
	missing := api.NotImplemented("lb-v2-service", "fixture Store.Lane")
	f.store.laneErr = missing
	_, err := f.service.LaneStatus(context.Background(),
		f.scope("lane.status", f.target, f.parent), f.target)
	if err != missing {
		t.Fatalf("dependency error was replaced or swallowed: %v", err)
	}
}

func TestFollowIgnoresOtherEnds(t *testing.T) {
	f := newFixture(t)
	old := f.ended()
	f.store.events[0].Run = 1
	hidden := f.ended()
	f.store.events[1].LifeID = "sibling"
	f.add("lane.ended", api.RunEndEvent{}, 2, "observation", f.parent)
	request := api.EventTailRequest{LifeID: "child", Run: 2, Since: old.Seq,
		Follow: true, Until: "lane.ended", DeadlineMS: 2000}
	stream, err := f.service.OpenEvents(context.Background(),
		f.scope("event.tail", request, f.parent), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	type delivered struct {
		frame api.StreamFrame
		err   error
	}
	result := make(chan delivered, 1)
	go func() {
		frame, err := stream.Next(context.Background())
		result <- delivered{frame, err}
	}()
	select {
	case <-f.store.read:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher never read its authorized snapshot")
	}
	select {
	case early := <-result:
		t.Fatalf("older/hidden/observed end completed follow: %v", early.err)
	default:
	}
	committed := time.Now()
	selected := f.ended()
	f.service.NotifyCommit()
	select {
	case got := <-result:
		if got.err != nil || got.frame.Event == nil || got.frame.Event.Seq != selected.Seq ||
			got.frame.Event.Seq == hidden.Seq || got.frame.End {
			t.Fatalf("wrong selected event: %v", got.err)
		}
		if time.Since(committed) > 2*time.Second {
			t.Fatal("fixture watcher exceeded commit-to-delivery bound")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("selected committed end was not delivered")
	}
	end, err := stream.Next(context.Background())
	if err != nil || !end.End || end.Event != nil || end.Index != 2 {
		t.Fatalf("missing separate stream end frame: %v", err)
	}
}

func TestFollowRechecksRevocation(t *testing.T) {
	f := newFixture(t)
	f.add("run.observed", f.launcher.observation, 2, "service", f.parent)
	f.add("run.observed", f.launcher.observation, 2, "service", f.parent)
	request := api.EventTailRequest{LifeID: "child", Run: 2, Follow: true,
		Until: "lane.ended", DeadlineMS: 2000}
	stream, err := f.service.OpenEvents(context.Background(),
		f.scope("event.tail", request, f.parent), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	first, err := stream.Next(context.Background())
	if err != nil || first.Event == nil || first.Cursor != "" {
		t.Fatalf("partial page exposed a skipping cursor: %v", err)
	}
	f.identity.denied.Store(true)
	_, err = stream.Next(context.Background())
	requireCode(t, err, api.CodeForbidden)
}

func TestWatcherCloseDoesNotStop(t *testing.T) {
	f := newFixture(t)
	request := api.EventTailRequest{LifeID: "child", Run: 2, Follow: true,
		Until: "lane.ended", DeadlineMS: 2000}
	stream, err := f.service.OpenEvents(context.Background(),
		f.scope("event.tail", request, f.parent), request)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := stream.Next(context.Background()); result <- err }()
	select {
	case <-f.store.read:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher never started")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("closed watcher did not terminate: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher close remained blocked")
	}
	if f.launcher.stopped.Load() != 0 || len(f.store.transactions) != 0 {
		t.Fatal("closing a watcher changed the lane")
	}
}

func TestStreamBounds(t *testing.T) {
	f := newFixture(t)
	for range 201 {
		f.add("run.observed", f.launcher.observation, 2, "service", f.parent)
	}
	f.store.pageOverride = &api.EventPage{Events: append([]api.Event{}, f.store.events...), Complete: true}
	request := api.EventTailRequest{LifeID: "child", Run: 2}
	_, err := f.service.EventTail(context.Background(),
		f.scope("event.tail", request, f.parent), request)
	requireCode(t, err, api.CodeUnavailable)
}

func TestCursorBindingDelegated(t *testing.T) {
	f := newFixture(t)
	f.ended()
	request := api.EventTailRequest{LifeID: "child", Run: 2}
	scope := f.scope("event.tail", request, f.parent)
	page, err := f.service.EventTail(context.Background(), scope, request)
	if err != nil || page.Cursor == "" {
		t.Fatal("store cursor not returned", err)
	}
	request.Cursor = page.Cursor
	request.Run = 1
	_, err = f.service.EventTail(context.Background(),
		f.scope("event.tail", request, f.parent), request)
	requireCode(t, err, api.CodeCursorExpired)
}

func TestUnknownCheckRecordsNoEnd(t *testing.T) {
	f := newFixture(t)
	f.ended()
	f.launcher.observation.State = "unknown"
	f.launcher.observation.ExitCode = nil
	f.launcher.observation.Survivors = nil
	_, err := f.service.LaneCheck(context.Background(),
		f.scope("lane.check", f.target, f.parent), f.target)
	requireCode(t, err, api.CodeContainmentUnknown)
	if len(f.store.transactions) != 1 {
		t.Fatal("unknown containment has no durable error receipt")
	}
	tx := f.store.transactions[0]
	if tx.Reply == nil || tx.Reply.Error != err || len(tx.Events) != 0 ||
		len(tx.Effects) != 0 || len(tx.Guards) != 0 || !reflect.ValueOf(tx.Writes).IsZero() {
		t.Fatal("unknown containment changed state instead of retaining its exact error")
	}
	if f.store.lanes["child"].State != "verifying" {
		t.Fatal("unknown observation fabricated a lifecycle transition")
	}
}

func TestStopPersistsIntentOnly(t *testing.T) {
	f := newFixture(t)
	f.add("identity.bound", f.store.launches["launch"], 2, "service", f.parent)
	f.add("run.observed", f.launcher.observation, 2, "service", f.parent)
	lane := f.child
	lane.State = "running"
	f.store.lanes["child"] = lane
	request := api.StopRequest{Target: f.target, ExpectedGeneration: 1,
		Reason: f.blob("reason", "task", []byte("stop the contained run\n"))}
	scope := f.scope("lane.stop", request, f.parent)
	operation, err := f.service.LaneStop(context.Background(), scope, request)
	if err != nil || operation.Status != "pending" {
		t.Fatalf("stop did not return its durable pending intent: %v", err)
	}
	if f.launcher.stopped.Load() != 0 || len(f.store.transactions) != 1 {
		t.Fatal("stop executed before the outbox committed")
	}
	tx := f.store.transactions[0]
	if len(tx.Effects) != 1 || tx.Effects[0].Stop == nil ||
		tx.Effects[0].OperationID != tx.Events[0].OperationID || tx.Events[0].Kind != "lane.stopping" ||
		tx.Events[0].Actor != f.parent || tx.Events[0].RequestedBy != f.parent {
		t.Fatal("stop intent lost its effect or authentic requester")
	}
	replayed, err := f.service.LaneStop(context.Background(), scope, request)
	if err != nil || replayed.ID != operation.ID || len(f.store.transactions) != 1 {
		t.Fatalf("stale identical retry duplicated stop intent: %v", err)
	}
}

func fixtureReview(f *fixture) api.ReviewReceipt {
	return fixtureReviewFor(f, f.store.lanes[f.target.LifeID])
}

func TestMarkConsumesTrustedReview(t *testing.T) {
	f := newFixture(t)
	f.ended()
	receipt := fixtureReview(f)
	f.add("lane.reviewed", receipt, 2, "service", f.parent)
	request := api.MarkRequest{Target: f.target, ExpectedGeneration: 1, State: "accepted", Review: receipt}
	scope := f.scope("lane.mark", request, f.parent)
	operation, err := f.service.LaneMark(context.Background(), scope, request)
	if err != nil || operation.Status != "succeeded" || f.store.lanes["child"].State != "accepted" {
		t.Fatalf("trusted independent review could not be accepted: %v", err)
	}
	replayed, err := f.service.LaneMark(context.Background(), scope, request)
	if err != nil || replayed.ID != operation.ID || len(f.store.transactions) != 1 {
		t.Fatalf("accepted retry did not replay before CAS: %v", err)
	}
	changed := request
	changed.Review.Diff.SHA256 = digestOf([]byte("changed"))
	changedScope := scope
	changedScope.Request.Params, err = json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	changedScope.Request.RequestSHA256, err = api.RequestDigest(changedScope.Request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.LaneMark(context.Background(), changedScope, changed)
	requireCode(t, err, api.CodeIdempotencyConflict)
}

func TestForgedReviewsRefuse(t *testing.T) {
	for _, mutation := range []string{"missing", "altered", "checks", "inventory", "resolution", "uncovered", "self"} {
		t.Run(mutation, func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			receipt := fixtureReview(f)
			if mutation == "resolution" {
				control := f.service.deps.ReviewControl.(*fixtureReviewControl)
				control.subject.RefusalIDs = []api.ID{"first-refusal", "second-refusal"}
				receipt.Evidence.Subject = control.subject
				receipt.RefusalResolution = append([]api.ID{}, control.subject.RefusalIDs...)
				for _, id := range control.subject.RefusalIDs {
					receipt.Evidence.Resolutions = append(receipt.Evidence.Resolutions, api.ReviewResolution{RefusalID: id,
						EventSeq: control.subject.InventorySeq, Evidence: f.measuredBlob(id, "manifest", []byte("authenticated resolution "+string(id)), "resolution-operation", f.target)})
				}
			}
			stored := f.add("lane.reviewed", receipt, 2, "service", f.parent)
			var retained api.ReviewReceipt
			if err := api.DecodeObject(stored.Payload, &retained); err != nil || !reflect.DeepEqual(retained, receipt) {
				t.Fatalf("review fixture lost its retained receipt: %v", err)
			}
			switch mutation {
			case "missing":
				receipt.ID = "not-a-receipt"
			case "altered":
				receipt.Diff = f.measuredBlob("other-diff", "diff", []byte("different reviewed diff\n"), "verifier-operation", f.target)
				receipt.Evidence.Diff = receipt.Diff
			case "checks":
				receipt.Checks = append([]api.BlobRef{}, receipt.Checks...)
				receipt.Checks[0] = f.measuredBlob("other-check", "check", []byte("different check evidence\n"), "check-operation", f.target)
				receipt.Evidence.Checks[0].Receipt = receipt.Checks[0]
			case "inventory":
				receipt.RecordInventory = f.measuredBlob("other-inventory", "manifest", []byte("different inventory\n"), "verifier-operation", f.target)
				receipt.Evidence.Inventory.Manifest = receipt.RecordInventory
			case "resolution":
				receipt.RefusalResolution = []api.ID{"second-refusal", "first-refusal"}
			case "uncovered":
				receipt.Coverage = "incomplete"
			case "self":
				receipt.Reviewer = api.Actor{Kind: "lane", ID: "executor", LifeID: "child", Level: 3, Role: "executor"}
			}
			request := api.MarkRequest{Target: f.target, ExpectedGeneration: 1, State: "accepted", Review: receipt}
			scope := f.scope("lane.mark", request, f.parent)
			if mutation == "altered" {
				original, err := f.service.readBlob(context.Background(), scope, retained.Diff)
				if err != nil {
					t.Fatalf("retained review diff was not readable: %v", err)
				}
				altered, err := f.service.readBlob(context.Background(), scope, receipt.Diff)
				if err != nil || bytes.Equal(original, altered) || retained.Diff.SHA256 == receipt.Diff.SHA256 {
					t.Fatalf("review fixture did not provide distinct valid diff bytes: %v", err)
				}
			}
			_, err := f.service.LaneMark(context.Background(), scope, request)
			requireCode(t, err, api.CodeForbidden)
			if len(f.store.transactions) != 0 {
				t.Fatal("forged review changed authoritative state")
			}
		})
	}
}

func TestSelfAcceptanceRefuses(t *testing.T) {
	f := newFixture(t)
	f.ended()
	receipt := fixtureReview(f)
	f.add("lane.reviewed", receipt, 2, "service", f.parent)
	request := api.MarkRequest{Target: f.target, ExpectedGeneration: 1,
		State: "accepted", Review: receipt}
	executor := api.Actor{Kind: "lane", ID: "executor", LifeID: "child", Level: 3, Role: "executor"}
	reads := f.store.laneReads
	_, err := f.service.LaneMark(context.Background(), f.scope("lane.mark", request, executor), request)
	requireCode(t, err, api.CodeForbidden)
	// The self-accept mutation removes the early independence gate. Later
	// receipt checks also refuse, so observe whether that boundary was crossed
	// without weakening the original forbidden/no-write assertions.
	if f.store.laneReads != reads {
		t.Fatal("wanted forbidden before self-accept target access")
	}
	if len(f.store.transactions) != 0 {
		t.Fatal("executor accepted its own work")
	}
}

func TestArchiveReadBackBeforeClean(t *testing.T) {
	for _, mode := range []string{"missing", "mismatch", "worker"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			end := f.ended()
			lane := f.child
			lane.State = "merged"
			f.store.lanes["child"] = lane
			receipt := fixtureArchive(f)
			if mode == "mismatch" {
				receipt.ReadBackSHA256 = digestOf([]byte("different archive"))
			}
			if mode != "missing" {
				f.add("archive.verified", receipt, 2, "service", f.parent)
			}
			request := api.CleanRequest{Target: f.target, ExpectedGeneration: 1, ArchiveReceiptID: "archive"}
			scope := f.scope("lane.clean", request, f.parent)
			if mode == "worker" {
				verified, err := f.service.archiveReceipt(context.Background(), scope, lane, request, end.Seq)
				if err != nil || !reflect.DeepEqual(verified, receipt) {
					t.Fatalf("verified archive did not pass the read-back gate: %v", err)
				}
			}
			operation, err := f.service.LaneClean(context.Background(), scope, request)
			if mode == "worker" {
				if err != nil || operation.Status != "pending" || len(f.store.transactions) != 1 || len(f.store.transactions[0].Effects) != 1 || f.store.transactions[0].Effects[0].Clean == nil {
					t.Fatalf("verified archive did not retain the original removal intent: %v", err)
				}
			} else {
				requireCode(t, err, api.CodeIntegrity)
				if len(f.store.transactions) != 0 {
					t.Fatal("cleanup passed its archive receipt barrier")
				}
			}
			if f.store.lanes["child"].Cleaned {
				t.Fatal("cleanup passed a receipt or missing-worker barrier")
			}
		})
	}
}

func fixtureStart(f *fixture) api.StartRequest {
	return api.StartRequest{Lane: "new-child", ProjectID: "project", Level: 3, Role: "executor",
		Task: f.blob("task", "task", []byte("real task input\n")), Driver: api.DriverCodex,
		ProfileGrantID: "profile", Model: "fixture-model", Effort: "max", Budget: f.budget,
		ExpectedPolicyGeneration: 1, Grants: api.GrantRequest{Resources: []api.ResourceDelegation{},
			Data: []api.DataGrantRequest{}, Secrets: []api.SecretDelegation{}, Profiles: []api.ProfileDelegation{},
			Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
}

func TestLaunchGateCannotBeSkipped(t *testing.T) {
	f := newFixture(t)
	f.launcher.available = false
	request := fixtureStart(f)
	_, err := f.service.LaneStart(context.Background(), f.scope("lane.start", request, f.parent), request)
	requireCode(t, err, api.CodePrerequisite)
	if f.launcher.prepared.Load() != 0 || f.launcher.launched.Load() != 0 || len(f.store.transactions) != 0 {
		t.Fatal("failed launch gate executed or registered an agent")
	}
}

func TestStrictLowerSpawnLevel(t *testing.T) {
	for _, level := range []int{5, 6} {
		f := newFixture(t)
		request := fixtureStart(f)
		request.Level = level
		_, err := f.service.LaneStart(context.Background(), f.scope("lane.start", request, f.parent), request)
		requireCode(t, err, api.CodeForbidden)
		if f.launcher.prepared.Load() != 0 || len(f.store.transactions) != 0 {
			t.Fatal("same/higher level launch passed D9")
		}
	}
}

func TestCleanedResumeRefuses(t *testing.T) {
	f := newFixture(t)
	lane := f.child
	lane.Cleaned = true
	f.store.lanes["child"] = lane
	request := api.ResumeRequest{Target: f.target, ExpectedGeneration: 1,
		Message: f.blob("message", "task", []byte("continue\n")), Budget: f.budget}
	_, err := f.service.LaneResume(context.Background(), f.scope("lane.resume", request, f.parent), request)
	requireCode(t, err, api.CodeConflict)
	if f.launcher.prepared.Load() != 0 || len(f.store.transactions) != 0 {
		t.Fatal("cleaned life was reused")
	}
}

func TestUnknownResumeRefuses(t *testing.T) {
	f := newFixture(t)
	f.ended()
	f.launcher.observation.State = "unknown"
	f.launcher.observation.ExitCode = nil
	f.launcher.observation.Survivors = nil
	request := api.ResumeRequest{Target: f.target, ExpectedGeneration: 1,
		Message: f.blob("message", "task", []byte("continue\n")), Budget: f.budget}
	_, err := f.service.LaneResume(context.Background(), f.scope("lane.resume", request, f.parent), request)
	requireCode(t, err, api.CodeContainmentUnknown)
	if len(f.store.transactions) != 0 {
		t.Fatal("unknown survivors admitted a new run")
	}
}

type fixtureRegistry struct {
	handlers map[api.Method]api.Handler
	streams  map[api.Method]api.StreamHandler
}

func (registry *fixtureRegistry) Register(method api.Method, handler api.Handler) error {
	if registry.handlers[method] != nil {
		return errors.New("fixture duplicate registration")
	}
	registry.handlers[method] = handler
	return nil
}

func (registry *fixtureRegistry) RegisterStream(method api.Method, handler api.StreamHandler) error {
	if registry.streams[method] != nil {
		return errors.New("fixture duplicate stream registration")
	}
	registry.streams[method] = handler
	return nil
}

func TestRegistersFrozenMethods(t *testing.T) {
	f := newFixture(t)
	registry := &fixtureRegistry{handlers: map[api.Method]api.Handler{}, streams: map[api.Method]api.StreamHandler{}}
	if err := f.service.Register(registry); err != nil {
		t.Fatal(err)
	}
	want := map[api.Method]bool{}
	for method, spec := range api.Methods {
		if spec.Owner == owner {
			want[method] = true
		}
	}
	got := map[api.Method]bool{}
	for method := range registry.handlers {
		got[method] = true
	}
	if !reflect.DeepEqual(got, want) || len(registry.streams) != 2 ||
		registry.streams["event.tail"] == nil || registry.streams["lane.attach"] == nil {
		t.Fatal("lifecycle registration drifted from its closed catalog")
	}
	_, err := registry.handlers["lane.status"](context.Background(), api.Scope{},
		json.RawMessage(`{"life_id":"child","run":2,"actor":"parent"}`))
	requireCode(t, err, api.CodeInvalid)
}
