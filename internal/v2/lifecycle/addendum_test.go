package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func fixtureLostRun(f *fixture, afterEnd bool) {
	f.t.Helper()
	fixtureActiveRun(f)
	if afterEnd {
		f.ended()
	}
	lost := f.launcher.observation
	lost.State, lost.Survivors, lost.ExitCode, lost.Signal = "unknown", nil, nil, nil
	lost.PromptStatus = "unknown"
	f.add("lane.lost", api.RunEndEvent{LaunchID: f.child.LaunchID, Reason: "service_lost", Observation: lost,
		BudgetRemaining: f.budget}, f.target.Run, "service", f.parent)
}

func TestLostIsNotEnded(t *testing.T) {
	for _, mode := range []string{"lost", "after-end"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			fixtureLostRun(f, mode == "after-end")
			lane := f.store.lanes[f.target.LifeID]
			lane.State = "verifying"
			f.store.lanes[lane.LifeID] = lane
			review := fixtureReview(f)
			f.add("lane.reviewed", review, lane.Run, "service", f.parent)
			request := api.MarkRequest{Target: f.target, ExpectedGeneration: lane.Generation, State: "accepted", Review: review}
			_, err := f.service.LaneMark(context.Background(), f.scope("lane.mark", request, f.parent), request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || len(f.store.transactions) != 0 {
				t.Fatalf("lost observation substituted for a committed end: %v", err)
			}
			lane.State = "abandoned"
			f.store.lanes[lane.LifeID] = lane
			digest := digestOf([]byte("archive"))
			archive := api.ArchiveReceipt{ID: "archive", LifeID: lane.LifeID, StoreID: "store",
				Manifest:      fixtureArchiveManifest(f, "manifest"),
				ArchiveSHA256: digest, ReadBackSHA256: digest, VerifiedAt: "2030-01-02T03:04:05Z"}
			f.add("archive.verified", archive, lane.Run, "service", f.parent)
			clean := api.CleanRequest{Target: f.target, ExpectedGeneration: lane.Generation, ArchiveReceiptID: archive.ID}
			_, err = f.service.LaneClean(context.Background(), f.scope("lane.clean", clean, f.parent), clean)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeContainmentUnknown || len(f.store.transactions) != 0 {
				t.Fatalf("lost observation passed the cleanup end gate: %v", err)
			}
		})
	}
}

func TestLostCanReconcileRealEnd(t *testing.T) {
	f := newFixture(t)
	fixtureLostRun(f, false)
	_, err := f.service.LaneCheck(context.Background(), f.scope("lane.check", f.target, f.parent), f.target)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.store.transactions) != 1 || len(f.store.transactions[0].Events) != 3 ||
		f.store.transactions[0].Events[1].Kind != "lane.ended" || f.store.transactions[0].Events[2].Kind != "lane.state" || f.store.lanes[f.target.LifeID].State != "verifying" {
		t.Fatal("lost run could not record a later measured end")
	}
}

func TestEventsSkipForeignPages(t *testing.T) {
	for _, mode := range []string{"snapshot", "follow"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			count := 401
			if mode == "follow" {
				count = 8201
			}
			for range count {
				f.add("run.observed", f.launcher.observation, f.target.Run, "service", f.parent)
				f.store.events[len(f.store.events)-1].LifeID = "unselected"
			}
			end := f.ended()
			request := api.EventTailRequest{LifeID: f.target.LifeID, Run: f.target.Run, Until: "lane.ended"}
			if mode == "snapshot" {
				page, err := f.service.EventTail(context.Background(), f.scope("event.tail", request, f.parent), request)
				if err != nil || len(page.Events) != 1 || page.Events[0].Seq != end.Seq || !page.Complete {
					t.Fatalf("committed selected events hid behind foreign pages: %v", err)
				}
				return
			}
			request.Follow, request.DeadlineMS = true, 2000
			stream, err := f.service.OpenEvents(context.Background(), f.scope("event.tail", request, f.parent), request)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			started := time.Now()
			frame, err := stream.Next(context.Background())
			if err != nil || frame.Event == nil || frame.Event.Seq != end.Seq || time.Since(started) >= 2*time.Second {
				t.Fatalf("follow slept behind committed foreign pages: %v", err)
			}
		})
	}
}

func TestForeignCursorAdvance(t *testing.T) {
	for _, cursor := range []string{"", "same"} {
		t.Run("cursor-"+cursor, func(t *testing.T) {
			f := newFixture(t)
			event := f.ended()
			event.LifeID = "unselected"
			f.store.pageOverride = &api.EventPage{Events: []api.Event{event}, Cursor: cursor}
			request := api.EventTailRequest{LifeID: f.target.LifeID, Run: f.target.Run, Cursor: cursor}
			_, err := f.service.EventTail(context.Background(), f.scope("event.tail", request, f.parent), request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.store.eventCalls != 1 {
				t.Fatalf("unselected page bypassed cursor progress: %v", err)
			}
		})
	}
}

func fixtureRetainedReply(f *fixture, scope api.Scope, result any) {
	f.t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		f.t.Fatal(err)
	}
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey,
		RequestSHA256: scope.Request.RequestSHA256}
	operation := api.Operation{ID: "retained-operation", LifeID: f.target.LifeID, Run: f.target.Run, Status: "succeeded"}
	if retained, ok := result.(api.Operation); ok {
		operation = retained
	}
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	f.store.receipts[fixtureReceiptKey(scope, key)] = api.MutationReceipt{Config: scope.Config,
		Key: key, Actor: scope.Actor, Reply: &api.RPCReply{Result: raw}, PolicyGeneration: scope.PolicyGeneration,
		Operation: operation}
	f.store.closePending(fixtureReceiptKey(scope, key))
}

func TestReplayBeforeChangedState(t *testing.T) {
	for _, method := range []api.Method{"lane.start", "lane.adopt", "lane.check", "lane.review", "lane.archive", "lane.loop", "lane.input"} {
		t.Run(strings.TrimPrefix(string(method), "lane."), func(t *testing.T) {
			f := newFixture(t)
			inputs := fixtureReview(f)
			operation := api.Operation{ID: "retained-operation", LifeID: f.target.LifeID, Run: f.target.Run, Status: "succeeded"}
			var request any
			var want any = operation
			var call func(api.Scope) (any, error)
			switch method {
			case "lane.start":
				q := fixtureStart(f)
				request, call = q, func(scope api.Scope) (any, error) { return f.service.LaneStart(context.Background(), scope, q) }
			case "lane.adopt":
				start := fixtureStart(f)
				q := api.AdoptRequest{Lane: start.Lane, Level: start.Level, Role: start.Role, Task: start.Task,
					Driver: start.Driver, ProfileGrantID: start.ProfileGrantID, Model: start.Model, Effort: start.Effort,
					Budget: start.Budget, Grants: start.Grants, ExpectedPolicyGeneration: 1, ImportManifest: inputs.RecordInventory}
				request, call = q, func(scope api.Scope) (any, error) { return f.service.LaneAdopt(context.Background(), scope, q) }
			case "lane.check":
				request, want = f.target, f.launcher.observation
				call = func(scope api.Scope) (any, error) { return f.service.LaneCheck(context.Background(), scope, f.target) }
			case "lane.review":
				q := api.ReviewRequest{Target: f.target, Diff: inputs.Diff, Checks: inputs.Checks,
					RecordInventory: inputs.RecordInventory, RefusalResolution: []api.ID{}}
				request, want = q, inputs
				call = func(scope api.Scope) (any, error) { return f.service.LaneReview(context.Background(), scope, q) }
			case "lane.archive":
				q := api.ArchiveRequest{Target: f.target, ExpectedGeneration: 1}
				digest := digestOf([]byte("archive"))
				request, want = q, api.ArchiveReceipt{ID: "archive", LifeID: f.target.LifeID, StoreID: "store",
					Manifest: inputs.RecordInventory, ArchiveSHA256: digest, ReadBackSHA256: digest, VerifiedAt: "2030-01-02T03:04:05Z"}
				call = func(scope api.Scope) (any, error) { return f.service.LaneArchive(context.Background(), scope, q) }
			case "lane.loop":
				q := api.LoopRequest{Target: f.target, ExpectedGeneration: 1, BackoffMS: 100}
				request, call = q, func(scope api.Scope) (any, error) { return f.service.LaneLoop(context.Background(), scope, q) }
			case "lane.input":
				q := api.AttachInputRequest{Target: f.target, ChannelID: "input-channel", Input: []byte("data")}
				request, call = q, func(scope api.Scope) (any, error) { return f.service.LaneInput(context.Background(), scope, q) }
			}
			scope := f.scope(method, request, f.parent)
			fixtureRetainedReply(f, scope, want)
			lane := f.store.lanes[f.target.LifeID]
			lane.Run, lane.Generation = lane.Run+1, lane.Generation+1
			lane.State, lane.Cleaned = "merged", true
			f.store.lanes[lane.LifeID] = lane
			f.launcher.available = false
			got, err := call(scope)
			if err != nil || !reflect.DeepEqual(got, want) || f.store.lookupCalls == 0 || f.store.dispatchCalls != 0 ||
				len(f.store.transactions) != 0 || f.launcher.observed.Load() != 0 {
				t.Fatalf("retained reply was replaced by changed preflight state: %v", err)
			}
		})
	}
}

func TestInteractiveSerializes(t *testing.T) {
	for _, method := range []api.Method{"lane.loop", "lane.input"} {
		t.Run(strings.TrimPrefix(string(method), "lane."), func(t *testing.T) {
			f := newFixture(t)
			unlock, err := f.service.lockLife(context.Background(), f.target.LifeID)
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if method == "lane.loop" {
				q := api.LoopRequest{Target: f.target, ExpectedGeneration: 1, BackoffMS: 100}
				_, err = f.service.LaneLoop(ctx, f.scope(method, q, f.parent), q)
			} else {
				q := api.AttachInputRequest{Target: f.target, ChannelID: "input-channel", Input: []byte("data")}
				_, err = f.service.LaneInput(ctx, f.scope(method, q, f.parent), q)
			}
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeDeadline || f.store.laneReads != 0 || len(f.store.transactions) != 0 {
				t.Fatalf("interactive mutation escaped per-life serialization: %v", err)
			}
		})
	}
}

func TestProfileLimits(t *testing.T) {
	for _, mode := range []string{"paid-fallback", "no-spend", "expired", "bad-expiry", "paid-allowed"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			request := fixtureContinuation(f)
			grants := f.store.grants[f.child.GrantSetID]
			switch mode {
			case "paid-fallback":
				grants.Profiles[1].Paid = true
				lane := f.store.lanes[f.target.LifeID]
				lane.BudgetRemaining.SpendMicros = 100
				f.store.lanes[lane.LifeID] = lane
			case "no-spend", "paid-allowed":
				grants.Profiles[0].Paid, grants.Profiles[1].Paid = true, true
				if mode == "paid-allowed" {
					lane := f.store.lanes[f.target.LifeID]
					lane.BudgetRemaining.SpendMicros = 100
					f.store.lanes[lane.LifeID] = lane
				}
			case "expired":
				grants.Profiles[1].ExpiresAt = "2029-01-01T00:00:00Z"
			case "bad-expiry":
				grants.Profiles[1].ExpiresAt = "invalid"
			}
			f.store.grants[grants.ID] = grants
			scope := api.Scope{Config: "example", Actor: api.Actor{Kind: "watchdog", ID: "watchdog"},
				Source: "watchdog", PolicyGeneration: f.store.policy.Generation}
			_, err := f.service.Continue(context.Background(), scope, request)
			if mode == "paid-allowed" {
				if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeNotImplemented ||
					typed.Owner != "lb-v2-service" || !strings.Contains(typed.Message, "store.ReserveLaunch") {
					t.Fatalf("delegated paid profile did not reach the launch barrier: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeForbidden {
				t.Fatalf("profile continuation crossed its payment or expiry limit: %v", err)
			}
			if f.service.deps.Credentials.(*fixtureCredentials).acquired.Load() != 0 || len(f.store.transactions) != 0 {
				t.Fatal("profile preflight acquired a slot or committed a launch")
			}
		})
	}
}

func TestOptionalEmptyField(t *testing.T) {
	f := newFixture(t)
	request := fixtureStart(f)
	scope := f.prepareScope("lane.start", request, f.parent)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(scope.Request.Params, &fields); err != nil {
		t.Fatal(err)
	}
	fields["root_ticket_id"] = json.RawMessage(`""`)
	var err error
	scope.Request.Params, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request.RequestSHA256, err = api.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope = f.reserveScope(scope)
	if err := f.service.authorize(context.Background(), scope, "lane.start", request); err != nil ||
		len(f.identity.actors) != 1 || f.identity.actors[0] != f.parent {
		t.Fatalf("explicit empty optional field changed request meaning: %v", err)
	}
}

func TestInputCanonicalBase64(t *testing.T) {
	request := api.AttachInputRequest{Target: api.LifeRef{LifeID: "child", Run: 1}, ChannelID: "input", Input: []byte("x")}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded api.AttachInputRequest
	if err := DecodeRequest(raw, &decoded); err != nil || !reflect.DeepEqual(decoded, request) {
		t.Fatalf("canonical input was not retained: %v", err)
	}
	for _, spelling := range []string{"eB==", `eA==\n`} {
		altered := strings.Replace(string(raw), "eA==", spelling, 1)
		if altered == string(raw) {
			t.Fatal("base64 fixture did not change its input")
		}
		if typed, ok := DecodeRequest([]byte(altered), &decoded).(*api.Error); !ok || typed.Code != api.CodeInvalid {
			t.Fatalf("noncanonical base64 changed retained input bytes: %v", typed)
		}
	}
}

func TestMergedCancelsOldIntent(t *testing.T) {
	f := newFixture(t)
	f.ended()
	review := fixtureReview(f)
	f.add("lane.reviewed", review, f.target.Run, "service", f.parent)
	lane := f.store.lanes[f.target.LifeID]
	lane.State, lane.Generation, lane.CancellationEpoch = "accepted", lane.Generation+1, 7
	f.store.lanes[lane.LifeID] = lane
	request := api.MarkRequest{Target: f.target, ExpectedGeneration: lane.Generation, State: "merged", Review: review}
	_, err := f.service.LaneMark(context.Background(), f.scope("lane.mark", request, f.parent), request)
	if err != nil {
		t.Fatal(err)
	}
	current := f.store.lanes[lane.LifeID]
	if current.State != "merged" || current.CancellationEpoch != lane.CancellationEpoch+1 ||
		len(f.store.transactions) != 1 || len(f.store.transactions[0].Writes.Lanes) != 1 {
		t.Fatal("merged state retained the old continuation epoch")
	}
}

func TestNewWritesInvalidate(t *testing.T) {
	for _, mode := range []string{"prompt", "data", "lost"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			end := f.ended()
			review := fixtureReview(f)
			f.add("lane.reviewed", review, f.target.Run, "service", f.parent)
			digest := digestOf([]byte("archive bytes"))
			archive := api.ArchiveReceipt{ID: "archive", LifeID: f.target.LifeID, StoreID: "store",
				Manifest:      fixtureArchiveManifest(f, "archive-manifest"),
				ArchiveSHA256: digest, ReadBackSHA256: digest, VerifiedAt: "2030-01-02T03:04:05Z"}
			f.add("archive.verified", archive, f.target.Run, "service", f.parent)
			switch mode {
			case "prompt":
				f.add("prompt.observed", api.TurnEvent{Task: f.child.Task,
					Trigger: api.Trigger{Kind: "idle", MailIDs: []api.ID{}, CausingSeqs: []api.Sequence{}},
					Prompt:  f.blob("prompt", "prompt", []byte("new prompt\n")), Status: "written", MailIDs: []api.ID{}},
					f.target.Run, "service", f.parent)
			case "data":
				f.add("data.materialized", api.Materialization{GrantSetID: f.child.GrantSetID,
					Manifest: f.blob("new-materialization", "manifest", []byte("new data\n")), Objects: []api.MaterializedObject{}},
					f.target.Run, "service", f.parent)
			case "lost":
				observation := f.launcher.observation
				observation.State, observation.Survivors, observation.ExitCode = "unknown", nil, nil
				f.add("lane.lost", api.RunEndEvent{LaunchID: f.child.LaunchID, Reason: "service_lost",
					Observation: observation, BudgetRemaining: f.budget}, f.target.Run, "service", f.parent)
			}
			request := api.MarkRequest{Target: f.target, ExpectedGeneration: 1, State: "accepted", Review: review}
			scope := f.scope("lane.mark", request, f.parent)
			err := f.service.storedReview(context.Background(), scope, f.child, f.target, review, end.Seq)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeForbidden {
				t.Fatalf("new run evidence reused a stale review: %v", err)
			}
			clean := api.CleanRequest{Target: f.target, ExpectedGeneration: 1, ArchiveReceiptID: archive.ID}
			_, err = f.service.archiveReceipt(context.Background(), f.scope("lane.clean", clean, f.parent), f.child, clean, end.Seq)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("new run evidence reused a stale archive: %v", err)
			}
		})
	}
}
