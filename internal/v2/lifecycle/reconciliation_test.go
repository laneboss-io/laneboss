package lifecycle

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func fixtureActiveRun(f *fixture) {
	f.t.Helper()
	lane := f.store.lanes[f.target.LifeID]
	lane.State = "running"
	f.store.lanes[lane.LifeID] = lane
	f.add("identity.bound", f.store.launches[lane.LaunchID], lane.Run, "service", f.parent)
	live := f.launcher.observation
	one := uint64(1)
	live.State, live.Survivors, live.ExitCode = "running", &one, nil
	live.PromptStatus = "written"
	f.add("run.observed", live, lane.Run, "service", f.parent)
}

func TestCheckNaturalExit(t *testing.T) {
	for _, outcome := range []string{"exit", "failure", "signal"} {
		t.Run(outcome, func(t *testing.T) {
			f := newFixture(t)
			fixtureActiveRun(f)
			lane := f.store.lanes[f.target.LifeID]
			lane.CancellationEpoch = 4
			lane.BudgetRemaining.WallMS /= 2
			f.store.lanes[lane.LifeID] = lane
			if outcome == "failure" {
				exit := 7
				f.launcher.observation.ExitCode = &exit
			} else if outcome == "signal" {
				signal := 15
				f.launcher.observation.ExitCode, f.launcher.observation.Signal = nil, &signal
			}
			since := f.store.seq
			scope := f.scope("lane.check", f.target, f.parent)
			observed, err := f.service.LaneCheck(context.Background(), scope, f.target)
			if err != nil || !reflect.DeepEqual(observed, f.launcher.observation) {
				t.Fatalf("terminal check did not return its actual observation: %v", err)
			}
			if len(f.store.transactions) != 1 {
				t.Fatal("check did not atomically end the natural run")
			}
			tx := f.store.transactions[0]
			if len(tx.Events) != 3 || tx.Events[0].Kind != "run.observed" ||
				tx.Events[1].Kind != "lane.ended" || tx.Events[2].Kind != "lane.state" || len(tx.Writes.Lanes) != 1 ||
				tx.Writes.Lanes[0].State != "verifying" || tx.Writes.Lanes[0].Generation != lane.Generation+1 {
				t.Fatal("check did not atomically end the natural run")
			}
			if !reflect.DeepEqual(tx.Compare, []api.Compare{{Kind: api.CompareLane,
				ID: lane.LifeID, Generation: lane.Generation}}) || len(tx.Guards) != 1 ||
				tx.Guards[0].Cancellation == nil || *tx.Guards[0].Cancellation !=
				(api.CancellationCheck{LifeID: lane.LifeID, Epoch: lane.CancellationEpoch}) {
				t.Fatal("natural end lost its generation or cancellation fence")
			}
			var end api.RunEndEvent
			if err := api.DecodeObject(tx.Events[1].Payload, &end); err != nil {
				t.Fatal(err)
			}
			if end.LaunchID != lane.LaunchID || end.Reason != "exit" || end.ProfileContinuation ||
				!reflect.DeepEqual(end.Observation, observed) || end.BudgetRemaining != lane.BudgetRemaining {
				t.Fatal("natural end lost its measured outcome or remaining budget")
			}
			var state api.StateEvent
			if api.DecodeObject(tx.Events[2].Payload, &state) != nil || state.From != lane.State || state.To != "verifying" || state.Generation != lane.Generation+1 {
				t.Fatal("natural end lost its explicit measured state event")
			}
			for _, event := range tx.Events {
				if event.OperationID == "" || event.OperationID != tx.Events[0].OperationID ||
					event.Actor.Kind != "service" || event.RequestedBy != f.parent ||
					event.ObservedAt != observed.ObservedAt {
					t.Fatal("natural end lost its causal observation or requester")
				}
			}
			query := api.EventTailRequest{LifeID: lane.LifeID, Run: lane.Run, Since: since, Until: "lane.ended"}
			page, err := f.service.EventTail(context.Background(), f.scope("event.tail", query, f.parent), query)
			if err != nil || len(page.Events) != 2 || page.Events[1].Kind != "lane.ended" || !page.Complete {
				t.Fatalf("natural committed end was not visible to its parent: %v", err)
			}
			before := f.launcher.observed.Load()
			replayed, err := f.service.LaneCheck(context.Background(), scope, f.target)
			if err != nil || !reflect.DeepEqual(replayed, observed) || len(f.store.transactions) != 1 ||
				f.launcher.observed.Load() != before {
				t.Fatalf("natural-end retry repeated observation or commit: %v", err)
			}
		})
	}
}

func TestCheckEndIsStable(t *testing.T) {
	f := newFixture(t)
	f.ended()
	lane := f.store.lanes[f.target.LifeID]
	lane.State, lane.Generation = "accepted", 5
	f.store.lanes[lane.LifeID] = lane
	_, err := f.service.LaneCheck(context.Background(), f.scope("lane.check", f.target, f.parent), f.target)
	if err != nil {
		t.Fatal(err)
	}
	tx := f.store.transactions[0]
	if len(tx.Events) != 1 || tx.Events[0].Kind != "run.observed" || len(tx.Writes.Lanes) != 0 ||
		f.store.lanes[lane.LifeID].State != lane.State || f.store.lanes[lane.LifeID].Generation != lane.Generation {
		t.Fatal("check repeated a committed end or reset a reviewed state")
	}
}

func TestCheckSurvivorsRefuse(t *testing.T) {
	f := newFixture(t)
	fixtureActiveRun(f)
	survivors := uint64(3)
	f.launcher.observation.Survivors = &survivors
	_, err := f.service.LaneCheck(context.Background(), f.scope("lane.check", f.target, f.parent), f.target)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict ||
		len(f.store.transactions) != 0 || f.store.lanes[f.target.LifeID].State != "running" {
		t.Fatalf("check recorded an end while survivors existed: %v", err)
	}
}

func TestCheckRunningIsObservation(t *testing.T) {
	f := newFixture(t)
	fixtureActiveRun(f)
	live := f.launcher.observation
	one := uint64(1)
	live.State, live.Survivors, live.ExitCode = "running", &one, nil
	f.launcher.observation = live
	result, err := f.service.LaneCheck(context.Background(), f.scope("lane.check", f.target, f.parent), f.target)
	if err != nil || !reflect.DeepEqual(result, live) {
		t.Fatalf("live check lost its actual observation: %v", err)
	}
	tx := f.store.transactions[0]
	if len(tx.Events) != 1 || tx.Events[0].Kind != "run.observed" || len(tx.Writes.Lanes) != 0 ||
		f.store.lanes[f.target.LifeID].State != "running" {
		t.Fatal("live observation became a terminal state")
	}
}

func TestCheckEndCommitFailure(t *testing.T) {
	for _, mode := range []string{"store", "generation"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			fixtureActiveRun(f)
			want := api.CodeConflict
			if mode == "store" {
				f.store.transactErr = &api.Error{Code: want, Message: "fixture concurrent change"}
			} else {
				lane := f.store.lanes[f.target.LifeID]
				lane.Generation = api.Generation(maxInteger)
				f.store.lanes[lane.LifeID] = lane
				want = api.CodeIntegrity
			}
			before, seq := f.store.lanes[f.target.LifeID], f.store.seq
			_, err := f.service.LaneCheck(context.Background(), f.scope("lane.check", f.target, f.parent), f.target)
			if typed, ok := err.(*api.Error); !ok || typed.Code != want ||
				len(f.store.transactions) != 0 || f.store.seq != seq ||
				!reflect.DeepEqual(f.store.lanes[f.target.LifeID], before) {
				t.Fatalf("failed natural-end commit changed authoritative state: %v", err)
			}
		})
	}
}

func TestParentGrantRevalidation(t *testing.T) {
	for _, mode := range []string{"valid", "stale", "zero", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			scope := f.scope("lane.check", f.target, f.parent)
			f.store.policy.Generation = scope.PolicyGeneration
			f.store.briefingHook = func(api.Scope, api.BriefingInput) api.BriefingInput {
				t.Fatal("parent grant preflight queried a child briefing")
				return api.BriefingInput{}
			}
			switch mode {
			case "stale":
				scope.PolicyGeneration++
			case "zero":
				scope.PolicyGeneration = 0
			case "overflow":
				scope.PolicyGeneration = api.Generation(maxInteger + 1)
			}
			grants, err := f.service.revalidate(context.Background(), scope, f.child)
			if mode == "valid" {
				if err != nil || !reflect.DeepEqual(grants, f.store.grants[f.child.GrantSetID]) {
					t.Fatalf("parent grant preflight could not use authenticated policy: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict {
				t.Fatalf("continuation ignored authenticated policy generation: %v", err)
			}
		})
	}
}

func TestParentControlPreflight(t *testing.T) {
	for _, method := range []api.Method{"lane.resume", "lane.turn"} {
		t.Run(strings.TrimPrefix(string(method), "lane."), func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			message := f.blob("follow-up", "task", []byte("parent continuation input\n"))
			delete(f.store.blobs, message.ID)
			call := func(actor api.Actor) error {
				if method == "lane.resume" {
					request := api.ResumeRequest{Target: f.target, ExpectedGeneration: 1, Message: message, Budget: f.budget}
					_, err := f.service.LaneResume(context.Background(), f.scope(method, request, actor), request)
					return err
				}
				request := api.TurnRequest{Target: f.target, ExpectedGeneration: 1,
					MailIDs: []api.ID{}, IdleMessage: &message, Budget: f.budget}
				_, err := f.service.LaneTurn(context.Background(), f.scope(method, request, actor), request)
				return err
			}
			if typed, ok := call(f.parent).(*api.Error); !ok || typed.Code != api.CodeNotFound {
				t.Fatalf("parent continuation stopped before input read-back: %v", typed)
			}
			message = f.blob(message.ID, "task", []byte("parent continuation input\n"))
			if typed, ok := call(f.parent).(*api.Error); !ok || typed.Code != api.CodeNotImplemented ||
				typed.Owner != "lb-v2-service" || !strings.Contains(typed.Message, "store.ReserveLaunch") {
				t.Fatalf("parent continuation did not reach the shared launch barrier: %v", typed)
			}
			unrelated := api.Actor{Kind: "lane", ID: "unrelated-actor", LifeID: "unrelated", Level: 5, Role: "supervisor"}
			before := f.launcher.observed.Load()
			if typed, ok := call(unrelated).(*api.Error); !ok || typed.Code != api.CodeNotFound ||
				f.launcher.observed.Load() != before {
				t.Fatalf("non-descendant crossed the continuation boundary: %v", typed)
			}
			if len(f.identity.actors) != 3 || f.identity.actors[0] != f.parent ||
				f.identity.actors[1] != f.parent || f.identity.actors[2] != unrelated ||
				len(f.store.transactions) != 0 || f.launcher.prepared.Load() != 0 {
				t.Fatal("continuation relabelled its requester or crossed the launch barrier")
			}
		})
	}
}

func TestWorkerTreeVisibility(t *testing.T) {
	for _, relation := range []string{"own", "ancestor", "unrelated", "unbound"} {
		t.Run(relation, func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			worker := api.Actor{Kind: "worker", ID: "data-worker", LifeID: f.child.LifeID}
			count := 1
			switch relation {
			case "ancestor":
				worker.LifeID, count = f.parent.LifeID, 2
			case "unrelated":
				worker.LifeID, count = "unrelated", 0
			case "unbound":
				worker.LifeID, count = "", 0
			}
			lane, err := f.service.LaneStatus(context.Background(), f.scope("lane.status", f.target, worker), f.target)
			if count == 0 {
				if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeNotFound {
					t.Fatalf("worker escaped its starter tree: %v", err)
				}
			} else if err != nil || lane.LifeID != f.target.LifeID {
				t.Fatalf("worker lost its authentic tree: %v", err)
			}
			query := api.ListRequest{Limit: 100}
			page, err := f.service.LaneList(context.Background(), f.scope("lane.list", query, worker), query)
			if err != nil || len(page.Lanes) != count {
				t.Fatalf("worker list escaped its starter tree: %v", err)
			}
			selection := api.EventTailRequest{LifeID: f.target.LifeID, Run: f.target.Run}
			events, err := f.service.EventTail(context.Background(), f.scope("event.tail", selection, worker), selection)
			if count == 0 {
				if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeNotFound {
					t.Fatalf("worker event read escaped its starter tree: %v", err)
				}
			} else if err != nil || len(events.Events) != 1 || events.Events[0].Kind != "lane.ended" {
				t.Fatalf("worker lost its authorized events: %v", err)
			}
		})
	}
}

func TestReviewRequiresEnd(t *testing.T) {
	f := newFixture(t)
	fixtureActiveRun(f)
	lane := f.store.lanes[f.target.LifeID]
	lane.State = "verifying"
	f.store.lanes[lane.LifeID] = lane
	inputs := fixtureReview(f)
	request := api.ReviewRequest{Target: f.target, Diff: inputs.Diff, Checks: inputs.Checks,
		RecordInventory: inputs.RecordInventory, RefusalResolution: []api.ID{}}
	_, err := f.service.LaneReview(context.Background(), f.scope("lane.review", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || len(f.store.transactions) != 0 {
		t.Fatalf("review accepted evidence before a committed end: %v", err)
	}
}

func TestReviewInputReadBack(t *testing.T) {
	for _, mode := range []string{"diff", "check", "inventory", "denied", "digest"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			inputs := fixtureReview(f)
			want := api.CodeNotFound
			switch mode {
			case "diff":
				delete(f.store.blobs, inputs.Diff.ID)
			case "check":
				delete(f.store.blobs, inputs.Checks[0].ID)
			case "inventory":
				delete(f.store.blobs, inputs.RecordInventory.ID)
			case "denied":
				want = api.CodeForbidden
				f.store.blobHook = func(chunk api.BlobChunk) (api.BlobChunk, error) {
					if chunk.ObjectID == inputs.RecordInventory.ID {
						return api.BlobChunk{}, &api.Error{Code: want, Message: "fixture ACL refusal"}
					}
					return chunk, nil
				}
			case "digest":
				want = api.CodeIntegrity
				f.store.blobHook = func(chunk api.BlobChunk) (api.BlobChunk, error) {
					if chunk.ObjectID == inputs.Checks[0].ID {
						chunk.Data[0] ^= 1
						chunk.SHA256 = digestOf(chunk.Data)
					}
					return chunk, nil
				}
			}
			request := api.ReviewRequest{Target: f.target, Diff: inputs.Diff, Checks: inputs.Checks,
				RecordInventory: inputs.RecordInventory, RefusalResolution: []api.ID{}}
			_, err := f.service.LaneReview(context.Background(), f.scope("lane.review", request, f.parent), request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != want || len(f.store.transactions) != 0 {
				t.Fatalf("review skipped immutable evidence read-back: %v", err)
			}
		})
	}
}
