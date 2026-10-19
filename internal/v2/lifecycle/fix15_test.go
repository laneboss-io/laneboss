package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPlannerScopePolicy(t *testing.T) {
	for _, generation := range []api.Generation{0, 2} {
		f := newLaunchFixture(t)
		_, record := f.reserve(t)
		scope, request := f.claim(t, record)
		scope.PolicyGeneration = generation
		_, err := f.service.PlanLaunch(context.Background(), scope, request)
		if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || f.ports.calls["grants"] != 0 || f.ports.calls["allocate"] != 0 {
			t.Fatalf("unopened planner ignored authenticated policy: %v", err)
		}
	}
}

func TestFreshReservedGrantPolicy(t *testing.T) {
	for _, mode := range []string{"resume", "turn", "continue"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, lane := f.endedPlan(t)
			old := launchClone(t, f.store.grants[lane.GrantSetID])
			advanceFixturePolicy(f.fixture)
			control := api.Scope{Config: "example", Actor: f.parent, PolicyGeneration: f.store.policy.Generation}
			var err error
			lane, err = f.service.refreshLaunchPolicy(context.Background(), control, lane)
			if err != nil {
				t.Fatal(err)
			}
			message := f.fixture.blob(launchIDForTest(), "task", []byte("fresh policy work"))
			target := api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}
			var operation api.Operation
			switch mode {
			case "resume":
				request := api.ResumeRequest{Target: target, ExpectedGeneration: lane.Generation, Message: message, Budget: lane.BudgetRemaining}
				operation, err = f.service.LaneResume(context.Background(), f.fixture.scope("lane.resume", request, f.parent), request)
			case "turn":
				request := api.TurnRequest{Target: target, ExpectedGeneration: lane.Generation, IdleMessage: &message, MailIDs: []api.ID{}, Budget: lane.BudgetRemaining}
				operation, err = f.service.LaneTurn(context.Background(), f.fixture.scope("lane.turn", request, f.parent), request)
			case "continue":
				scope, request, _ := f.continuation(t, lane)
				operation, err = f.service.Continue(context.Background(), scope, request)
			}
			if err != nil {
				t.Fatal(err)
			}
			var record api.LaunchPlanRecord
			for _, candidate := range f.store.plans {
				if candidate.Reservation.OperationID == operation.ID {
					record = candidate
				}
			}
			before := f.ports.calls["allocate"]
			f.ports.grantHook = func(grants *api.GrantSet) { grants.PolicyGeneration = old.PolicyGeneration }
			scope, request := f.claim(t, record)
			_, err = f.service.PlanLaunch(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.ports.calls["allocate"] != before ||
				!reflect.DeepEqual(f.store.grants[old.ID], old) || f.store.plans[record.Reservation.ID].Phase != "reserved" {
				t.Fatalf("fresh launch used stale reserved grants or rewrote issuance: %s: %v", mode, err)
			}
		})
	}
}

func TestContinuationMissingRunner(t *testing.T) {
	f := newFixture(t)
	execution := &planExecution{service: f.service, record: api.LaunchPlanRecord{Reservation: api.LaunchReservation{Mode: "continue"}},
		input: launchInput{previous: &api.LaunchBindingRequest{Recovery: &api.LaunchRecovery{}}}}
	_, err := execution.prompt(context.Background(), api.LaunchInputs{})
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("missing retained runner did not return its integrity error: %v", err)
	}
}

func TestChildPolicyRefresh(t *testing.T) {
	f := newLaunchFixture(t)
	advanceFixturePolicy(f.fixture)
	f.request.ExpectedPolicyGeneration = f.store.policy.Generation
	f.scope = f.fixture.scope("lane.start", f.request, f.parent)
	operation, err := f.service.LaneStart(context.Background(), f.scope, f.request)
	parent := f.store.lanes[f.parent.LifeID]
	if err != nil || operation.Status != "pending" || parent.PolicyGeneration != f.store.policy.Generation || f.store.policyRefreshes != 1 {
		t.Fatalf("child policy was resolved before its current projection: %v", err)
	}
}

func TestPolicyProjectionGeneration(t *testing.T) {
	f := newFixture(t)
	f.store.briefingHook = func(_ api.Scope, input api.BriefingInput) api.BriefingInput {
		input.Policy.Generation++
		return input
	}
	actor := api.Actor{Kind: "lane", ID: "executor", LifeID: f.child.LifeID, Level: f.child.Level, Role: f.child.Role}
	_, err := f.service.policyForLane(context.Background(), f.scope("lane.status", f.target, actor), f.child)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("target policy accepted a different projection generation: %v", err)
	}
}

func TestStarterCurrentBinding(t *testing.T) {
	for _, mode := range []string{"kind", "actor", "run", "launch", "ancestry"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			starter := f.store.launches[f.scope.LaunchID]
			parent := f.store.lanes[f.parent.LifeID]
			switch mode {
			case "kind":
				starter.Kind = "worker"
			case "actor":
				starter.Actor.ID = "foreign-starter"
			case "run":
				parent.Run++
			case "launch":
				parent.LaunchID = "replacement-launch"
			case "ancestry":
				parent.RootLifeID = "foreign-root"
			}
			f.store.launches[starter.ID], f.store.lanes[parent.LifeID] = starter, parent
			_, err := f.service.LaneStart(context.Background(), f.scope, f.request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeForbidden || f.store.reservationCalls != 0 {
				t.Fatalf("stale starter produced a child reservation: %s: %v", mode, err)
			}
		})
	}
}

func TestChildReservationStoredLevel(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	r := record.Reservation
	parent := f.store.lanes[f.parent.LifeID]
	if !childReservation(parent, r) {
		t.Fatal("valid stored child reservation was rejected")
	}
	r.Level = parent.Level
	if childReservation(parent, r) {
		t.Fatal("stored reservation level reached its current parent level")
	}
}

func TestPlannerStarterAncestry(t *testing.T) {
	for _, mode := range []string{"level", "root", "chain", "run", "launch"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			parent := f.store.lanes[f.parent.LifeID]
			switch mode {
			case "level":
				// Retain coherent request/reservation pins; the stored parent
				// relation, rather than a request comparison, must refuse.
				f.request.Level = parent.Level
				original := f.scope.Request
				params, err := json.Marshal(f.request)
				if err != nil {
					t.Fatal(err)
				}
				original.Params = params
				original.RequestSHA256, err = api.RequestDigest(original)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(original)
				if err != nil {
					t.Fatal(err)
				}
				r := &record.Reservation
				r.Level, r.RequestSHA256 = f.request.Level, original.RequestSHA256
				r.OriginalRequest = f.fixture.measuredBlob(r.OriginalRequest.ID, "launch_request", raw, r.OperationID, r.Target)
			case "root":
				record.Reservation.RootLifeID = "foreign-root"
				record.Reservation.StarterChain = []api.ID{"foreign-root", parent.LifeID}
			case "chain":
				record.Reservation.StarterChain = []api.ID{parent.RootLifeID, "unrelated", parent.LifeID}
			case "run":
				parent.Run++
			case "launch":
				parent.LaunchID = "replacement-launch"
			}
			f.store.lanes[parent.LifeID] = parent
			f.store.plans[record.Reservation.ID] = record
			scope, request := f.claim(t, record)
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err == nil || f.ports.calls["grants"] != 0 || f.ports.calls["allocate"] != 0 {
				t.Fatalf("planner accepted foreign starter ancestry: %s: %v", mode, err)
			}
		})
	}
}

func TestReserveLaunchOwnership(t *testing.T) {
	f := newLaunchFixture(t)
	retry := f.scope
	retry.Frame = &fixtureFrame{raw: append([]byte{}, f.scope.Frame.Bytes()...)}
	_, err := f.service.reservePublicLaunch(context.Background(), retry, "start", api.Lane{})
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.store.reservationCalls != 0 {
		t.Fatalf("foreign invocation reserved a public launch: %v", err)
	}
}

type reviewPrepareCounter struct {
	ReviewControl
	calls int
}

func (counter *reviewPrepareCounter) PrepareReview(context.Context, api.Scope, api.ReviewRequest, api.Generation, api.ID, api.Sequence) (api.ReviewVerifyRequest, error) {
	counter.calls++
	return api.ReviewVerifyRequest{}, api.NotImplemented(owner, "unprepared fixture review")
}

func TestReviewPreparationOwnership(t *testing.T) {
	f := newFixture(t)
	request := api.ReviewRequest{Target: f.target, Checks: []api.BlobRef{}, RefusalResolution: []api.ID{}}
	scope := f.scope("lane.review", request, f.parent)
	scope.Frame = &fixtureFrame{raw: append([]byte{}, scope.Frame.Bytes()...)}
	counter := &reviewPrepareCounter{}
	f.service.deps.ReviewControl = counter
	_, err := f.service.verifyReviewLease(context.Background(), scope, request, f.child, runFacts{}, api.ReviewSubject{})
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || counter.calls != 0 {
		t.Fatalf("foreign invocation prepared a review worker: %v", err)
	}
}

func TestNilContexts(t *testing.T) {
	service := newFixture(t).service
	for _, name := range []string{"LaneStart", "LaneAdopt", "LaneResume", "LaneTurn", "LaneStop", "LaneMark", "LaneReview", "LaneClean", "LaneArchive", "LaneCheck", "LaneLoop", "LaneInput", "LaneStatus", "LaneList", "LaneAttach", "EventTail", "Continue", "RevokeLaunch", "PlanLaunch"} {
		t.Run(name, func(t *testing.T) {
			method := reflect.ValueOf(service).MethodByName(name)
			results := method.Call([]reflect.Value{reflect.Zero(method.Type().In(0)), reflect.ValueOf(api.Scope{}), reflect.Zero(method.Type().In(2))})
			if typed, ok := results[len(results)-1].Interface().(*api.Error); !ok || typed == nil || typed.Code != api.CodeInvalid {
				t.Fatalf("nil context did not return its typed shape error: %s", name)
			}
		})
	}
	_, err := CapturePipe(nil, nil, 0, nil)
	requireCode(t, err, api.CodeInvalid)
	requireCode(t, RunInternal(nil, "example", nil), api.CodeInvalid)
	_, err = (&eventStream{}).Next(nil)
	requireCode(t, err, api.CodeInvalid)
}

func TestTypedNilFailures(t *testing.T) {
	var typed *api.Error
	err := failure(typed)
	if actual, ok := err.(*api.Error); !ok || actual == nil || actual.Code != api.CodeIntegrity || notFound(typed) {
		t.Fatal("typed nil dependency error became a successful result")
	}
	for _, field := range []string{"Store", "Identity", "Clock"} {
		f := newFixture(t)
		switch field {
		case "Store":
			f.service.deps.Store = (*fixtureStore)(nil)
		case "Identity":
			f.service.deps.Identity = (*fixtureIdentity)(nil)
		case "Clock":
			f.service.deps.Clock = (*fixtureClock)(nil)
		}
		if err := f.service.ready(); absent(err) {
			t.Fatalf("typed nil core dependency became ready: %s", field)
		}
	}
}

type effectReadCounter struct {
	api.StateStore
	calls int
}

func (counter *effectReadCounter) Effect(context.Context, api.Scope, api.ID) (api.EffectRecord, error) {
	counter.calls++
	return api.EffectRecord{}, api.NotImplemented(owner, "fixture effect read")
}

func TestRevocationEmptyLease(t *testing.T) {
	f := newFixture(t)
	counter := &effectReadCounter{StateStore: f.store}
	f.service.deps.Store = counter
	err := f.service.RevokeLaunch(context.Background(), api.Scope{Config: "example", Actor: api.Actor{Kind: "service", ID: "lifecycle"}}, api.EffectLease{})
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeForbidden || counter.calls != 0 {
		t.Fatalf("empty revocation lease reached the store: %v", err)
	}
}

func TestCompletedLaunchUnassignedEnvelope(t *testing.T) {
	f := newLaunchFixture(t)
	operation, _ := f.reserve(t)
	key := api.RequestKey{Method: f.scope.Request.Method, IdempotencyKey: f.scope.Request.IdempotencyKey, RequestSHA256: f.scope.Request.RequestSHA256}
	domain := fixtureReceiptKey(f.scope, key)
	receipt := f.store.receipts[domain]
	receipt.Operation.LifeID, receipt.Operation.Run = "", 0
	f.store.receipts[domain] = receipt
	replayed, err := f.service.LaneStart(context.Background(), f.scope, f.request)
	if err != nil || !reflect.DeepEqual(replayed, operation) || f.store.reservationCalls != 1 {
		t.Fatalf("completed launch replay depended on unassigned envelope target: %v", err)
	}
}

func TestCompletedReceiptActorMetadata(t *testing.T) {
	f := newLaunchFixture(t)
	f.reserve(t)
	key := api.RequestKey{Method: f.scope.Request.Method, IdempotencyKey: f.scope.Request.IdempotencyKey, RequestSHA256: f.scope.Request.RequestSHA256}
	domain := fixtureReceiptKey(f.scope, key)
	receipt := f.store.receipts[domain]
	receipt.Actor.Role = "foreign-role"
	f.store.receipts[domain] = receipt
	_, err := f.service.LaneStart(context.Background(), f.scope, f.request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("foreign receipt actor metadata lost its integrity error: %v", err)
	}
}

func TestCompletedReplyTarget(t *testing.T) {
	for _, method := range []api.Method{"lane.archive", "lane.input", "lane.resume"} {
		t.Run(string(method)[5:], func(t *testing.T) {
			f := newFixture(t)
			var request, result any
			var call func(api.Scope) error
			switch method {
			case "lane.archive":
				value := api.ArchiveRequest{Target: f.target, ExpectedGeneration: f.child.Generation}
				wrong := fixtureArchive(f)
				wrong.LifeID = "foreign-life"
				request, result = value, wrong
				call = func(scope api.Scope) error {
					_, err := f.service.LaneArchive(context.Background(), scope, value)
					return err
				}
			case "lane.input":
				value := api.AttachInputRequest{Target: f.target, ChannelID: "channel", Input: []byte("x")}
				request, result = value, api.Operation{ID: "retained-operation", LifeID: "foreign-life", Run: f.target.Run, Status: "succeeded"}
				call = func(scope api.Scope) error {
					_, err := f.service.LaneInput(context.Background(), scope, value)
					return err
				}
			case "lane.resume":
				value := api.ResumeRequest{Target: f.target, ExpectedGeneration: f.child.Generation, Budget: f.budget,
					Message: f.blob("message", "task", []byte("resume"))}
				request, result = value, api.Operation{ID: "retained-operation", LifeID: "foreign-life", Run: f.target.Run + 1, Status: "pending"}
				call = func(scope api.Scope) error {
					_, err := f.service.LaneResume(context.Background(), scope, value)
					return err
				}
			}
			scope := f.scope(method, request, f.parent)
			fixtureRetainedReply(f, scope, result)
			if typed, ok := call(scope).(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("completed reply accepted another requested life: %s: %v", method, typed)
			}
		})
	}
}

func TestCleanCommitsEffect(t *testing.T) {
	f := newFixture(t)
	f.ended()
	f.add("archive.verified", fixtureArchive(f), f.target.Run, "service", f.parent)
	lane := f.child
	lane.State = "abandoned"
	f.store.lanes[lane.LifeID] = lane
	request := api.CleanRequest{Target: f.target, ExpectedGeneration: lane.Generation, ArchiveReceiptID: "archive"}
	scope := f.scope("lane.clean", request, f.parent)
	operation, err := f.service.LaneClean(context.Background(), scope, request)
	if err != nil || operation.Status != "pending" || len(f.store.transactions) != 1 {
		t.Fatalf("clean did not retain its pending collector effect: %v", err)
	}
	tx := f.store.transactions[0]
	if len(tx.Effects) != 1 || tx.Effects[0].Clean == nil || *tx.Effects[0].Clean != request || tx.Effects[0].OperationID != operation.ID ||
		tx.Effects[0].Context == nil || tx.Effects[0].Context.RequestedBy != f.parent || tx.Effects[0].Context.Target != f.target ||
		f.store.lanes[lane.LifeID].Cleaned || f.launcher.stopped.Load() != 0 {
		t.Fatal("clean claimed removal before its owned collector completed")
	}
	prior := len(f.store.transactions)
	replayed, err := f.service.LaneClean(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(replayed, operation) || len(f.store.transactions) != prior {
		t.Fatalf("clean retry submitted another removal effect: %v", err)
	}
}
