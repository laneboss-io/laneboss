package lifecycle

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestEffectVocabulary(t *testing.T) {
	for _, mode := range []string{"succeeded", "failed"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			if request.Lease.Record.State != api.EffectClaimed {
				t.Fatal("planner did not claim the shared effect state")
			}
			if mode == "failed" {
				f.ports.failStage, f.ports.failure = "allocate", api.NotImplemented("allocation-owner", "retained allocation failure")
			}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			child := f.store.effects[launchObjectID(record.Reservation.ID, "allocate-effect")]
			if mode == "succeeded" {
				if err != nil || child.State != api.EffectCompleted || child.Outcome == nil || child.Outcome.Status != mode {
					t.Fatalf("effect state did not follow its successful outcome: %v", err)
				}
			} else if err != f.ports.failure || child.State != api.EffectFailed || child.Outcome == nil || child.Outcome.Status != mode || child.Outcome.Error != f.ports.failure {
				t.Fatalf("effect state did not retain its failed outcome: %v", err)
			}
		})
	}
}

type completionStateStore struct{ *launchFixtureStore }

func (store completionStateStore) CompleteEffect(ctx context.Context, scope api.Scope, outcome api.EffectOutcome) (api.Commit, error) {
	commit, err := store.launchFixtureStore.CompleteEffect(ctx, scope, outcome)
	if err != nil {
		return api.Commit{}, err
	}
	record := store.effects[outcome.EffectID]
	record.State = api.EffectClaimed
	store.effects[outcome.EffectID] = record
	return commit, nil
}

func TestEffectCompleteState(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	f.service.deps.Store = completionStateStore{f.store}
	_, err := f.service.PlanLaunch(context.Background(), scope, request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.ports.calls["materialize-entry"] != 0 {
		t.Fatalf("launch crossed its effect completion state: %v", err)
	}
}

func TestEffectReceiptPins(t *testing.T) {
	for _, mode := range []string{"allocation", "claimed", "failed"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			plan, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			id := launchObjectID(record.Reservation.ID, "allocate-effect")
			child := f.store.effects[id]
			child.State = api.EffectClaimed
			if mode == "failed" {
				child.State = api.EffectFailed
			}
			f.store.effects[id] = child
			if mode == "allocation" {
				_, err = f.service.PlanLaunch(context.Background(), scope, request)
			} else {
				execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: f.store.plans[plan.Reservation.ID]}
				_, err = execution.childEffect(context.Background(), child.Effect)
			}
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("launch trusted a mismatched effect state and outcome: %s: %v", mode, err)
			}
		})
	}
}

func TestTurnIdentity(t *testing.T) {
	for _, mode := range []string{"valid", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			lane := f.child
			if mode == "missing" {
				lane.LogicalTurnID = ""
			}
			payload := api.TurnEvent{Task: lane.Task, Prompt: f.blob("turn-prompt", "prompt", []byte("actual turn input")),
				Trigger: api.Trigger{Kind: "idle", MailIDs: []api.ID{}, CausingSeqs: []api.Sequence{}}, MailIDs: []api.ID{}, Status: "not_written"}
			event, err := f.service.event(api.Scope{Config: "example", Actor: f.parent}, lane, "lane.turn", payload, f.parent)
			if mode == "valid" {
				if err != nil || event.LogicalTurnID != lane.LogicalTurnID || event.LifeID != lane.LifeID || event.Run != lane.Run {
					t.Fatalf("turn event lost its actual logical identity: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("turn event accepted an absent logical identity: %v", err)
			}
		})
	}
}

func preparedFixture(t *testing.T) (*launchFixture, api.Scope, api.LaunchPlanRequest, api.LaunchPlan) {
	t.Helper()
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	plan, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	f.bindPrepared(t, scope, request, plan)
	return f, scope, request, plan
}

func openFixtureTransaction(t *testing.T, f *launchFixture) api.Transaction {
	t.Helper()
	// This input deliberately starts unstamped. The writer must bind a new
	// current-policy fence for opening instead of reusing the prepare fence.
	tx := launchClone(t, f.store.transactions[len(f.store.transactions)-1])
	tx.Internal.Kind, tx.Internal.ID = api.InternalHelperOpen, launchIDForTest()
	record := tx.Writes.LaunchPlans[0]
	record.Phase, record.Generation = "opened", record.Generation+1
	tx.Writes.LaunchPlans[0] = record
	tx.Writes.Turns, tx.Events = nil, nil
	if loop := record.Reservation.Loop; loop != nil {
		lane := tx.Writes.Lanes[0]
		body := api.TurnEvent{Task: *loop.Setting.IdleMessage, Prompt: record.Plan.Runner.Prompt, Status: "written", MailIDs: []api.ID{},
			Trigger: api.Trigger{Kind: "loop", MailIDs: []api.ID{}, CausingRun: loop.Selector.Target.Run,
				CausingSeqs: []api.Sequence{loop.Selector.SettingSeq, loop.Selector.EndSeq}}}
		event, err := f.service.event(tx.Scope, lane, "lane.turn", body, record.Reservation.RequestedBy)
		if err != nil {
			t.Fatal(err)
		}
		event.Actor, event.RequestedBy = record.Reservation.RequestedBy, record.Reservation.RequestedBy
		event.OperationID, event.RequestID = record.Reservation.OperationID, record.Reservation.RequestID
		if err := api.ValidateLoopTurnEvent(event, record.Reservation); err != nil {
			t.Fatal(err)
		}
		tx.Events = []api.Event{event}
	}
	for i := range tx.Compare {
		if tx.Compare[i].Kind == api.CompareLaunchPlan {
			tx.Compare[i].Generation = record.Generation - 1
		}
		if tx.Compare[i].Kind == api.CompareLane {
			tx.Compare[i].Generation = tx.Writes.Lanes[0].Generation
		}
	}
	return tx
}

func TestWriterPolicy(t *testing.T) {
	for _, mode := range []string{"prepare", "open", "open-valid"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _, plan := preparedFixture(t)
			original := f.store.transactions[len(f.store.transactions)-1]
			if api.ValidateTransactionShape(original) != nil {
				t.Fatal("writer omitted its locked prepare policy binding")
			}
			tx := launchClone(t, original)
			if mode != "prepare" {
				tx = openFixtureTransaction(t, f)
			}
			if mode != "open-valid" {
				f.store.policy.Generation++
			}
			before, intentReads := len(f.store.transactions), f.store.intentReads
			_, err := f.store.Transact(context.Background(), tx)
			if mode == "open-valid" {
				if err != nil || f.store.plans[plan.Reservation.ID].Phase != "opened" || len(f.store.transactions) != before+1 {
					t.Fatalf("writer did not bind current policy before opening: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeInvalid ||
				f.store.intentReads != intentReads || len(f.store.transactions) != before || f.store.plans[plan.Reservation.ID].Phase != "bound" {
				t.Fatalf("writer crossed its current policy fence: %s: %v", mode, err)
			}
		})
	}
}

type projectionResponse struct {
	api.CredentialProjectionIdentity
	change func(*api.CredentialProjectionRecord)
}

func (source projectionResponse) CheckLaunchCredentials(ctx context.Context, binding api.LaunchBindingRequest) (api.CredentialProjectionRecord, error) {
	record, err := source.CredentialProjectionIdentity.CheckLaunchCredentials(ctx, binding)
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	source.change(&record)
	return record, nil
}

func TestProjectionRecovery(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "revoked", "home", "source", "gate", "store", "turn", "port", "owner", "opened", "opened-missing"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, request, plan := preparedFixture(t)
			if mode == "opened" || mode == "opened-missing" {
				if _, err := f.store.Transact(context.Background(), openFixtureTransaction(t, f)); err != nil {
					t.Fatal(err)
				}
			}
			var id api.ID
			for key := range f.store.projections {
				id = key
			}
			record := launchClone(t, f.store.projections[id])
			switch mode {
			case "missing", "opened-missing":
				delete(f.store.projections, id)
			case "revoked":
				record.Authority.Revoked = true
			case "home":
				record.Receipt.Home.RootID = "foreign-home"
			case "source":
				record.Authority.Sources[0].Revoked = true
			case "gate":
				record.Receipt.GateClosed = false
			case "turn":
				r := &record.Authority.Request
				r.Cause.LogicalTurnID = "foreign-turn"
				r.Claim.Record.Effect.Context = &r.Cause
				r.Claim.Record.Effect.HelperPrepare.Cause = r.Cause
				// Keep the store effect coherent so this existing control still
				// isolates the logical-turn comparison after prepare read-back.
				f.store.effects[r.Claim.Record.Effect.ID] = r.Claim.Record
			case "store":
				f.service.deps.CredentialIdentity = projectionResponse{CredentialProjectionIdentity: f.ports,
					change: func(r *api.CredentialProjectionRecord) { r.Authority.Broker.Version = "foreign-producer" }}
			case "port":
				f.service.deps.CredentialIdentity = nil
			case "owner":
				f.ports.failStage, f.ports.failure = "credential-check", api.NotImplemented("lb-v2-identity", "actual projection producer")
			}
			if mode != "missing" && mode != "opened-missing" {
				f.store.projections[id] = record
			}
			before := f.ports.calls["acquire"]
			got, err := f.service.PlanLaunch(context.Background(), scope, request)
			if mode == "valid" || mode == "opened" || mode == "port" {
				checks := 1
				if mode == "opened" || mode == "port" {
					checks = 0
				}
				if err != nil || !reflect.DeepEqual(got, plan) || f.ports.calls["credential-check"] != checks || f.ports.calls["acquire"] != before {
					t.Fatalf("recovery lost its retained credential projection: %v", err)
				}
				return
			}
			want := api.CodeIntegrity
			if mode == "missing" || mode == "opened-missing" {
				want = api.CodeNotFound
			}
			if mode == "owner" {
				want = api.CodeNotImplemented
			}
			if typed, ok := err.(*api.Error); !ok || typed.Code != want || f.ports.calls["acquire"] != before {
				t.Fatalf("recovery ignored its real credential projection: %s: %v", mode, err)
			}
			if mode == "owner" && err != f.ports.failure {
				t.Fatal("recovery hid its projection owner's error")
			}
		})
	}
}
