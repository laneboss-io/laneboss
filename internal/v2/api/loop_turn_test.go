package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type schedulerFixture struct {
	identity InstalledScheduler
	err      error
	calls    int
}

func (s *schedulerFixture) VerifyScheduler(ctx context.Context) (InstalledScheduler, error) {
	s.calls++
	if err := ctx.Err(); err != nil {
		return InstalledScheduler{}, err
	}
	return s.identity, s.err
}
func schedulerSource() *schedulerFixture {
	return &schedulerFixture{identity: InstalledScheduler{Config: "demo", Actor: Actor{Kind: "scheduler", ID: "installed-scheduler"},
		CapabilityID: "scheduler-capability", CapabilityGeneration: 1, InstallationGeneration: 1, BootID: "boot-one", PolicyGeneration: 3,
		ExpiresAt: contractStamp(contractNow().Add(time.Minute))}}
}
func loopFixture(t *testing.T) (Scope, LaunchReservationRequest, LaunchReservation, *schedulerFixture) {
	t.Helper()
	source := schedulerSource()
	scope, err := BindSchedulerScope(context.Background(), source, contractNow())
	if err != nil {
		t.Fatal(err)
	}
	p := launchFixture(t)
	r := p.Reservation
	selector := LoopTurnSelector{Target: r.Target, SettingEventID: "loop-setting", SettingSeq: 6, SettingOperationID: "setting-operation",
		EndEventID: "causing-end", EndSeq: 5, ExpectedGeneration: 4, CancellationEpoch: 1, PreviousLaunchID: "previous-launch"}
	idle := launchFixtureBlob("idle-input", "task")
	zero := uint64(0)
	cause := LoopTurnCause{Schema: "laneboss.loop-turn.v2", Scheduler: source.identity, Selector: selector,
		ConfiguredBy: Actor{Kind: "human", ID: "configurator"},
		Setting:      LoopRequest{Target: selector.Target, ExpectedGeneration: 1, Enabled: true, IdleMessage: &idle, BackoffMS: 1000},
		End: RunEndEvent{LaunchID: selector.PreviousLaunchID, Reason: "exit", BudgetRemaining: p.Budget,
			Observation: ProcessObservation{Handle: ProcessHandle{ID: "previous-process", Target: selector.Target}, State: "exited",
				Survivors: &zero, ObservedAt: contractStamp(contractNow().Add(-2 * time.Second))}},
		GrantGeneration: 1, PreviousSession: p.Runner.Session, PreviousHome: p.Data.Home, BudgetRemaining: p.Budget,
		DueAt: contractStamp(contractNow().Add(-time.Second)), ReservedAt: contractStamp(contractNow()),
		ReservationID: r.ID, OperationID: r.OperationID, RequestID: r.RequestID, LaunchID: r.LaunchID, GrantSetID: r.GrantSetID,
		LogicalTurnID: "loop-turn", PreviousLogicalTurnID: "previous-turn", PlanEffectID: "loop-plan-effect"}
	r.Loop, r.Mode, r.Target.Run, r.BaseGeneration, r.Generation = &cause, "turn", 2, 4, 5
	r.PreviousLaunchID, r.RequestedBy = selector.PreviousLaunchID, source.identity.Actor
	r.Authority = LaunchAuthority{Kind: "scheduler", ID: source.identity.CapabilityID}
	sealLoop(t, &r)
	return scope, LaunchReservationRequest{Loop: &selector}, r, source
}
func sealLoop(t *testing.T, r *LaunchReservation) {
	t.Helper()
	raw, digest := launchFixtureHash(t, *r.Loop)
	r.OriginalRequest = BlobRef{ID: "loop-input-record", SHA256: digest, Bytes: int64(len(raw)), Class: "manifest"}
	r.RequestSHA256 = digest
}

func loopPlanFixture(t *testing.T) LaunchPlan {
	t.Helper()
	_, _, r, _ := loopFixture(t)
	p := launchFixture(t)
	r.Loop.PreviousSession.VendorID = "vendor-one"
	r.Loop.PreviousHome.Generation = 2
	sealLoop(t, &r)
	p.Reservation = r
	p.Inputs.Sources.ReservationID = r.ID
	p.Data.ReservationID, p.Data.Target, p.Data.Home = r.ID, r.Target, r.Loop.PreviousHome
	p.Injection.Target = r.Target
	p.Capture.ReservationID, p.Capture.Target, p.Capture.LaunchID = r.ID, r.Target, r.LaunchID
	p.Capture.OperationID, p.Capture.RequestID, p.Capture.RequestedBy = r.OperationID, r.RequestID, r.RequestedBy
	p.Runner.Session = r.Loop.PreviousSession
	p.Runner.Prompt = launchFixtureBlob("loop-prompt", "prompt")
	return p
}

func loopPlanTx(t *testing.T, phase string) Transaction {
	t.Helper()
	p := loopPlanFixture(t)
	r := p.Reservation
	binding := launchFixtureBinding(t, p)
	kind, effect := InternalLaunchPlan, r.Loop.PlanEffectID
	if phase == "bound" {
		kind, effect = InternalHelperPrepare, "loop-prepare-effect"
	} else if phase == "opened" {
		kind, effect = InternalHelperOpen, "loop-open-effect"
	}
	cause := InternalIntent{ID: "loop-intent", Kind: kind, Config: r.Config, Target: r.Target,
		Actor: Actor{Kind: "service", ID: "planner"}, RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID,
		CauseRequestID: r.RequestID, EffectID: effect, CancellationEpoch: r.CancellationEpoch, LogicalTurnID: r.Loop.LogicalTurnID}
	record := LaunchPlanRecord{Reservation: r, Generation: 4, Phase: phase, Inputs: &p.Inputs, Plan: &p}
	tx := Transaction{Scope: Scope{Config: r.Config, Actor: cause.Actor, PolicyGeneration: r.PolicyGeneration}, Internal: &cause,
		Writes: StateWrites{LaunchPlans: []LaunchPlanRecord{record}}, Compare: []Compare{{Kind: CompareLaunchPlan, ID: r.ID, Generation: 3}},
		Guards: []TransactionGuard{{Cancellation: &CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}
	if phase == "bound" || phase == "opened" {
		tx.Writes.LaunchPlans[0].Handoff = &binding.Recovery.Handoff
		tx = gatePolicyForTest(t, tx, r.PolicyGeneration)
	}
	if phase == "bound" {
		tx.Writes.IdentityBindings = []LaunchBindingRequest{binding}
		tx.Writes.Lanes = []Lane{{LifeID: r.Target.LifeID, Run: r.Target.Run, Generation: r.Generation, GrantSetID: r.GrantSetID,
			LaunchID: r.LaunchID, LogicalTurnID: r.Loop.LogicalTurnID, Level: r.Level, Role: r.Role, Session: p.Runner.Session}}
		tx.Compare = append(tx.Compare, Compare{Kind: CompareLane, ID: r.Target.LifeID, Generation: r.BaseGeneration})
	} else if phase == "opened" {
		tx.Events = []Event{loopEvent(t, r, "lane.turn")}
	}
	return tx
}

func TestLoopPlan(t *testing.T) {
	for _, fault := range []string{"budget", "grant", "root", "generation", "home", "history", "session", "vendor"} {
		t.Run(fault, func(t *testing.T) {
			p := loopPlanFixture(t)
			if err := ValidateLaunchPlan(p); err != nil {
				t.Fatal("valid loop plan was refused", err)
			}
			switch fault {
			case "budget":
				p.Budget.WallMS++
			case "grant":
				p.Inputs.Grants.Generation++
			case "root":
				p.Data.Home.RootID = "foreign-root"
			case "generation":
				p.Data.Home.Generation--
			case "home":
				p.Data.Home.Home.ID, p.Runner.Home.ID, p.Runner.Session.HomeID = "foreign-home", "foreign-home", "foreign-home"
			case "history":
				p.Data.Home.Home.HistoryID, p.Runner.Home.HistoryID, p.Runner.Session.HistoryID = "foreign-history", "foreign-history", "foreign-history"
			case "session":
				p.Runner.Session.ID = "foreign-session"
			case "vendor":
				p.Runner.Session.VendorID = "foreign-vendor"
			}
			contractCode(t, ValidateLaunchPlan(p), CodeInvalid, "loop plan escaped its retained cause")
			record := LaunchPlanRecord{Reservation: p.Reservation, Generation: 2, Phase: "planned", Inputs: &p.Inputs, Plan: &p}
			contractCode(t, ValidateLaunchPlanRecord(record), CodeInvalid, "loop record escaped its retained cause")
		})
	}
}

func TestLoopWrite(t *testing.T) {
	for _, fault := range []string{"plan_turn", "effect", "prepare_turn", "lane_turn", "open_turn"} {
		t.Run(fault, func(t *testing.T) {
			phase := "planned"
			if fault == "prepare_turn" || fault == "lane_turn" {
				phase = "bound"
			} else if fault == "open_turn" {
				phase = "opened"
			}
			tx := loopPlanTx(t, phase)
			if err := ValidateTransactionShape(tx); err != nil {
				t.Fatal("valid loop write was refused", err)
			}
			if fault == "effect" {
				tx.Internal.EffectID = "foreign-effect"
			} else if fault == "lane_turn" {
				tx.Writes.Lanes[0].LogicalTurnID = "foreign-turn"
			} else {
				tx.Internal.LogicalTurnID = "foreign-turn"
			}
			// Refresh only the real policy stamp so that it cannot mask this fence.
			if phase != "planned" {
				tx = gatePolicyForTest(t, tx, tx.Scope.PolicyGeneration)
			}
			contractCode(t, ValidateTransactionShape(tx), CodeInvalid, "loop write escaped its logical turn or effect")
		})
	}
}
func TestLoopRequest(t *testing.T) {
	for _, fault := range []string{"unbound", "operation", "continuation", "guard", "frame", "actor"} {
		t.Run(fault, func(t *testing.T) {
			scope, request, _, _ := loopFixture(t)
			if err := ValidateLaunchReservationRequest(scope, request); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "unbound":
				scope.scheduler = nil
			case "operation":
				request.OperationID = "borrowed-operation"
			case "continuation":
				request.ContinuationID = "borrowed-continuation"
			case "guard":
				request.Guards = []TransactionGuard{{Proof: &ProofUse{}}}
			case "frame":
				scope.Request = Request{Method: "lane.turn"}
			case "actor":
				scope.Actor.Kind = "service"
			}
			contractCode(t, ValidateLaunchReservationRequest(scope, request), CodeInvalid, "loop reservation authority was bypassed")
		})
	}
}

func TestSchedulerScope(t *testing.T) {
	for _, fault := range []string{"endpoint", "read", "authority", "source", "connection", "frame", "config", "actor", "actor_id", "life", "level", "role", "cap_id", "cap_gen", "install", "boot", "policy", "expiry"} {
		t.Run(fault, func(t *testing.T) {
			scope, request, _, _ := loopFixture(t)
			if err := ValidateLaunchReservationRequest(scope, request); err != nil {
				t.Fatal(err)
			}
			if err := CheckSchedulerScope(context.Background(), scope, contractNow()); err != nil {
				t.Fatal(err)
			}
			p := &scope.scheduler.identity
			switch fault {
			case "endpoint":
				scope.EndpointGeneration = 2
			case "read":
				scope.ReadView = struct{ ReadView }{}
			case "authority":
				scope.ReadAuthority = &ReadAuthority{}
			case "source":
				scope.Source = "human"
			case "connection":
				scope.Connection = struct{ ConnectionContext }{}
			case "frame":
				scope.Frame = struct{ FrameContext }{}
			case "config":
				p.Config, scope.Config = "../demo", "../demo"
			case "actor":
				p.Actor.Kind, scope.Actor.Kind = "human", "human"
			case "actor_id":
				p.Actor.ID, scope.Actor.ID = "", ""
			case "life":
				p.Actor.LifeID, scope.Actor.LifeID = "borrowed-life", "borrowed-life"
			case "level":
				p.Actor.Level, scope.Actor.Level = 6, 6
			case "role":
				p.Actor.Role, scope.Actor.Role = "supervisor", "supervisor"
			case "cap_id":
				p.CapabilityID = ""
			case "cap_gen":
				p.CapabilityGeneration = 0
			case "install":
				p.InstallationGeneration = 0
			case "boot":
				p.BootID = ""
			case "policy":
				p.PolicyGeneration, scope.PolicyGeneration = 0, 0
			case "expiry":
				p.ExpiresAt = "invalid"
			}
			contractCode(t, ValidateLaunchReservationRequest(scope, request), CodeInvalid, "contaminated scheduler scope was accepted")
			contractCode(t, CheckSchedulerScope(context.Background(), scope, contractNow()), CodeInvalid, "scheduler scope shape was not rechecked")
		})
	}
}

func TestLoopMetadata(t *testing.T) {
	for _, fault := range []string{"event", "launch", "operation", "reservation", "effect", "human_life", "human_level", "human_role", "lane_life", "lane_level", "lane_role", "handle", "version", "vendor", "workspace", "root", "directory"} {
		t.Run(fault, func(t *testing.T) {
			_, _, r, _ := loopFixture(t)
			c := *r.Loop
			if fault == "lane_life" || fault == "lane_level" || fault == "lane_role" {
				c.ConfiguredBy = Actor{Kind: "lane", ID: "configurator", LifeID: "configurator-life", Level: 5, Role: "supervisor"}
			}
			if fault == "vendor" {
				c.Selector.Target.Run = 2
				c.End.Observation.Handle.Target.Run = 2
				c.PreviousSession.VendorID = "vendor-one"
			}
			if err := ValidateLoopTurnCause(c); err != nil {
				t.Fatal("valid loop metadata was refused", err)
			}
			switch fault {
			case "event":
				c.Selector.EndEventID = c.Selector.SettingEventID
			case "launch":
				c.LaunchID = c.Selector.PreviousLaunchID
			case "operation":
				c.OperationID = c.Selector.SettingOperationID
			case "reservation":
				c.ReservationID = c.LaunchID
			case "effect":
				c.PlanEffectID = c.ReservationID
			case "human_life":
				c.ConfiguredBy.LifeID = "borrowed-life"
			case "human_level":
				c.ConfiguredBy.Level = 6
			case "human_role":
				c.ConfiguredBy.Role = "supervisor"
			case "lane_life":
				c.ConfiguredBy.LifeID = ""
			case "lane_level":
				c.ConfiguredBy.Level = 0
			case "lane_role":
				c.ConfiguredBy.Role = ""
			case "handle":
				c.End.Observation.Handle.ID = ""
			case "version":
				c.PreviousSession.VendorVersion = ""
			case "vendor":
				c.PreviousSession.VendorID = ""
			case "workspace":
				c.PreviousHome.Home.WorkspaceID = ""
			case "root":
				c.PreviousHome.RootID = c.PreviousHome.Home.WorkspaceID
			case "directory":
				c.PreviousHome.Home.VendorDirectory = "../../escape"
			}
			contractCode(t, ValidateLoopTurnCause(c), CodeInvalid, "loop metadata fence was bypassed")
		})
	}
}
func TestSchedulerIdentity(t *testing.T) {
	for _, fault := range []string{"actor", "expiry", "capability", "installation"} {
		t.Run(fault, func(t *testing.T) {
			p := schedulerSource().identity
			if err := ValidateInstalledScheduler(p, contractNow()); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "actor":
				p.Actor.Kind = "service"
			case "expiry":
				p.ExpiresAt = contractStamp(contractNow())
			case "capability":
				p.CapabilityGeneration = 0
			case "installation":
				p.InstallationGeneration = 0
			}
			contractCode(t, ValidateInstalledScheduler(p, contractNow()), CodeInvalid, "invalid scheduler identity was accepted")
		})
	}
}
func TestSchedulerFresh(t *testing.T) {
	for _, fault := range []string{"capability", "refusal", "expiry"} {
		t.Run(fault, func(t *testing.T) {
			scope, _, _, source := loopFixture(t)
			if err := CheckSchedulerScope(context.Background(), scope, contractNow()); err != nil || source.calls != 2 {
				t.Fatal("scheduler producer was not rechecked", err)
			}
			if fault != "refusal" {
				if fault == "capability" {
					source.identity.CapabilityGeneration++
				} else {
					source.identity.ExpiresAt = contractStamp(contractNow().Add(2 * time.Minute))
				}
				contractCode(t, CheckSchedulerScope(context.Background(), scope, contractNow()), CodeConflict, "stale scheduler capability was reused")
			} else {
				sentinel := &Error{Code: CodeForbidden, Owner: "lb-v2-identity", Message: "scheduler revoked"}
				source.err = sentinel
				if !errors.Is(CheckSchedulerScope(context.Background(), scope, contractNow()), sentinel) {
					t.Fatal("scheduler producer refusal was swallowed")
				}
			}
		})
	}
}
func TestLoopCause(t *testing.T) {
	for _, fault := range []string{"setting", "survivors", "due", "budget", "history", "turn", "ids", "grant", "lost", "configurator"} {
		t.Run(fault, func(t *testing.T) {
			_, _, r, _ := loopFixture(t)
			c := *r.Loop
			if err := ValidateLoopTurnCause(c); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "setting":
				c.Setting.Enabled = false
			case "survivors":
				one := uint64(1)
				c.End.Observation.Survivors = &one
			case "due":
				c.ReservedAt = c.End.Observation.ObservedAt
			case "budget":
				c.BudgetRemaining.WallMS++
			case "history":
				c.PreviousSession.HistoryID = "foreign-history"
			case "turn":
				c.LogicalTurnID = c.PreviousLogicalTurnID
			case "ids":
				c.PlanEffectID = ""
			case "grant":
				c.GrantGeneration = 0
			case "lost":
				c.End.Reason = "service_lost"
			case "configurator":
				c.ConfiguredBy = c.Scheduler.Actor
			}
			contractCode(t, ValidateLoopTurnCause(c), CodeInvalid, "loop turn causal fence was bypassed")
		})
	}
}
func TestLoopRecord(t *testing.T) {
	for _, fault := range []string{"digest", "authority", "requester", "target"} {
		t.Run(fault, func(t *testing.T) {
			_, _, r, _ := loopFixture(t)
			if err := ValidateLaunchReservation(r); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "digest":
				r.RequestSHA256 = launchFixtureBlob("foreign-input", "manifest").SHA256
			case "authority":
				r.Authority.ID = "foreign-capability"
			case "requester":
				r.RequestedBy.ID = "foreign-scheduler"
			case "target":
				r.Target.Run++
			}
			contractCode(t, ValidateLaunchReservation(r), CodeInvalid, "loop reservation record was detached from its cause")
		})
	}
}
func TestLoopLegacy(t *testing.T) {
	_, _, r, _ := loopFixture(t)
	r.Loop = nil
	r.Authority = LaunchAuthority{Kind: "starter", ID: r.PreviousLaunchID}
	r.OriginalRequest = launchFixtureBlob("legacy-frame", "launch_request")
	r.RequestSHA256 = r.OriginalRequest.SHA256
	contractCode(t, ValidateLaunchReservation(r), CodeInvalid, "scheduler turn borrowed a manual reservation")
}
func loopEvent(t *testing.T, r LaunchReservation, kind EventKind) Event {
	t.Helper()
	var payload any = r.Loop
	if kind == "lane.turn" {
		payload = TurnEvent{Task: *r.Loop.Setting.IdleMessage, Prompt: launchFixtureBlob("loop-prompt", "prompt"), Status: "written",
			MailIDs: []ID{}, Trigger: Trigger{Kind: "loop", MailIDs: []ID{}, CausingRun: r.Loop.Selector.Target.Run,
				CausingSeqs: []Sequence{r.Loop.Selector.SettingSeq, r.Loop.Selector.EndSeq}}}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return Event{Schema: SchemaVersion, ID: "loop-event", Kind: kind, Config: r.Config, Actor: r.RequestedBy, RequestedBy: r.RequestedBy,
		OperationID: r.OperationID, RequestID: r.RequestID, LifeID: r.Target.LifeID, Run: r.Target.Run, LogicalTurnID: r.Loop.LogicalTurnID, Payload: raw}
}
func TestLoopEvent(t *testing.T) {
	_, _, r, _ := loopFixture(t)
	e := loopEvent(t, r, "loop.reserved")
	if err := ValidateLoopReservedEvent(e, r); err != nil {
		t.Fatal(err)
	}
	e.Actor = r.Loop.ConfiguredBy
	contractCode(t, ValidateLoopReservedEvent(e, r), CodeInvalid, "loop audit relabelled the scheduler")
}
func TestLoopAudit(t *testing.T) {
	for _, fault := range []string{"missing", "actor", "input", "cause"} {
		t.Run(fault, func(t *testing.T) {
			_, _, r, _ := loopFixture(t)
			e := loopEvent(t, r, "lane.turn")
			if err := ValidateLoopTurnEvent(e, r); err != nil {
				t.Fatal(err)
			}
			if fault == "missing" {
				p := loopPlanFixture(t)
				r = p.Reservation
				e = loopEvent(t, r, "lane.turn")
				tx := Transaction{Writes: StateWrites{LaunchPlans: []LaunchPlanRecord{{Reservation: r, Phase: "opened", Plan: &p}}}, Events: []Event{e}}
				if !validLoopTurnWrites(tx) {
					t.Fatal("valid loop audit was refused")
				}
				tx.Events = nil
				if validLoopTurnWrites(tx) {
					t.Fatal("opened loop omitted its launch audit")
				}
				return
			}
			var body TurnEvent
			if err := json.Unmarshal(e.Payload, &body); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "actor":
				e.Actor = r.Loop.ConfiguredBy
			case "input":
				body.Task = launchFixtureBlob("foreign-idle", "task")
			case "cause":
				body.Trigger.CausingSeqs[1]++
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			e.Payload = raw
			contractCode(t, ValidateLoopTurnEvent(e, r), CodeInvalid, "loop launch audit boundary was bypassed")
		})
	}
}

func TestLoopAuditPins(t *testing.T) {
	for _, fault := range []string{"mail", "trigger_mail", "run", "zero_run", "prompt", "legacy", "nil_plan"} {
		t.Run(fault, func(t *testing.T) {
			tx := loopPlanTx(t, "opened")
			if err := ValidateTransactionShape(tx); err != nil {
				t.Fatal("valid opened loop was refused", err)
			}
			var body TurnEvent
			if err := json.Unmarshal(tx.Events[0].Payload, &body); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "mail":
				body.MailIDs = []ID{"unselected-mail"}
			case "trigger_mail":
				body.Trigger.MailIDs = []ID{"unselected-mail"}
			case "run":
				body.Trigger.CausingRun = 99
			case "zero_run":
				body.Trigger.CausingRun = 0
			case "prompt":
				body.Prompt = launchFixtureBlob("foreign-prompt", "prompt")
			case "legacy":
				body.Trigger.Kind = "idle"
			case "nil_plan":
				tx.Writes.LaunchPlans[0].Plan = nil
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			tx.Events[0].Payload = raw
			if fault != "prompt" && fault != "nil_plan" {
				contractCode(t, ValidateLoopTurnEvent(tx.Events[0], tx.Writes.LaunchPlans[0].Reservation), CodeInvalid, "loop event carried unselected mail or cause")
			}
			if validLoopTurnWrites(tx) {
				t.Fatal("loop audit lost its retained prompt or causal pins")
			}
		})
	}
}

func TestLoopForged(t *testing.T) {
	for _, emitter := range []string{"public", "open", "empty"} {
		for _, fault := range []string{"actor", "requester", "trigger"} {
			t.Run(emitter+"_"+fault, func(t *testing.T) {
				var tx Transaction
				if emitter == "public" {
					tx = catalogTransaction(t, "lane.turn")
				} else {
					tx = gateTransaction(t, InternalHelperOpen)
					if emitter == "empty" {
						tx.Writes = StateWrites{}
						tx.Internal.Kind = InternalLifecycleEffect
					}
					if emitter == "open" {
						tx = gatePolicyForTest(t, tx, tx.Scope.PolicyGeneration)
					}
				}
				_, _, r, _ := loopFixture(t)
				e := loopEvent(t, r, "lane.turn")
				if tx.Internal != nil {
					e.LifeID, e.Run = tx.Internal.Target.LifeID, tx.Internal.Target.Run
				} else {
					e.LifeID, e.Run = tx.Scope.Actor.LifeID, 1
				}
				e.Actor, e.RequestedBy = Actor{Kind: "human", ID: "human-one"}, Actor{Kind: "human", ID: "human-one"}
				var body TurnEvent
				if err := json.Unmarshal(e.Payload, &body); err != nil {
					t.Fatal(err)
				}
				body.Trigger.Kind = "manual"
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				e.Payload = raw
				tx.Events = []Event{e}
				if err := ValidateTransactionShape(tx); err != nil {
					t.Fatal("ordinary turn was refused", err)
				}
				switch fault {
				case "actor":
					tx.Events[0].Actor = r.RequestedBy
				case "requester":
					tx.Events[0].RequestedBy = r.RequestedBy
				case "trigger":
					body.Trigger.Kind = "loop"
					raw, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					tx.Events[0].Payload = raw
				}
				contractCode(t, ValidateTransactionShape(tx), CodeInvalid, "unreserved scheduler turn was accepted")
			})
		}
	}
}
