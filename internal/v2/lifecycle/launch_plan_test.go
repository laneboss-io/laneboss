package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestLaunchReservation(t *testing.T) {
	f := newLaunchFixture(t)
	operation, record := f.reserve(t)
	r := record.Reservation
	if operation.Status != "pending" || operation.ID != r.OperationID || operation.LifeID != r.Target.LifeID ||
		operation.Run != 1 || r.Target.LifeID == f.parent.LifeID || r.Target.LifeID == f.request.ProjectID ||
		r.RequestedBy != f.parent || r.ParentLifeID != f.parent.LifeID || r.OriginalRequest.Class != "launch_request" ||
		record.Phase != "reserved" || record.Plan != nil || len(f.store.effects) != 1 || f.store.awaitCalls != 0 {
		t.Fatal("launch did not hand off its fresh pending reservation")
	}
	key := api.RequestKey{Method: f.scope.Request.Method, IdempotencyKey: f.scope.Request.IdempotencyKey, RequestSHA256: f.scope.Request.RequestSHA256}
	receipt := f.store.receipts[fixtureReceiptKey(f.scope, key)]
	if !bytes.Equal(receipt.RawRequest, f.store.blobs[r.OriginalRequest.ID]) {
		t.Fatal("launch reservation did not retain the original request bytes")
	}
	// A retry returns the retained pending reply before changed preflight; it
	// cannot await its own dispatcher reservation or issue another life.
	f.launcher.available = false
	second, err := f.service.LaneStart(context.Background(), f.scope, f.request)
	if err != nil || !reflect.DeepEqual(second, operation) || f.store.reservationCalls != 1 || len(f.store.effects) != 1 {
		t.Fatalf("launch retry did not replay its retained pending operation: %v", err)
	}
	if _, exists := f.store.lanes[r.Target.LifeID]; exists || f.launcher.prepared.Load() != 0 || f.launcher.launched.Load() != 0 {
		t.Fatal("reservation fabricated a ready lane or released an agent")
	}
}

func TestLaunchForeignReservation(t *testing.T) {
	for _, field := range []string{"config", "mode", "operation", "request", "digest", "requester", "policy", "original", "parent"} {
		t.Run(field, func(t *testing.T) {
			f := newLaunchFixture(t)
			f.store.reservationHook = func(r *api.LaunchReservation) {
				switch field {
				case "config":
					r.Config = "foreign"
				case "mode":
					r.Mode = "adopt"
				case "operation":
					r.OperationID = "foreign-operation"
				case "request":
					r.RequestID = "foreign-request"
				case "digest":
					r.RequestSHA256 = digestOf([]byte("different input"))
				case "requester":
					r.RequestedBy.ID = "foreign-principal"
				case "policy":
					r.PolicyGeneration++
				case "original":
					r.OriginalRequest.SHA256 = digestOf([]byte("foreign-frame"))
				case "parent":
					r.ParentLifeID, r.RootLifeID, r.StarterChain = "foreign-parent", "foreign-parent", []api.ID{"foreign-parent"}
				}
			}
			_, err := f.service.LaneStart(context.Background(), f.scope, f.request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("public launch accepted a foreign reservation: %v", err)
			}
			if field == "parent" && err.(*api.Error).Message != "store returned an invalid launch reservation" {
				t.Fatal("foreign parent missed the shared reservation boundary")
			}
		})
	}
}

func TestLaunchOriginalFrame(t *testing.T) {
	f := newLaunchFixture(t)
	key := api.RequestKey{Method: f.scope.Request.Method, IdempotencyKey: f.scope.Request.IdempotencyKey, RequestSHA256: f.scope.Request.RequestSHA256}
	receipt := f.store.receipts[fixtureReceiptKey(f.scope, key)]
	var original api.Request
	if err := json.Unmarshal(receipt.RawRequest, &original); err != nil {
		t.Fatal(err)
	}
	original.RequestID = "changed-frame"
	var err error
	receipt.RawRequest, err = json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	f.store.receipts[fixtureReceiptKey(f.scope, key)] = receipt
	_, err = f.service.LaneStart(context.Background(), f.scope, f.request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.store.reservationCalls != 0 {
		t.Fatalf("launch changed its retained original frame: %v", err)
	}
}

func TestPlanLaunch(t *testing.T) {
	for _, driver := range []api.Driver{api.DriverCodex, api.DriverClaudock} {
		for _, disposition := range []string{"registered", "refused"} {
			t.Run(string(driver)+"/"+disposition, func(t *testing.T) {
				f := newLaunchFixture(t)
				f.request.Driver, f.ports.enrollment.Runtimes[0].Driver = driver, driver
				for i := range f.ports.delegated.Profiles {
					f.ports.delegated.Profiles[i].Driver = driver
				}
				f.service.deps.Claudock = f.ports
				f.scope = f.fixture.scope("lane.start", f.request, f.parent)
				f.ports.refuseCapture = disposition == "refused"
				if f.ports.refuseCapture {
					f.allowCaptureRefusal()
				}
				operation, record := f.reserve(t)
				scope, request := f.claim(t, record)
				plan, err := f.service.PlanLaunch(context.Background(), scope, request)
				if err != nil || api.ValidateLaunchPlan(plan) != nil {
					t.Fatalf("planner did not seal the measured launch: %v", err)
				}
				retained := f.store.plans[record.Reservation.ID]
				if retained.Phase != "spec_retained" || retained.Generation != 5 || retained.Handoff == nil || retained.DataStageID == "" ||
					!reflect.DeepEqual(*retained.Plan, plan) || plan.Capture.Status != disposition ||
					plan.Runner.Executable != f.ports.enrollment.Runtimes[0].Executable ||
					plan.Data.Home != f.ports.storage[plan.Lease.ID].Home {
					t.Fatal("planner lost the measured plan, home or mandatory capture disposition")
				}
				encoded, err := json.Marshal(retained.Handoff.Spec)
				if err != nil {
					t.Fatal(err)
				}
				canonical, err := api.CanonicalJSON(encoded)
				if err != nil {
					t.Fatal(err)
				}
				raw := f.store.blobs[retained.Handoff.Original.ID]
				if !bytes.Equal(raw, canonical) || digestOf(raw) != retained.Handoff.SpecSHA256 ||
					retained.Handoff.Original.Class != "launch_spec" ||
					api.ValidateAgentLaunchSpec(retained.Handoff.Spec, plan) != nil {
					t.Fatal("planner did not seal the exact canonical spec bytes")
				}
				var recovery api.LaunchRecovery
				if err := api.DecodeObject(f.store.blobs[launchObjectID(record.Reservation.ID, "recovery")], &recovery); err != nil ||
					recovery.PlanID != record.Reservation.ID || recovery.OriginalRequest != record.Reservation.OriginalRequest ||
					!reflect.DeepEqual(recovery.Handoff, *retained.Handoff) || recovery.Home != plan.Data.Home ||
					!reflect.DeepEqual(recovery.Capture, plan.Capture) {
					t.Fatalf("planner lost the complete retained recovery data: %v", err)
				}
				for _, stage := range []string{"allocate", "materialize", "briefing", "guidance", "acquire", "inject", "runner-start", "capture"} {
					if f.ports.calls[stage] != 1 {
						t.Fatalf("planner did not execute exactly one %s stage", stage)
					}
				}
				for _, effect := range f.store.effects {
					if effect.Effect.HelperAllocate != nil && (effect.Outcome == nil || effect.Outcome.HelperLease == nil || *effect.Outcome.HelperLease != plan.Lease) {
						t.Fatal("allocation did not retain its actual claimed effect outcome")
					}
					if effect.Effect.Worker != nil && (effect.Outcome == nil || effect.Outcome.Output == nil) {
						t.Fatal("materialization did not retain its actual claimed effect outcome")
					}
				}
				var prompt launchPrompt
				if err := api.DecodeObject(f.store.blobs[plan.Runner.Prompt.ID], &prompt); err != nil || prompt.Task != string(f.store.blobs[f.request.Task.ID]) {
					t.Fatalf("planner omitted the exact task prompt bytes: %v", err)
				}
				before := launchClone(t, f.ports.calls)
				second, err := f.service.PlanLaunch(context.Background(), scope, request)
				if err != nil || !reflect.DeepEqual(second, plan) {
					t.Fatalf("planner restart did not reuse the exact sealed plan: %v", err)
				}
				for _, stage := range []string{"allocate", "materialize", "acquire", "inject", "runner-start", "capture", "guidance"} {
					if f.ports.calls[stage] != before[stage] {
						t.Fatalf("planner restart repeated the %s stage", stage)
					}
				}
				if f.store.operations[operation.ID].Status != "pending" || f.launcher.prepared.Load() != 0 || f.launcher.launched.Load() != 0 {
					t.Fatal("completed plan falsely reported a prepared or running process")
				}
			})
		}
	}
}

func TestPlanLaunchClaim(t *testing.T) {
	for _, fault := range []string{"actor", "claim", "generation", "expired", "selector", "requester", "operation", "epoch", "policy", "caller_path", "caller_executable"} {
		t.Run(fault, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			request = launchClone(t, request)
			switch fault {
			case "actor":
				scope.Actor.Kind = "lane"
			case "claim":
				request.Lease.ClaimID = "foreign-claim"
			case "generation":
				request.Lease.Record.Generation++
			case "expired":
				current := f.store.effects[request.Lease.Record.Effect.ID]
				current.ClaimExpiresAt, request.Lease.ExpiresAt = "2029-01-01T00:00:00Z", "2029-01-01T00:00:00Z"
				f.store.effects[current.Effect.ID], request.Lease.Record = current, current
			case "selector":
				request.Lease.Record.Effect.PlanLaunch.ReservationID = "foreign-plan"
			case "caller_path":
				request.Lease.Record.Effect.Worker = &api.WorkerPlan{Argv: []string{"/caller/workspace"}}
			case "caller_executable":
				request.Lease.Record.Effect.Launch = &api.LaunchSpec{Runner: &api.RunnerPlan{Executable: api.Executable{ID: "caller-executable"}}}
			case "requester":
				record.Reservation.RequestedBy.ID = "foreign-requester"
				f.store.plans[record.Reservation.ID] = record
			case "operation":
				record.Reservation.OperationID = "foreign-operation"
				f.store.plans[record.Reservation.ID] = record
			case "epoch":
				f.store.fences[record.Reservation.Target.LifeID]++
			case "policy":
				f.store.policy.Generation++
				// The reservation is stale while the executor's authenticated
				// context is current. Keep the original reservation assertion
				// reachable after adding the independent scope-policy fence.
				scope.PolicyGeneration = f.store.policy.Generation
			}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err == nil || f.ports.calls["allocate"] != 0 || f.ports.calls["acquire"] != 0 ||
				fault != "epoch" && f.ports.calls["grants"] != 0 || f.store.plans[record.Reservation.ID].Phase != "reserved" {
				t.Fatalf("planner accepted a foreign or stale launch claim: %v", err)
			}
		})
	}
}

func TestPlanLaunchGrants(t *testing.T) {
	for _, fault := range []string{"id", "life", "parent", "policy", "revoked", "expired", "generation", "digest"} {
		t.Run(fault, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			f.ports.grantHook = func(grants *api.GrantSet) {
				switch fault {
				case "id":
					grants.ID = "foreign-grants"
				case "life":
					grants.LifeID = "foreign-life"
				case "parent":
					grants.ParentLifeID = "foreign-parent"
				case "policy":
					grants.PolicyGeneration++
				case "revoked":
					grants.Revoked = true
				case "expired":
					grants.ExpiresAt = "2029-01-01T00:00:00Z"
				case "generation":
					grants.Generation = 0
				case "digest":
					grants.SHA256 = "unmeasured"
				}
			}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.ports.calls["sources"] != 0 || f.ports.calls["allocate"] != 0 {
				t.Fatalf("planner used stale or foreign reserved grants: %v", err)
			}
		})
	}
}

func TestPlanLaunchData(t *testing.T) {
	for _, fault := range []string{"reservation", "run", "lease", "cwd", "branch", "home_path", "history", "source", "snapshot"} {
		t.Run(fault, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			f.ports.dataHook = func(data *api.LaunchData) {
				switch fault {
				case "reservation":
					data.ReservationID = "foreign-reservation"
				case "run":
					data.Target.Run++
				case "lease":
					data.LeaseID = "foreign-lease"
				case "cwd":
					data.Workspace.LogicalCWD = "/caller/workspace"
				case "branch":
					data.Workspace.Branch = "caller-branch"
				case "home_path":
					data.Home.Home.VendorDirectory = "../../caller-home"
				case "history":
					data.Home.Home.HistoryID = ""
				case "source":
					data.Source.Object.ID = "foreign-source"
				case "snapshot":
					data.Materialization.Objects[0].SnapshotSHA256 = digestOf([]byte("unmeasured snapshot"))
				}
			}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.ports.calls["acquire"] != 0 || f.ports.calls["capture"] != 0 {
				t.Fatalf("planner used a caller path or foreign materialization: %v", err)
			}
		})
	}
}

func TestPlanLaunchRunner(t *testing.T) {
	for _, fault := range []string{"executable", "prompt", "cwd", "home", "history"} {
		t.Run(fault, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			f.ports.runnerHook = func(plan *api.RunnerPlan) {
				switch fault {
				case "executable":
					plan.Executable.ID = "caller-executable"
				case "prompt":
					plan.Prompt.ID = "caller-prompt"
				case "cwd":
					plan.CWD = "/caller/cwd"
				case "home":
					plan.Home.ID = "foreign-home"
				case "history":
					plan.Session.HistoryID = "foreign-history"
				}
			}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.ports.calls["capture"] != 0 {
				t.Fatalf("planner accepted an unpinned runner input: %v", err)
			}
		})
	}
}

func TestPlanLaunchChangedSources(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	if _, err := f.service.PlanLaunch(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	f.ports.sourceHook = func(sources *api.LaunchSources) { sources.Project.Base = strings.Repeat("b", 40) }
	_, err := f.service.PlanLaunch(context.Background(), scope, request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.ports.calls["allocate"] != 1 || f.ports.calls["acquire"] != 1 {
		t.Fatalf("planner replay accepted changed pinned source inputs: %v", err)
	}
}

func TestPlanLaunchErrors(t *testing.T) {
	for _, stage := range []string{"grants", "sources", "allocate", "materialize", "briefing", "guidance", "acquire", "inject", "runner-start", "capture", "storage", "reconcile-capture"} {
		t.Run(stage, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			f.ports.failStage, f.ports.failure = stage, api.NotImplemented("dependency-owner", "actual "+stage)
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != f.ports.failure || f.store.operations[record.Reservation.OperationID].Status != "pending" || f.launcher.launched.Load() != 0 {
				t.Fatalf("planner replaced an owning dependency failure with success: %v", err)
			}
		})
	}
}

func TestPlanLaunchCaptureFailure(t *testing.T) {
	for _, code := range []api.ErrorCode{api.CodeNotImplemented, api.CodeUnavailable, api.CodeUnauthenticated, api.CodeIntegrity, api.CodeContainmentUnknown} {
		t.Run(string(code), func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			f.ports.failStage = "capture"
			f.ports.failure = &api.Error{Code: code, Owner: "capture-owner", Message: "actual capture failure", Instead: "Reconcile the original job."}
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != f.ports.failure {
				t.Fatalf("planner converted a capture failure to a discard binding: %v", err)
			}
			for _, event := range f.store.events {
				if event.Kind == "capture.refused" {
					t.Fatal("planner fabricated capture.refused from an error")
				}
			}
			observed := ""
			ctx := api.WithHelperReasonObserver(context.Background(), func(cause error, reason string) {
				if reflect.DeepEqual(cause, f.ports.failure) {
					observed = reason
				}
			})
			_, retry := f.service.PlanLaunch(ctx, scope, request)
			var typed *api.Error
			if !errors.As(retry, &typed) || !reflect.DeepEqual(typed, f.ports.failure) || f.ports.calls["capture"] != 1 {
				t.Fatalf("capture failure replay replaced the original owning result: %v", retry)
			}
			if (code == api.CodeUnavailable || code == api.CodeContainmentUnknown) && observed != "capture_retained_failure" {
				t.Fatal("retained capture failure was reported as fresh planning progress", observed)
			}
		})
	}
}

func TestPlanLaunchStageReplay(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	if _, err := f.service.PlanLaunch(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: f.store.plans[record.Reservation.ID]}
	if err := execution.original(context.Background()); err != nil {
		t.Fatal(err)
	}
	grant := execution.record.Plan.Inputs.Grants.Profiles[0]
	grant.ProfileID = "changed-profile"
	_, err := launchStage(context.Background(), execution, "credential-slot", grant, func() (api.CredentialSlot, error) {
		t.Fatal("changed stage replay invoked another credential acquisition")
		return api.CredentialSlot{}, launchConflict()
	})
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
		t.Fatalf("stage replay accepted changed retained inputs: %v", err)
	}
	delete(f.store.metadata, launchObjectID(record.Reservation.ID, "result-credential-slot"))
	_, err = launchStage(context.Background(), execution, "credential-slot", execution.record.Plan.Inputs.Grants.Profiles[0], func() (api.CredentialSlot, error) {
		t.Fatal("uncertain stage blindly acquired a replacement credential")
		return api.CredentialSlot{}, launchConflict()
	})
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeContainmentUnknown {
		t.Fatalf("uncertain launch stage replaced an unacknowledged outcome: %v", err)
	}
}

func TestLaunchPendingReply(t *testing.T) {
	f := newLaunchFixture(t)
	f.store.reservationHook = func(r *api.LaunchReservation) {
		operation := f.store.operations[r.OperationID]
		operation.Status = "running"
		f.store.operations[r.OperationID] = operation
	}
	operation, err := f.service.LaneStart(context.Background(), f.scope, f.request)
	if err != nil || operation.Status != "pending" || f.store.operations[operation.ID].Status != "running" || f.store.awaitCalls != 0 {
		t.Fatalf("launch did not return its exact pending operation reply: %v", err)
	}
}

func TestPlanCaptureTuple(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	f.ports.reconcileHook = func(binding *api.CaptureBinding) { binding.ProducerID = "foreign-producer" }
	_, err := f.service.PlanLaunch(context.Background(), scope, request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.store.plans[record.Reservation.ID].Handoff != nil {
		t.Fatalf("planner accepted a changed capture producer during reconciliation: %v", err)
	}
}

func TestPlanCaptureErrorRetention(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	primary := &api.Error{Code: api.CodeIntegrity, Owner: "capture-owner", Message: "actual producer integrity failure"}
	retention := &api.Error{Code: api.CodeUnavailable, Owner: "store-owner", Message: "actual failure retention unavailable"}
	f.ports.failStage, f.ports.failure = "capture", primary
	f.ports.onStage = func(stage string) {
		if stage == "capture" {
			f.store.retainErr = retention
		}
	}
	_, err := f.service.PlanLaunch(context.Background(), scope, request)
	if !errors.Is(err, primary) || !errors.Is(err, retention) || f.store.plans[record.Reservation.ID].Plan != nil {
		t.Fatalf("capture error retention hid an actual producer or store failure: %v", err)
	}
}

func TestPlanStorageTuple(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	plan, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	storage := f.ports.storage[plan.Lease.ID]
	storage.Home.RootID = "foreign-storage"
	f.ports.storage[plan.Lease.ID] = storage
	_, err = f.service.PlanLaunch(context.Background(), scope, request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.ports.calls["allocate"] != 1 {
		t.Fatalf("planner restart accepted changed private storage ownership: %v", err)
	}
}

func TestContinuationCurrentPolicy(t *testing.T) {
	for _, current := range []bool{true, false} {
		f := newFixture(t)
		advanceFixturePolicy(f)
		scope := api.Scope{Config: "example", Actor: api.Actor{Kind: "watchdog", ID: "watchdog"}, Source: "watchdog", PolicyGeneration: f.store.policy.Generation}
		lane, refreshErr := f.service.refreshLaunchPolicy(context.Background(), scope, f.child)
		if refreshErr != nil {
			t.Fatal(refreshErr)
		}
		f.child = lane
		request := fixtureContinuation(f)
		if !current {
			scope.PolicyGeneration--
		}
		_, err := f.service.Continue(context.Background(), scope, request)
		want := api.CodeNotImplemented
		if !current {
			want = api.CodeConflict
		}
		if typed, ok := err.(*api.Error); !ok || typed.Code != want {
			t.Fatalf("continuation did not compare the current policy generation: %v", err)
		}
	}
}
