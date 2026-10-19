package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Model an owning journal's correlated completion or a protected-record
// corruption. Hash the actual replacement bytes; never bypass blob read-back.
func replaceStage(t *testing.T, f *launchFixture, id api.ID, value any) {
	t.Helper()
	var result launchStageResult
	if err := api.DecodeObject(f.store.blobs[id], &result); err != nil {
		t.Fatal(err)
	}
	var err error
	result.Value, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	result.Error = nil
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = api.CanonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	meta := f.store.metadata[id]
	meta.Ref.SHA256, meta.Ref.Bytes = digestOf(raw), int64(len(raw))
	f.store.metadata[id], f.store.blobs[id] = meta, raw
}

func TestTransientPlan(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "unavailable", "uncertain", "retryable", "joined"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			var injected error
			switch mode {
			case "cancel":
				injected = context.Canceled
			case "deadline":
				injected = context.DeadlineExceeded
			case "unavailable":
				injected = problem(api.CodeUnavailable, "producer temporarily unavailable", "Reconcile the same producer.")
			case "uncertain":
				injected = problem(api.CodeContainmentUnknown, "producer result unacknowledged", "Reconcile its retained input.")
			case "retryable":
				injected = &api.Error{Code: api.CodeConflict, Owner: "stage-owner", Message: "retry original journal", Retryable: true}
			case "joined":
				injected = errors.Join(problem(api.CodeIntegrity, "retained failure", "Preserve it."), context.DeadlineExceeded)
			}
			f.ports.failStage, f.ports.failure = "capture", planError(injected)
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err == nil || !transientPlan(err) || f.store.plans[record.Reservation.ID].Phase == "failed" || len(f.store.failedWrites) != 0 || len(f.store.cleanups) != 0 {
				t.Fatalf("transient planning error permanently failed its reservation: %v", err)
			}
			var input api.CaptureRegistrationRequest
			if err := api.DecodeObject(f.store.blobs[launchObjectID(record.Reservation.ID, "input-capture")], &input); err != nil {
				t.Fatal(err)
			}
			f.ports.failStage, f.ports.failure = "", nil
			input.Claim = api.PlanningClaim(record.Reservation.ID, request.Lease)
			binding, err := f.service.deps.Capture.RegisterCapture(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			replaceStage(t, f, launchObjectID(record.Reservation.ID, "result-capture"), binding)
			plan, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != nil || plan.Reservation.ID != record.Reservation.ID || f.ports.calls["acquire"] != 1 || len(f.store.failedWrites) != 0 {
				t.Fatalf("transient reconciliation replaced or abandoned its original plan: %v", err)
			}
		})
	}
}

func TestTransientChild(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	f.ports.failStage, f.ports.failure = "allocate", problem(api.CodeUnavailable, "allocation journal unavailable", "Reconcile the original allocation.")
	_, err := f.service.PlanLaunch(context.Background(), scope, request)
	child := f.store.effects[launchObjectID(record.Reservation.ID, "allocate-effect")]
	if err == nil || child.State != api.EffectClaimed || child.Outcome != nil || f.store.plans[record.Reservation.ID].Phase == "failed" {
		t.Fatalf("transient child failure sealed a terminal outcome: %v", err)
	}
	f.ports.failStage, f.ports.failure = "", nil
	plan, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != nil || plan.Reservation.ID != record.Reservation.ID || f.ports.calls["acquire"] != 1 {
		t.Fatalf("transient child retry abandoned its original claim: %v", err)
	}
}

func TestSlotEvidence(t *testing.T) {
	for _, mode := range []string{"none", "input", "plan", "bound", "carried", "carried-conflict"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			var record api.LaunchPlanRecord
			var scope api.Scope
			var request api.LaunchPlanRequest
			var retainedSlot api.ObjectMetadata
			var carried *api.CredentialSlot
			var carriedProfile api.ProfileGrant
			if mode == "carried" || mode == "carried-conflict" {
				_, lane := f.endedPlan(t)
				watchdog, continuation, profile := f.continuation(t, lane)
				operation, err := f.service.Continue(context.Background(), watchdog, continuation)
				if err != nil {
					t.Fatal(err)
				}
				for _, candidate := range f.store.plans {
					if candidate.Reservation.OperationID == operation.ID {
						record = candidate
					}
				}
				slot, err := f.ports.Acquire(context.Background(), record.Reservation.Target, profile)
				if err != nil {
					t.Fatal(err)
				}
				intent := f.store.continuations[continuation.IntentID]
				intent.Slot = &slot
				f.store.continuations[intent.ID] = intent
				carried, carriedProfile = &slot, profile
				scope, request = f.claim(t, record)
			} else {
				_, record = f.reserve(t)
				scope, request = f.claim(t, record)
				if mode != "none" {
					plan, err := f.service.PlanLaunch(context.Background(), scope, request)
					if err != nil {
						t.Fatal(err)
					}
					if mode == "bound" {
						f.bindPrepared(t, scope, request, plan)
					}
					record = f.store.plans[record.Reservation.ID]
					retainedSlot = f.store.metadata[launchObjectID(record.Reservation.ID, "result-credential-slot")]
					delete(f.store.metadata, launchObjectID(record.Reservation.ID, "result-credential-slot"))
					if mode == "input" {
						record.Plan, record.Handoff, record.Phase = nil, nil, "sourced"
						f.store.plans[record.Reservation.ID] = record
					} else {
						delete(f.store.metadata, launchObjectID(record.Reservation.ID, "input-credential-slot"))
					}
				}
			}
			execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: record}
			if mode == "carried" {
				if err := execution.original(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "carried-conflict" {
				if err := execution.original(context.Background()); err != nil {
					t.Fatal(err)
				}
				foreign := *carried
				foreign.ID = "foreign-slot"
				if _, err := launchStage(context.Background(), execution, "credential-slot", carriedProfile,
					func() (api.CredentialSlot, error) { return foreign, nil }); err != nil {
					t.Fatal(err)
				}
				base, needed := execution.cleanupSlot(context.Background())
				jobs := execution.cleanupJobs(context.Background(), base)
				if !needed || base.SlotKnown || len(base.Issues) == 0 || len(jobs) == 0 {
					t.Fatal("continuation slot conflict became a known release selector")
				}
				unknown := false
				for _, job := range jobs {
					for _, issue := range job.Issues {
						unknown = unknown || issue.Code == api.CodeContainmentUnknown
					}
				}
				if !unknown {
					t.Fatal("continuation slot conflict omitted containment uncertainty")
				}
				primary := problem(api.CodeForbidden, "terminal planning refusal", "Retain the original cleanup.")
				if err := execution.failPlan(context.Background(), primary); !reflect.DeepEqual(err, primary) || len(f.store.failedWrites) != 1 {
					t.Fatalf("continuation slot conflict made the failed plan uncommittable: %v", err)
				}
				return
			}
			before := f.ports.calls["acquire"]
			primary := problem(api.CodeForbidden, "terminal planning refusal", "Retain the original cleanup.")
			err := execution.failPlan(context.Background(), primary)
			if mode == "none" {
				if err != primary || len(f.store.failedWrites) != 0 {
					t.Fatalf("resource-free planning failure invented credential cleanup: %v", err)
				}
				return
			}
			// The shared writer requires a retained result reference. Missing
			// acknowledgement is still resource evidence, but cannot be made
			// into a successful cleanup request by inventing that reference.
			invalid := false
			if joined, ok := err.(interface{ Unwrap() []error }); ok {
				for _, cause := range joined.Unwrap() {
					if typed, ok := cause.(*api.Error); ok && typed.Code == api.CodeInvalid && typed.Owner == "lb-v2-integrate" {
						invalid = true
					}
				}
			}
			base, needed := execution.cleanupSlot(context.Background())
			if !errors.Is(err, primary) || !invalid || !needed || base.SlotKnown != (mode != "input") ||
				!reflect.DeepEqual(f.store.plans[record.Reservation.ID], record) || len(f.store.failedWrites) != 0 || len(f.store.cleanups) != 0 || f.ports.calls["acquire"] != before {
				t.Fatalf("retained slot evidence lost its atomic cleanup trigger: unresolved result: %v", err)
			}
			if mode == "input" {
				input, ok := f.store.metadata[launchObjectID(record.Reservation.ID, "input-credential-slot")]
				if !ok || input.SourceOperationID != record.Reservation.OperationID || input.Origin != "service" || len(f.store.blobs[input.Ref.ID]) == 0 {
					t.Fatal("cleanup discarded its original unacknowledged slot input")
				}
			}
			// Reconcile only actual producer evidence: the retained bytes whose
			// index was lost, or the existing continuation slot through the
			// production stage journal. Neither path calls Acquire again.
			if carried != nil {
				if _, err := launchStage(context.Background(), execution, "credential-slot", carriedProfile,
					func() (api.CredentialSlot, error) { return *carried, nil }); err != nil {
					t.Fatal(err)
				}
			} else {
				f.store.metadata[retainedSlot.Ref.ID] = retainedSlot
			}
			err = execution.failPlan(context.Background(), primary)
			if !reflect.DeepEqual(err, primary) || len(f.store.failedWrites) != 1 || f.store.plans[record.Reservation.ID].Phase != "failed" || f.ports.calls["acquire"] != before {
				t.Fatalf("retained slot evidence lost its atomic cleanup trigger: %v", err)
			}
			for _, job := range f.store.cleanups {
				if !job.SlotKnown || job.SlotResult.ID != launchObjectID(record.Reservation.ID, "result-credential-slot") || mode == "bound" && job.Kind != "withdraw" {
					t.Fatal("cleanup replaced uncertain or carried slot evidence")
				}
			}
		})
	}
}

func TestInjectionGap(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "foreign", "mutated"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			plan, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			id := launchObjectID(record.Reservation.ID, "result-injection")
			if mode == "missing" {
				delete(f.store.metadata, id)
			} else if mode == "corrupt" {
				replaceStage(t, f, id, "not an injection")
			} else {
				injection := plan.Injection
				if mode == "foreign" {
					injection.Target.Run++
				} else {
					injection.SlotIDs = append(append([]api.ID{}, injection.SlotIDs...), "foreign-slot")
				}
				replaceStage(t, f, id, injection)
			}
			execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: f.store.plans[record.Reservation.ID]}
			base, _ := execution.cleanupSlot(context.Background())
			jobs := execution.cleanupJobs(context.Background(), base)
			want := api.CodeIntegrity
			if mode == "missing" {
				want = api.CodeContainmentUnknown
			}
			for _, job := range jobs {
				found := false
				for _, issue := range job.Issues {
					found = found || issue.Code == want
				}
				if !found || job.Injection != nil || job.InjectionIn == nil {
					t.Fatal("cleanup omitted an unacknowledged or corrupt injection issue")
				}
			}
		})
	}
}

func TestCleanupExpiry(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	plan, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	slot := plan.Runner.Slot
	slot.ExpiresAt = ""
	replaceStage(t, f, launchObjectID(record.Reservation.ID, "result-credential-slot"), slot)
	execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: f.store.plans[record.Reservation.ID]}
	base, needed := execution.cleanupSlot(context.Background())
	jobs := execution.cleanupJobs(context.Background(), base)
	if !needed || !base.SlotKnown || base.Slot != plan.Runner.Slot || len(base.Issues) == 0 || len(jobs) == 0 {
		t.Fatal("incomplete slot expiry was not reconciled to the retained plan")
	}
	primary := problem(api.CodeForbidden, "terminal planning refusal", "Retain the original cleanup.")
	if err := execution.failPlan(context.Background(), primary); err != primary || len(f.store.failedWrites) != 1 {
		t.Fatalf("incomplete slot expiry made the failed plan uncommittable: %v", err)
	}
}

func TestCleanupGate(t *testing.T) {
	for _, mode := range []string{"valid", "binding", "withdrawing", "prepare"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, request, plan := preparedFixture(t)
			binding := f.store.bindings[plan.Reservation.LaunchID]
			projection := f.store.projections[binding.Prepared.ID]
			switch mode {
			case "binding":
				binding.Record.Config = "foreign"
				f.store.bindings[plan.Reservation.LaunchID] = binding
			case "withdrawing":
				projection.State = "withdrawing"
				f.store.projections[binding.Prepared.ID] = projection
			case "prepare":
				delete(f.store.effects, projection.Authority.Request.Claim.Record.Effect.ID)
			}
			execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: f.store.plans[plan.Reservation.ID],
				input: launchInput{turn: request.Lease.Record.Effect.Context.LogicalTurnID}}
			base, _ := execution.cleanupSlot(context.Background())
			jobs := execution.cleanupJobs(context.Background(), base)
			if len(jobs) != 1 || jobs[0].Kind != "withdraw" {
				t.Fatal("cleanup lost its original projection selector")
			}
			job := jobs[0]
			if mode == "valid" {
				if job.Withdrawal == nil || api.ValidateCredentialWithdrawalRequest(projection, *job.Withdrawal) != nil {
					t.Fatal("cleanup refused its valid original withdrawal")
				}
			} else if job.Withdrawal != nil || len(job.Issues) == 0 || mode == "binding" && job.Prepared != nil {
				t.Fatal("cleanup trusted a foreign binding or invalid withdrawal")
			}
		})
	}
}

func TestPlanStages(t *testing.T) {
	for _, stage := range []string{"credential-slot", "injection", "runner"} {
		t.Run(stage, func(t *testing.T) {
			for _, mode := range []string{"missing", "mismatch"} {
				t.Run(mode, func(t *testing.T) {
					f := newLaunchFixture(t)
					_, record := f.reserve(t)
					scope, request := f.claim(t, record)
					plan, err := f.service.PlanLaunch(context.Background(), scope, request)
					if err != nil {
						t.Fatal(err)
					}
					id := launchObjectID(record.Reservation.ID, "result-"+stage)
					if mode == "missing" {
						delete(f.store.metadata, id)
					} else {
						switch stage {
						case "credential-slot":
							slot := plan.Runner.Slot
							slot.ID = "foreign-slot"
							replaceStage(t, f, id, slot)
						case "injection":
							injection := plan.Injection
							injection.Target.Run++
							replaceStage(t, f, id, injection)
						case "runner":
							runner := plan.Runner
							runner.Argv = append(append([]string{}, runner.Argv...), "foreign")
							replaceStage(t, f, id, runner)
						}
					}
					retainedRecord := launchClone(t, f.store.plans[record.Reservation.ID])
					_, err = f.service.PlanLaunch(context.Background(), scope, request)
					if err == nil || f.ports.calls["acquire"] != 1 || f.ports.calls["inject"] != 1 || f.ports.calls["runner-start"] != 1 {
						t.Fatalf("retained plan trusted a missing or replaced credential stage: %v", err)
					}
					if stage == "credential-slot" && mode == "mismatch" {
						// The retained plan slot is the safe selector; the foreign
						// result remains an integrity issue on the committed cleanup.
						execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: retainedRecord}
						base, needed := execution.cleanupSlot(context.Background())
						jobs := execution.cleanupJobs(context.Background(), base)
						if !needed || !base.SlotKnown || base.Slot != retainedRecord.Plan.Runner.Slot || len(base.Issues) == 0 ||
							len(jobs) == 0 || len(f.store.failedWrites) != 1 || f.store.plans[record.Reservation.ID].Phase != "failed" {
							t.Fatal("conflicting slot evidence was not retained safely")
						}
						for _, job := range jobs {
							if !job.SlotKnown || job.Slot != retainedRecord.Plan.Runner.Slot || len(job.Issues) == 0 {
								t.Fatal("conflicting slot evidence lost its integrity issue")
							}
						}
					}
				})
			}
		})
	}
}
