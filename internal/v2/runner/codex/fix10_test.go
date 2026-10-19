package codex

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Direct request comparisons isolate each reserved pin from later supervisor
// capability and runtime gates. A request never selects the returned level.
func TestLaunchPins(t *testing.T) {
	for _, fault := range []string{"level", "role", "driver", "ticket"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			record := f.currentPlan()
			r := record.Reservation
			original, err := f.service.originalLaunch(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if level, err := f.service.launchRequest(ctx, r, original, f.request, record.Inputs.Sources); err != nil || level != r.Level {
				t.Fatal("valid reserved child pins were not preserved", err)
			}
			code := api.CodeConflict
			switch fault {
			case "level":
				r.Level++
			case "role":
				r.Role = "reviewer"
			case "driver":
				r.Driver = api.DriverClaudock
			case "ticket":
				r.Authority.ID = "foreign_ticket"
				code = api.CodeIntegrity
			}
			level, err := f.service.launchRequest(ctx, r, original, f.request, record.Inputs.Sources)
			wantCode(t, err, code)
			if level != 0 {
				t.Fatal("refused reserved pins returned a level")
			}
		})
	}
}

func TestReservedDriver(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.service.Start(ctx, f.request); err != nil {
		t.Fatal(err)
	}
	record := f.currentPlan()
	record.Reservation.Driver = api.DriverClaudock
	f.store.plans[record.Reservation.ID] = record
	// The completed data stage must carry the same reservation. Its independent
	// equality check must not substitute for the adapter's reserved-driver pin.
	allocated := f.store.effects[f.service.deps.AllocationEffectID].Outcome.HelperLease
	storage, err := f.store.ResolveLaunchStorage(ctx, api.LaunchDataRequest{ReservationID: record.Reservation.ID,
		GrantSetID: record.Reservation.GrantSetID, LeaseID: allocated.ID})
	if err != nil {
		t.Fatal(err)
	}
	f.prepareDataStage(record.Reservation, *record.Inputs, *allocated, storage)
	if err := f.service.materializedLaunch(ctx, f.currentPlan(), f.service.deps.Planning.Lease.Record, storage); err != nil {
		t.Fatal("reserved driver fixture has an inconsistent materialization stage", err)
	}
	plan, err := f.service.Start(ctx, f.request)
	wantCode(t, err, api.CodeIntegrity)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Owner != "lb-v2-codex" || typed.Message != "Codex executable or source differs from protected enrollment" {
		t.Fatal("reserved driver control reached a different guard", err)
	}
	if !reflect.DeepEqual(plan, api.RunnerPlan{}) {
		t.Fatal("refused reserved driver returned a partial plan")
	}
}

func (f *runnerFixture) prepareNextLaunch(mode string) api.CaptureRecord {
	f.t.Helper()
	ctx := context.Background()
	if err := f.slot.Reserve(f.request); err != nil {
		f.t.Fatal(err)
	}
	record, exit := f.endCapture(threadLine(), 0)
	session, err := f.service.SessionFromCapture(ctx, record)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.slot.BindCodexSession(ctx, f.service, record); err != nil {
		f.t.Fatal(err)
	}
	f.store.event(f.request.Target, "runner.session", session)
	f.store.event(f.request.Target, "lane.ended", api.RunEndEvent{Observation: exit})
	if err := f.slot.Quiesce(exit); err != nil {
		f.t.Fatal(err)
	}
	f.store.lane.Session, f.store.lane.State = session, "verifying"
	f.request.Target.Run++
	f.request.Session = session
	f.request.Slot.ID, f.request.Slot.LeaseID = "next_slot", "next_lease"
	if err := f.slot.Install(f.request.Target, f.request.Slot, credentialFor(f.t, f.request.Slot.ProfileID, "login_one")); err != nil {
		f.t.Fatal(err)
	}
	f.prepareLaunch(mode, f.store.lane.Level)
	return record
}

func TestRetainedPins(t *testing.T) {
	for _, mode := range []string{"resume", "turn"} {
		t.Run(mode, func(t *testing.T) {
			for _, fault := range []string{"prior-level", "prior-role", "prior-driver", "lane-level", "lane-role", "lane-driver", "proof-id", "proof-digest", "proof-missing", "capture-refused"} {
				t.Run(fault, func(t *testing.T) {
					f := newFixture(t)
					priorCapture := f.prepareNextLaunch(mode)
					ctx := context.Background()
					record := f.currentPlan()
					r, request := record.Reservation, f.request
					original, err := f.service.originalLaunch(ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					if level, err := f.service.launchRequest(ctx, r, original, request, record.Inputs.Sources); err != nil || level != r.Level {
						t.Fatal("valid retained child pins were not preserved", err)
					}
					code := api.CodeIntegrity
					switch fault {
					case "prior-level":
						r.Level++
						f.store.lane.Level = r.Level
					case "prior-role":
						r.Role = "reviewer"
						f.store.lane.Role = r.Role
					case "prior-driver":
						r.Driver = api.DriverClaudock
						f.store.lane.Session.Driver, request.Session.Driver = r.Driver, r.Driver
					case "lane-level":
						f.store.lane.Level++
						code = api.CodeConflict
					case "lane-role":
						f.store.lane.Role = "reviewer"
						code = api.CodeConflict
					case "lane-driver":
						// Keep session equality so the reserved driver decides.
						f.store.lane.Session.Driver, request.Session.Driver = api.DriverClaudock, api.DriverClaudock
						code = api.CodeConflict
					case "proof-id":
						r.Authority.ID = "foreign_proof"
					case "proof-digest":
						original.Proof.RequestSHA256 = hashBytes([]byte("foreign intent"))
					case "proof-missing":
						original.Proof = nil
					case "capture-refused":
						f.retainCaptureDisposition(f.refusedCaptureState(priorCapture))
						code = api.CodeForbidden
					}
					level, err := f.service.launchRequest(ctx, r, original, request, record.Inputs.Sources)
					wantCode(t, err, code)
					if level != 0 {
						t.Fatal("refused retained pins returned a level")
					}
				})
			}
		})
	}
}

func (f *runnerFixture) refusedCaptureState(record api.CaptureRecord) api.CaptureState {
	f.t.Helper()
	state := fixtureCopy(f.store.captures[record.BindingID])
	binding := &state.Binding
	binding.Status = "refused"
	binding.Streams, binding.Supervisor = []api.CaptureStreamBinding{}, nil
	binding.WorkerLeaseID, binding.EffectID, binding.ProducerID, binding.ProducerGeneration, binding.BootID = "", "", "", "", ""
	binding.Refusal = api.NotImplemented("lb-v2-admin", "capture registration")
	binding.Refusal.OperationID = binding.OperationID
	binding.RefusalPolicy = f.fixtureRefusalPolicy()
	return state
}

func TestCapturePolicy(t *testing.T) {
	for _, fault := range []string{"disabled", "approval", "generation", "metadata", "snapshot", "snapshot-approval", "recovery"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			record, exit := f.endCapture(threadLine(), 0)
			f.retainCaptureDisposition(f.refusedCaptureState(record))
			ctx := context.Background()
			_, err := f.service.SessionFromCapture(ctx, record)
			wantCode(t, err, api.CodeNotImplemented)
			_, err = f.service.LimitFromCapture(ctx, record, exit)
			wantCode(t, err, api.CodeNotImplemented)
			code := api.CodeInvalid
			switch fault {
			case "disabled":
				f.store.policy.AllowCaptureRefusal = false
			case "approval":
				f.store.policy.CaptureRefusalApprovalID = "foreign_approval"
			case "generation":
				f.store.policy.Generation++
			case "metadata":
				state := fixtureCopy(f.store.captures[record.BindingID])
				state.Binding.RefusalPolicy = nil
				f.store.captures[record.BindingID] = state
			case "snapshot", "snapshot-approval":
				plan := f.currentPlan()
				if fault == "snapshot" {
					plan.Plan.CapturePolicy = nil
				} else {
					plan.Plan.CapturePolicy.CaptureRefusalApprovalID = "foreign_approval"
				}
				f.store.plans[plan.Reservation.ID] = plan
			case "recovery":
				bound := fixtureCopy(f.store.bindings[f.store.lane.LaunchID])
				bound.Recovery = nil
				f.store.bindings[f.store.lane.LaunchID] = bound
				code = api.CodeIntegrity
			}
			_, err = f.service.SessionFromCapture(ctx, record)
			wantCode(t, err, code)
			_, err = f.service.LimitFromCapture(ctx, record, exit)
			wantCode(t, err, code)
		})
	}
}

func TestReplayCapturePolicy(t *testing.T) {
	f := newFixture(t)
	record, _ := f.endCapture(threadLine(), 0)
	f.retainCaptureDisposition(f.refusedCaptureState(record))
	plan := f.currentPlan()
	plan.Phase, plan.Handoff = "planned", nil
	f.store.plans[plan.Reservation.ID] = plan
	ctx := context.Background()
	if _, err := f.service.Start(ctx, f.request); err != nil {
		t.Fatal("approved refused-capture replay control failed", err)
	}
	// A retained valid snapshot cannot turn the protected current flag on.
	f.store.policy.AllowCaptureRefusal = false
	_, err := f.service.Start(ctx, f.request)
	wantCode(t, err, api.CodeInvalid)
}

func TestAgentBinding(t *testing.T) {
	for _, fault := range []string{"kind", "worker", "level", "role"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			f.capture(threadLine(), 0)
			ctx := context.Background()
			launchID := f.store.lane.LaunchID
			if _, err := f.service.retainedLaunch(ctx, launchID); err != nil {
				t.Fatal(err)
			}
			bound := fixtureCopy(f.store.bindings[launchID])
			switch fault {
			case "kind":
				bound.Record.Kind = ""
			case "worker":
				bound.Record.Kind, bound.Record.Actor.Kind = "worker", "worker"
			case "level":
				bound.Record.Actor.Level++
			case "role":
				bound.Record.Actor.Role = "reviewer"
			}
			// Recompute the real canonical hash so the shared binding validator,
			// rather than a stale-hash shortcut, rejects the changed agent.
			bound.Identity.RecordSHA256 = f.keepJSON(bound.Record, "record").SHA256
			f.store.bindings[launchID] = bound
			_, err := f.service.retainedLaunch(ctx, launchID)
			wantCode(t, err, api.CodeInvalid)
		})
	}
}
