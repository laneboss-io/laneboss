package codex

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	storeport "laneboss.io/laneboss/internal/v2/store"
)

func (f *runnerFixture) currentPlan() api.LaunchPlanRecord {
	return fixtureCopy(f.store.plans[f.service.deps.Planning.Lease.Record.Effect.PlanLaunch.ReservationID])
}

// The full positive Start deliberately has no ready Lane. Every negative
// changes an actual selector, retained byte object or protected record.
func TestAllocState(t *testing.T) {
	f := newFixture(t)
	allocation := f.store.effects[f.service.deps.AllocationEffectID]
	if allocation.State != api.EffectCompleted || !api.ValidEffectState(allocation.State) {
		t.Fatal("allocation fixture used an obsolete state")
	}
	plan, err := f.service.Start(context.Background(), f.request)
	if err != nil || plan.Driver != api.DriverCodex {
		t.Fatalf("completed allocation was refused: %v", err)
	}
}

func TestLaunchConsumer(t *testing.T) {
	for _, name := range []string{"no-ready-lane", "caller-path", "caller-executable", "foreign-target", "claim", "policy", "grants", "enrollment", "storage", "allocation", "prompt", "session", "receipt", "replay"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			if _, err := f.service.Start(ctx, f.request); err != nil {
				t.Fatal("valid sourced launch control failed", err)
			}
			request := f.request
			code := api.CodeIntegrity
			record := f.currentPlan()
			switch name {
			case "no-ready-lane":
				f.store.lane = api.Lane{}
				plan, err := f.service.Start(ctx, request)
				if err != nil || plan.Home.VendorDirectory != ".codex" || plan.CWD != "/work/main" || plan.Executable != request.Executable {
					t.Fatal("launch still required a fabricated ready Lane", err)
				}
				return
			case "caller-path":
				request.Home.VendorDirectory = filepath.Join(f.home.path, ".codex")
			case "caller-executable":
				request.Executable.ID = "caller_executable"
				code = api.CodeVersion
			case "foreign-target":
				request.Target.LifeID = "foreign_life"
			case "claim":
				effectID := f.service.deps.Planning.Lease.Record.Effect.ID
				current := f.store.effects[effectID]
				current.ClaimID = "another_claim"
				f.store.effects[effectID] = current
				code = api.CodeConflict
			case "policy":
				f.store.policy.Generation++
				code = api.CodeConflict
			case "grants":
				f.store.grants.Revoked = true
				code = api.CodeForbidden
			case "enrollment":
				var enrollment api.LaunchEnrollment
				if err := f.store.retainedObject(f.store.enrollment, &enrollment); err != nil {
					t.Fatal(err)
				}
				enrollment.Runtimes[0].Executable.ID = "different_enrolled_executable"
				f.store.enrollment = f.keepJSON(enrollment, "manifest")
				record.Inputs.Sources.Runtime = enrollment.Runtimes[0]
				f.store.plans[record.Reservation.ID] = record
				// Keep the independent data stage coherent with the changed
				// enrollment so only the executable pin can decide this cell.
				allocated := f.store.effects[f.service.deps.AllocationEffectID].Outcome.HelperLease
				storage, err := f.store.ResolveLaunchStorage(ctx, api.LaunchDataRequest{ReservationID: record.Reservation.ID,
					GrantSetID: record.Reservation.GrantSetID, LeaseID: allocated.ID})
				if err != nil {
					t.Fatal(err)
				}
				f.prepareDataStage(record.Reservation, *record.Inputs, *allocated, storage)
				if err := f.service.materializedLaunch(ctx, f.currentPlan(), f.service.deps.Planning.Lease.Record, storage); err != nil {
					t.Fatal("runtime pin fixture has an inconsistent materialization stage", err)
				}
			case "storage":
				var storage api.LaunchStorage
				if err := f.store.retainedObject(f.store.journal[record.Reservation.ID], &storage); err != nil {
					t.Fatal(err)
				}
				storage.Home.LifeID = "foreign_life"
				f.store.journal[record.Reservation.ID] = f.keepJSON(storage, "record")
			case "allocation":
				allocation := f.store.effects[f.service.deps.AllocationEffectID]
				allocation.Outcome = nil
				f.store.effects[f.service.deps.AllocationEffectID] = allocation
			case "prompt":
				request.Prompt = f.store.keepClass([]byte("different committed prompt"), "prompt")
			case "session":
				f.home.record.Session.ID = "changed_private_session"
				if err := f.home.save(); err != nil {
					t.Fatal(err)
				}
				code = api.CodeConflict
			case "receipt":
				for key, receipt := range f.store.receipts {
					receipt.RawRequest = append(receipt.RawRequest, ' ')
					f.store.receipts[key] = receipt
				}
			case "replay":
				f.capture(threadLine(), 0)
				record = f.currentPlan()
				record.Phase, record.Handoff = "planned", nil
				record.Plan.Runner.Argv = append(record.Plan.Runner.Argv, "changed_argument")
				f.store.plans[record.Reservation.ID] = record
			}
			plan, err := f.service.Start(ctx, request)
			wantCode(t, err, code)
			if name == "enrollment" {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Owner != "lb-v2-codex" || typed.Message != "Codex executable or source differs from protected enrollment" {
					t.Fatal("runtime pin control reached a different guard", err)
				}
			}
			if !reflect.DeepEqual(plan, api.RunnerPlan{}) {
				t.Fatal("refused launch returned a partial plan")
			}
		})
	}
}

func TestStartForeignProfileParent(t *testing.T) {
	f := newFixture(t)
	record := f.currentPlan()
	original, err := f.service.originalLaunch(context.Background(), record.Reservation)
	if err != nil {
		t.Fatal(err)
	}
	f.store.grants.Profiles[0].ParentGrantID = "foreign-parent"
	if _, err := f.service.launchRequest(context.Background(), record.Reservation, original, f.request, record.Inputs.Sources); err == nil {
		t.Fatal("Codex accepted an issued profile with a foreign parent grant")
	}
}

// These direct deciding-check controls isolate claim generation/expiry from
// later grant expiry and exercise every named reservation/effect correlation.
func TestPlanningClaim(t *testing.T) {
	for _, name := range []string{"generation", "zero-generation", "expiry", "claim", "claim-shape", "claim-expiry", "claimant", "state", "outcome", "scope", "scope-id"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			lease := f.service.deps.Planning.Lease
			current := fixtureCopy(lease.Record)
			scope, now := f.service.deps.ReadScope, f.clock.Now()
			if err := planningClaim(current, lease, scope, now); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "generation":
				current.Generation++
			case "zero-generation":
				current.Generation = 0
			case "expiry":
				now = now.Add(2 * time.Hour)
			case "claim":
				current.ClaimID = "foreign_claim"
			case "claim-shape":
				current.ClaimID, lease.ClaimID = "", ""
			case "claim-expiry":
				current.ClaimExpiresAt = api.Timestamp(now.Add(30 * time.Minute).Format(time.RFC3339Nano))
			case "claimant":
				current.ClaimantID = "foreign_worker"
			case "state":
				current.State = api.EffectCompleted
			case "outcome":
				current.Outcome = &api.EffectOutcome{}
			case "scope":
				scope.Actor.Kind = "lane"
			case "scope-id":
				scope.Actor.ID, current.ClaimantID = "", ""
			}
			if name != "generation" {
				// Isolate the named claim guard from the snapshot comparison.
				lease.Record = fixtureCopy(current)
			}
			wantCode(t, planningClaim(current, lease, scope, now), api.CodeConflict)
		})
	}
}

func TestReservationEffect(t *testing.T) {
	for _, name := range []string{"reservation", "config", "target", "operation", "request", "requester", "epoch"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			r := f.currentPlan().Reservation
			effect := f.service.deps.Planning.Lease.Record.Effect
			if err := reservationEffect(r, effect, f.service.deps.ReadScope, f.request.Target); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "reservation":
				r.ID = "foreign_reservation"
			case "config":
				r.Config = "foreign-config"
			case "target":
				r.Target.Run++
			case "operation":
				r.OperationID = "foreign_operation"
			case "request":
				r.RequestID = "foreign_request"
			case "requester":
				r.RequestedBy.ID = "foreign_requester"
			case "epoch":
				r.CancellationEpoch++
			}
			wantCode(t, reservationEffect(r, effect, f.service.deps.ReadScope, f.request.Target), api.CodeIntegrity)
		})
	}
}

func TestLaunchStoragePath(t *testing.T) {
	f := newFixture(t)
	record := f.currentPlan()
	allocation := f.store.effects[f.service.deps.AllocationEffectID]
	ctx := context.Background()
	if _, err := f.service.launchStorage(ctx, record.Reservation, *allocation.Outcome.HelperLease); err != nil {
		t.Fatal(err)
	}
	var storage api.LaunchStorage
	if err := f.store.retainedObject(f.store.journal[record.Reservation.ID], &storage); err != nil {
		t.Fatal(err)
	}
	storage.Home.Home.VendorDirectory = filepath.Join(f.home.path, ".codex")
	f.store.journal[record.Reservation.ID] = f.keepJSON(storage, "record")
	_, err := f.service.launchStorage(ctx, record.Reservation, *allocation.Outcome.HelperLease)
	wantCode(t, err, api.CodeIntegrity)
}

func TestOriginalLaunchFrame(t *testing.T) {
	f := newFixture(t)
	r := f.currentPlan().Reservation
	ctx := context.Background()
	if _, err := f.service.originalLaunch(ctx, r); err != nil {
		t.Fatal(err)
	}
	var original api.Request
	if err := decode(f.store.blobs[r.OriginalRequest.ID], &original); err != nil {
		t.Fatal(err)
	}
	original.RequestID = "different_original_request"
	r.OriginalRequest = f.keepJSON(original, "launch_request")
	for key, receipt := range f.store.receipts {
		receipt.RawRequest = append([]byte{}, f.store.blobs[r.OriginalRequest.ID]...)
		f.store.receipts[key] = receipt
	}
	_, err := f.service.originalLaunch(ctx, r)
	wantCode(t, err, api.CodeIntegrity)
}

// A recreated adapter uses retained plan/spec/identity/home/capture records.
// Missing or changed recovery never becomes a fresh binding after restart.
func TestRetainedRecovery(t *testing.T) {
	for _, name := range []string{"missing", "request", "spec", "provenance"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.capture(threadLine(), 0)
			record := f.currentPlan()
			ctx := context.Background()
			restarted, err := New(f.service.deps)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.retainedLaunch(ctx, record.Reservation.LaunchID); err != nil {
				t.Fatal("retained recovery control failed", err)
			}
			binding := fixtureCopy(f.store.bindings[record.Reservation.LaunchID])
			code := api.CodeIntegrity
			switch name {
			case "missing":
				binding.Recovery = nil
			case "request":
				binding.Recovery.OriginalRequest.ID = "foreign_request"
				code = api.CodeInvalid
			case "spec":
				f.store.blobs[binding.Recovery.Handoff.Original.ID][0] = '['
			case "provenance":
				id := binding.Recovery.Handoff.Original.ID
				metadata := f.store.metadata[id]
				metadata.SourceOperationID = "foreign_operation"
				f.store.metadata[id] = metadata
			}
			f.store.bindings[record.Reservation.LaunchID] = binding
			_, err = restarted.retainedLaunch(ctx, record.Reservation.LaunchID)
			wantCode(t, err, code)
		})
	}
}

func TestCaptureLaunchBinding(t *testing.T) {
	for _, name := range []string{"unbound", "supplementary", "foreign-binding", "missing-state", "missing-recovery", "registration", "cause", "position", "policy", "grants", "grants-revoked", "refused"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			record, exit := f.endCapture(threadLine(), 0)
			ctx := context.Background()
			if _, err := f.service.SessionFromCapture(ctx, record); err != nil {
				t.Fatal("bound capture control failed", err)
			}
			if signal, err := f.service.LimitFromCapture(ctx, record, exit); err != nil || signal != nil {
				t.Fatal("bound nonlimit control failed", err)
			}
			code := api.CodeIntegrity
			switch name {
			case "unbound":
				record.BindingID = ""
			case "supplementary":
				record.Primary = false
			case "foreign-binding":
				record.BindingID = "foreign_binding"
				code = api.CodeNotFound
			case "missing-state":
				delete(f.store.captures, record.BindingID)
				code = api.CodeNotFound
			case "missing-recovery":
				delete(f.store.bindings, f.store.lane.LaunchID)
				code = api.CodeNotFound
			case "registration":
				kept := []api.Event{}
				for _, event := range f.store.setupEvents {
					if event.Kind != "capture.bound" {
						kept = append(kept, event)
					}
				}
				f.store.setupEvents = kept
			case "cause":
				f.store.events[0].OperationID = "foreign_operation"
			case "position":
				state := f.store.captures[record.BindingID]
				state.Positions[0].NextOffset--
				f.store.captures[record.BindingID] = state
			case "policy":
				f.store.policy.Generation++
				f.service.deps.ReadScope.PolicyGeneration = f.store.policy.Generation
				if _, err := f.service.SessionFromCapture(ctx, record); err != nil {
					t.Fatal("policy advance blocked historical session capture", err)
				}
				if signal, err := f.service.LimitFromCapture(ctx, record, exit); err != nil || signal != nil {
					t.Fatal("policy advance blocked historical nonlimit capture", err)
				}
				return
			case "grants", "grants-revoked":
				f.store.grants.Revoked = true
				code = api.CodeForbidden
			case "refused":
				state := f.store.captures[record.BindingID]
				b := &state.Binding
				b.Status = "refused"
				b.Streams = []api.CaptureStreamBinding{}
				b.Supervisor = nil
				b.WorkerLeaseID, b.EffectID, b.ProducerID, b.ProducerGeneration, b.BootID = "", "", "", "", ""
				b.Refusal = api.NotImplemented("lb-v2-admin", "capture registration")
				b.Refusal.OperationID = b.OperationID
				b.RefusalPolicy = f.fixtureRefusalPolicy()
				f.retainCaptureDisposition(state)
				code = api.CodeNotImplemented
			}
			_, err := f.service.SessionFromCapture(ctx, record)
			wantCode(t, err, code)
			_, err = f.service.LimitFromCapture(ctx, record, exit)
			wantCode(t, err, code)
		})
	}
}

func TestCaptureEOF(t *testing.T) {
	f := newFixture(t)
	record, exit := f.endCapture(threadLine(), 0)
	ctx := context.Background()
	if _, err := f.service.LimitFromCapture(ctx, record, exit); err != nil {
		t.Fatal(err)
	}
	state := f.store.captures[record.BindingID]
	state.Positions[0].EOF = false
	f.store.captures[record.BindingID] = state
	if _, err := f.service.SessionFromCapture(ctx, record); err != nil {
		t.Fatal("in-progress session prefix became unavailable", err)
	}
	_, err := f.service.LimitFromCapture(ctx, record, exit)
	wantCode(t, err, api.CodeUnavailable)
}

func TestCaptureDisposition(t *testing.T) {
	f := newFixture(t)
	record := f.capture(threadLine(), 0)
	state := fixtureCopy(f.store.captures[record.BindingID])
	if err := captureDisposition(state, record, f.store.lane, "case-codex", f.store.policy); err != nil {
		t.Fatal(err)
	}
	b := &state.Binding
	b.Status = "refused"
	b.Streams = []api.CaptureStreamBinding{}
	b.Supervisor = nil
	b.WorkerLeaseID, b.EffectID, b.ProducerID, b.ProducerGeneration, b.BootID = "", "", "", "", ""
	b.Refusal = api.NotImplemented("lb-v2-admin", "capture registration")
	b.Refusal.OperationID = b.OperationID
	b.RefusalPolicy = f.fixtureRefusalPolicy()
	wantCode(t, captureDisposition(state, record, f.store.lane, "case-codex", f.store.policy), api.CodeNotImplemented)
	for _, code := range []api.ErrorCode{api.CodeUnavailable, api.CodeUnsupported} {
		b.Refusal.Code = code
		if err := captureDisposition(state, record, f.store.lane, "case-codex", f.store.policy); err != b.Refusal {
			t.Fatal("capture refusal or recovery text changed", err)
		}
	}
	b.Refusal.Code = api.CodeForbidden
	wantCode(t, captureDisposition(state, record, f.store.lane, "case-codex", f.store.policy), api.CodeInvalid)
}

func TestPreparedSession(t *testing.T) {
	f := newFixture(t)
	if session, err := f.home.PreparedSession(); err != nil || session != f.request.Session {
		t.Fatal(err)
	}
	f.home.record.Session = api.Session{}
	if err := f.home.save(); err != nil {
		t.Fatal(err)
	}
	_, err := f.home.PreparedSession()
	wantCode(t, err, api.CodeConflict)
}

type realEffectPort struct {
	api.StateStore
	actual *storeport.Service
}

func (p realEffectPort) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	return p.actual.Effect(ctx, scope, id)
}

// These barriers call the actual owning packages. A fixture cannot replace
// their not_implemented result with successful empty sources or store state.
func TestOwnerPortRefusals(t *testing.T) {
	for _, name := range []string{"sources", "storage", "store"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			record := f.currentPlan()
			ctx := context.Background()
			var expected error
			switch name {
			case "sources":
				actual := &admin.Service{}
				_, expected = actual.ResolveLaunchSources(ctx, api.LaunchSourceRequest{ReservationID: record.Reservation.ID, GrantSetID: record.Reservation.GrantSetID})
				f.service.deps.Sources = actual
			case "storage":
				actual := &admin.Service{}
				allocation := f.store.effects[f.service.deps.AllocationEffectID]
				_, expected = actual.ResolveLaunchStorage(ctx, api.LaunchDataRequest{ReservationID: record.Reservation.ID, GrantSetID: record.Reservation.GrantSetID, LeaseID: allocation.Outcome.HelperLease.ID})
				f.service.deps.Storage = actual
			case "store":
				actual := &storeport.Service{}
				_, expected = actual.Effect(ctx, f.service.deps.ReadScope, f.service.deps.Planning.Lease.Record.Effect.ID)
				f.service.deps.Store = realEffectPort{StateStore: f.store, actual: actual}
			}
			if expected == nil {
				t.Fatal("owner dependency unexpectedly available without installation")
			}
			plan, err := f.service.Start(ctx, f.request)
			if !reflect.DeepEqual(err, expected) || !reflect.DeepEqual(plan, api.RunnerPlan{}) {
				t.Fatal("owning dependency refusal was not preserved", err)
			}
		})
	}
}
