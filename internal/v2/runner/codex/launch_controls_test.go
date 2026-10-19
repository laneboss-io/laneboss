package codex

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Each row changes one retained fact after a complete positive invocation.
// Narrow helper assertions isolate a deciding guard from later defence in
// depth; full Start/Resume/Turn and capture controls remain separate tests.
func TestLaunchGuards(t *testing.T) {
	for _, name := range []string{"effect-target", "phase", "mode", "allocation-runtime", "request-model", "original-provenance", "grant-revoked", "grant-generation", "replay-home"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			if _, err := f.service.Start(ctx, f.request); err != nil {
				t.Fatal("complete launch control failed", err)
			}
			record := f.currentPlan()
			r := record.Reservation
			code := api.CodeIntegrity
			var err error
			switch name {
			case "effect-target":
				id := f.service.deps.Planning.Lease.Record.Effect.ID
				current := fixtureCopy(f.store.effects[id])
				current.Effect.Context.Target.Run++
				f.store.effects[id] = current
				f.service.deps.Planning.Lease.Record = fixtureCopy(current)
				_, err = f.service.Start(ctx, f.request)
			case "phase":
				f.capture(threadLine(), 0)
				_, err = f.service.Start(ctx, f.request)
				code = api.CodeConflict
			case "mode":
				if _, err := f.service.launchInput(ctx, f.request, "start"); err != nil {
					t.Fatal(err)
				}
				_, err = f.service.launchInput(ctx, f.request, "resume")
				code = api.CodeConflict
			case "allocation-runtime":
				id := f.service.deps.AllocationEffectID
				current := fixtureCopy(f.store.effects[id])
				current.Effect.HelperAllocate.RuntimeManifestID = "foreign_runtime"
				f.store.effects[id] = current
				_, err = f.service.Start(ctx, f.request)
			case "request-model":
				original, originalErr := f.service.originalLaunch(ctx, r)
				if originalErr != nil {
					t.Fatal(originalErr)
				}
				if _, err := f.service.launchRequest(ctx, r, original, f.request, record.Inputs.Sources); err != nil {
					t.Fatal(err)
				}
				request := f.request
				request.Model = "gpt-6-sol"
				_, err = f.service.launchRequest(ctx, r, original, request, record.Inputs.Sources)
				code = api.CodeConflict
			case "original-provenance":
				metadata := f.store.metadata[r.OriginalRequest.ID]
				metadata.SourceOperationID = "foreign_operation"
				f.store.metadata[r.OriginalRequest.ID] = metadata
				_, err = f.service.originalLaunch(ctx, r)
			case "grant-revoked":
				f.store.grants.Revoked = true
				// Isolate revocation from the independently checked snapshot.
				err = f.service.launchAuthority(ctx, r, fixtureCopy(f.store.grants))
				code = api.CodeForbidden
			case "grant-generation":
				f.store.grants.Generation++
				err = f.service.launchAuthority(ctx, r, record.Inputs.Grants)
				code = api.CodeForbidden
			case "replay-home":
				f.capture(threadLine(), 0)
				record = f.currentPlan()
				record.Phase, record.Handoff = "planned", nil
				f.store.plans[r.ID] = record
				if _, err := f.service.Start(ctx, f.request); err != nil {
					t.Fatal("sealed replay control failed", err)
				}
				var storage api.LaunchStorage
				if err := f.store.retainedObject(f.store.journal[r.ID], &storage); err != nil {
					t.Fatal(err)
				}
				storage.Home.RootID = "replacement_home_root"
				f.store.journal[r.ID] = f.keepJSON(storage, "record")
				_, err = f.service.Start(ctx, f.request)
			}
			wantCode(t, err, code)
		})
	}
}

func TestCaptureGuards(t *testing.T) {
	for _, name := range []string{"plan-session", "storage-home", "identity-event", "identity-pin", "registration-cause", "object-cause", "position-missing", "position-invalid", "stream"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			record, exit := f.endCapture(threadLine(), 0)
			ctx := context.Background()
			if _, err := f.service.SessionFromCapture(ctx, record); err != nil {
				t.Fatal("complete capture control failed", err)
			}
			if _, err := f.service.LimitFromCapture(ctx, record, exit); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "plan-session":
				f.store.lane.Session.ID = "foreign_session"
			case "storage-home":
				r := f.currentPlan().Reservation
				var storage api.LaunchStorage
				if err := f.store.retainedObject(f.store.journal[r.ID], &storage); err != nil {
					t.Fatal(err)
				}
				storage.Home.RootID = "replacement_home_root"
				f.store.journal[r.ID] = f.keepJSON(storage, "record")
			case "identity-event":
				kept := []api.Event{}
				for _, event := range f.store.setupEvents {
					if event.Kind != "identity.bound" {
						kept = append(kept, event)
					}
				}
				f.store.setupEvents = kept
			case "identity-pin":
				for i := range f.store.setupEvents {
					if f.store.setupEvents[i].Kind == "identity.bound" {
						f.store.setupEvents[i].ID = "foreign_identity_event"
					}
				}
			case "registration-cause":
				for i := range f.store.setupEvents {
					if f.store.setupEvents[i].Kind == "capture.bound" {
						f.store.setupEvents[i].RequestedBy.ID = "foreign_requester"
					}
				}
			case "object-cause":
				metadata := f.store.metadata[record.Data.ID]
				metadata.SourceOperationID = "foreign_operation"
				f.store.metadata[record.Data.ID] = metadata
			case "position-missing", "position-invalid", "stream":
				state := fixtureCopy(f.store.captures[record.BindingID])
				switch name {
				case "position-missing":
					state.Positions = state.Positions[1:]
				case "position-invalid":
					state.Positions[0].NextOffset = -1
				case "stream":
					// An orphan position cannot register an absent vendor pipe.
					record.Stream = "vendor"
					state.Positions = append(state.Positions, api.CapturePosition{NextOffset: record.Data.Bytes})
				}
				f.store.captures[record.BindingID] = state
				events, err := f.service.events(ctx, record.Target)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.service.captureSource(ctx, record, f.store.lane, events)
				wantCode(t, err, api.CodeIntegrity)
				return
			}
			_, err := f.service.SessionFromCapture(ctx, record)
			wantCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestCapturePrefixBinding(t *testing.T) {
	f := newFixture(t)
	line := threadLine()
	first := f.capture(line[:17], 0)
	last := f.capture(line[17:], 17)
	ctx := context.Background()
	if _, err := f.service.SessionFromCapture(ctx, last); err != nil {
		t.Fatal(err)
	}
	first.BindingID = "foreign_capture_binding"
	data, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	f.store.events[0].Payload = data
	_, err = f.service.SessionFromCapture(ctx, last)
	wantCode(t, err, api.CodeIntegrity)
}

func TestCaptureDispositionPins(t *testing.T) {
	for _, name := range []string{"binding", "config", "target", "launch", "generation", "sequence", "producer"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			record := f.capture(threadLine(), 0)
			state := fixtureCopy(f.store.captures[record.BindingID])
			if err := captureDisposition(state, record, f.store.lane, "case-codex", f.store.policy); err != nil {
				t.Fatal(err)
			}
			code := api.CodeIntegrity
			switch name {
			case "binding":
				state.Binding.ID = "foreign_binding"
			case "config":
				state.Binding.Config = "foreign-config"
			case "target":
				state.Binding.Target.Run++
			case "launch":
				state.Binding.LaunchID = "foreign_launch"
			case "generation":
				state.Generation = 0
			case "sequence":
				state.LastSeq = 0
			case "producer":
				state.Binding.ProducerID = ""
				code = api.CodeInvalid
			}
			wantCode(t, captureDisposition(state, record, f.store.lane, "case-codex", f.store.policy), code)
		})
	}
}

func TestCaptureGapBinding(t *testing.T) {
	f := newFixture(t)
	record := f.capture(threadLine(), 0)
	ctx := context.Background()
	if _, err := f.service.SessionFromCapture(ctx, record); err != nil {
		t.Fatal(err)
	}
	f.store.event(record.Target, "capture.gap", api.CaptureGap{BindingID: "foreign_binding", Target: record.Target,
		Stream: "stderr", StartOffset: 0, Reason: "synthetic unknown stream gap", ObservedAt: record.ObservedAt})
	_, err := f.service.SessionFromCapture(ctx, record)
	wantCode(t, err, api.CodeIntegrity)
}

func TestCaptureClosureReceipt(t *testing.T) {
	for _, name := range []string{"missing", "position", "binding", "stream", "offset", "next", "generation", "sequence", "eof"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			record, exit := f.endCapture(threadLine(), 0)
			ctx := context.Background()
			if _, err := f.service.LimitFromCapture(ctx, record, exit); err != nil {
				t.Fatal(err)
			}
			last := len(f.store.events) - 1
			if f.store.events[last].Kind != "capture.closed" {
				t.Fatal("closure fixture did not retain its EOF event")
			}
			if name == "missing" {
				f.store.events = f.store.events[:last]
			} else if name == "position" {
				state := fixtureCopy(f.store.captures[record.BindingID])
				state.Positions[0].NextOffset++
				f.store.captures[record.BindingID] = state
			} else {
				var receipt api.CaptureAppendReceipt
				if err := decode(f.store.events[last].Payload, &receipt); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "binding":
					receipt.BindingID = "foreign_binding"
				case "stream":
					receipt.StreamID = "foreign_stream"
				case "offset":
					receipt.Offset++
				case "next":
					receipt.NextOffset++
				case "generation":
					receipt.Generation++
				case "sequence":
					receipt.LastSeq++
				case "eof":
					receipt.EOF = false
				}
				data, err := json.Marshal(receipt)
				if err != nil {
					t.Fatal(err)
				}
				f.store.events[last].Payload = data
			}
			_, err := f.service.LimitFromCapture(ctx, record, exit)
			wantCode(t, err, api.CodeUnavailable)
		})
	}
}

func TestCaptureCauseBounds(t *testing.T) {
	for _, name := range []string{"request", "requester", "registration", "identity", "acknowledgement"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			record, _ := f.endCapture(threadLine(), 0)
			ctx := context.Background()
			events, err := f.service.events(ctx, record.Target)
			if err != nil {
				t.Fatal(err)
			}
			source, err := f.service.captureSource(ctx, record, f.store.lane, events)
			if err != nil {
				t.Fatal(err)
			}
			event := fixtureCopy(f.store.events[0])
			if !captureCause(event, source) {
				t.Fatal("valid capture cause was rejected")
			}
			switch name {
			case "request":
				event.RequestID = "foreign_request"
			case "requester":
				event.RequestedBy.ID = "foreign_requester"
			case "registration":
				source.boundSeq = event.Seq
			case "identity":
				source.identitySeq = event.Seq
			case "acknowledgement":
				source.state.LastSeq = event.Seq - 1
			}
			if captureCause(event, source) {
				t.Fatal("capture cause accepted a foreign or unacknowledged range")
			}
		})
	}
}

func TestRetainedLaunchStorage(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.slot.Reserve(f.request); err != nil {
		t.Fatal(err)
	}
	record, exit := f.endCapture(threadLine(), 0)
	session, err := f.service.SessionFromCapture(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.slot.BindCodexSession(ctx, f.service, record); err != nil {
		t.Fatal(err)
	}
	f.store.event(f.request.Target, "runner.session", session)
	f.store.event(f.request.Target, "lane.ended", api.RunEndEvent{Observation: exit})
	if err := f.slot.Quiesce(exit); err != nil {
		t.Fatal(err)
	}
	f.store.lane.Session, f.store.lane.State = session, "verifying"
	f.request.Target.Run++
	f.request.Session = session
	f.request.Slot.ID, f.request.Slot.LeaseID = "next_slot", "next_lease"
	if err := f.slot.Install(f.request.Target, f.request.Slot, credentialFor(t, f.request.Slot.ProfileID, "login_one")); err != nil {
		t.Fatal(err)
	}
	f.prepareLaunch("resume", 3)
	if _, err := f.service.Resume(ctx, f.request); err != nil {
		t.Fatal("retained home control failed", err)
	}
	r := f.currentPlan().Reservation
	var storage api.LaunchStorage
	if err := f.store.retainedObject(f.store.journal[r.ID], &storage); err != nil {
		t.Fatal(err)
	}
	storage.Home.RootID = "replacement_retained_home"
	f.store.journal[r.ID] = f.keepJSON(storage, "record")
	// Retain the changed storage through the real stage validators. Otherwise
	// the independent stage/storage comparison masks the continuity guard.
	current := f.currentPlan()
	allocated := f.store.effects[f.service.deps.AllocationEffectID].Outcome.HelperLease
	f.prepareDataStage(r, *current.Inputs, *allocated, storage)
	if err := f.service.materializedLaunch(ctx, f.currentPlan(), f.service.deps.Planning.Lease.Record, storage); err != nil {
		t.Fatal("retained home fixture has an inconsistent materialization stage", err)
	}
	plan, err := f.service.Resume(ctx, f.request)
	wantCode(t, err, api.CodeIntegrity)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Owner != "lb-v2-codex" || typed.Message != "Codex retained run changed its allocated home or workspace" {
		t.Fatal("retained home control reached a different guard", err)
	}
	if !reflect.DeepEqual(plan, api.RunnerPlan{}) {
		t.Fatal("refused retained home returned a partial plan")
	}
}

func TestRefusedCaptureScope(t *testing.T) {
	f := newFixture(t)
	record := f.capture(threadLine(), 0)
	state := fixtureCopy(f.store.captures[record.BindingID])
	binding := &state.Binding
	binding.Status = "refused"
	binding.Streams, binding.Supervisor = []api.CaptureStreamBinding{}, nil
	binding.WorkerLeaseID, binding.EffectID, binding.ProducerID, binding.ProducerGeneration, binding.BootID = "", "", "", "", ""
	binding.Refusal = api.NotImplemented("lb-v2-admin", "capture registration")
	binding.Refusal.OperationID = binding.OperationID
	binding.RefusalPolicy = f.fixtureRefusalPolicy()
	if err := captureDisposition(state, record, f.store.lane, "case-codex", f.store.policy); err != binding.Refusal {
		t.Fatal("matching capture refusal was not preserved", err)
	}
	binding.Target.Run++
	err := captureDisposition(state, record, f.store.lane, "case-codex", f.store.policy)
	if err == binding.Refusal {
		t.Fatal("foreign refused capture chose another launch's error")
	}
	wantCode(t, err, api.CodeIntegrity)
}
