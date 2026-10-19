package claudock

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func (f *runnerFixture) launchRecord(t *testing.T) (LaunchSelector, api.LaunchPlanRecord) {
	t.Helper()
	selector, err := f.launch.selectRun(context.Background(), f.request.Target)
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.launch.LaunchPlan(context.Background(), selector.Scope, selector.ReservationID)
	if err != nil {
		t.Fatal(err)
	}
	return selector, record
}

func (f *runnerFixture) editStart(t *testing.T, record *api.LaunchPlanRecord, edit func(*api.StartRequest)) {
	t.Helper()
	selector, _ := f.launchRecord(t)
	r := &record.Reservation
	data, err := f.service.objectBytes(context.Background(), selector.Scope, r.OriginalRequest, "launch_request", r.OperationID, "")
	if err != nil {
		t.Fatal(err)
	}
	var original api.Request
	if err := api.DecodeObject(data, &original); err != nil {
		t.Fatal(err)
	}
	var start api.StartRequest
	if err := api.DecodeObject(original.Params, &start); err != nil {
		t.Fatal(err)
	}
	edit(&start)
	original.Params, err = json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	original.RequestSHA256, err = api.RequestDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	id, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	r.RequestSHA256 = original.RequestSHA256
	r.OriginalRequest = f.launch.object(api.ID("original-edit-"+id), "launch_request", data, r.OperationID, "")
	f.launch.write("plan-"+string(r.ID), *record)
}

func refusalFixture(t *testing.T) *runnerFixture {
	t.Helper()
	return runnerSetupWith(t, func(f *runnerFixture) {
		selector, _ := f.launchRecord(t)
		policy, err := f.launch.Policy(context.Background(), selector.Scope)
		if err != nil {
			t.Fatal(err)
		}
		policy.AllowCaptureRefusal, policy.CaptureRefusalApprovalID = true, "capture-approval"
		f.launch.write("policy", policy)
	})
}

// Retain the same explicit refused disposition in the plan, spec, prepared
// identity recovery and journal. This synthetic stopped fixture attests no
// producer, pipe, primary bytes, consumed D6 approval or live kernel state.
func (f *runnerFixture) refuseCapture(t *testing.T) api.CaptureBinding {
	t.Helper()
	selector, record := f.launchRecord(t)
	policy, err := f.launch.Policy(context.Background(), selector.Scope)
	if err != nil {
		t.Fatal(err)
	}
	binding := record.Plan.Capture
	binding.Status, binding.WorkerLeaseID, binding.EffectID, binding.ProducerID, binding.ProducerGeneration, binding.BootID = "refused", "", "", "", "", ""
	binding.Supervisor, binding.Streams = nil, []api.CaptureStreamBinding{}
	binding.RefusalPolicy = &api.CaptureRefusalPolicy{Allowed: true, PolicyGeneration: policy.Generation, ApprovalID: policy.CaptureRefusalApprovalID}
	binding.Refusal = api.NotImplemented("lb-v2-admin", "capture producer unavailable")
	binding.Refusal.OperationID = binding.OperationID
	record.Plan.Capture, record.Plan.CapturePolicy = binding, &policy
	record.Handoff.Spec.Capture = &binding
	sum, data := fixtureHash(t, record.Handoff.Spec)
	id, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	record.Handoff.SpecSHA256 = sum
	record.Handoff.Original = f.launch.object(api.ID("refused-spec-"+id), "launch_spec", data, record.Reservation.OperationID, record.Reservation.Target.LifeID)
	identity, err := f.launch.LaunchBinding(context.Background(), record.Reservation.LaunchID)
	if err != nil {
		t.Fatal(err)
	}
	identity.Prepared.SpecSHA256 = sum
	identity.Recovery.Handoff, identity.Recovery.Capture = *record.Handoff, binding
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		t.Fatal("refused fixture failed the real plan validator", err)
	}
	if err := api.ValidateLaunchBindingPlan(identity, *record.Plan); err != nil {
		t.Fatal("refused fixture failed the real prepared-binding validator", err)
	}
	f.launch.write("binding-"+string(record.Reservation.LaunchID), identity)
	f.launch.write("plan-"+string(selector.ReservationID), record)
	f.launch.write("capture-"+string(binding.ID), api.CaptureState{Binding: binding, Generation: 2, Positions: []api.CapturePosition{}, LastSeq: 11})
	return binding
}

func TestReservedChildPins(t *testing.T) {
	for _, field := range []string{"level", "role", "reservation-driver", "original-driver"} {
		t.Run(field, func(t *testing.T) {
			f := runnerSetup(t)
			if _, err := f.service.planning(context.Background(), f.request, "start"); err != nil {
				t.Fatal("reserved child control failed", err)
			}
			_, record := f.launchRecord(t)
			record.Phase, record.Plan, record.Handoff = "sourced", nil, nil
			switch field {
			case "level":
				record.Reservation.Level++
			case "role":
				record.Reservation.Role = "reviewer"
			case "reservation-driver":
				record.Reservation.Driver = api.DriverCodex
			case "original-driver":
				f.editStart(t, &record, func(start *api.StartRequest) { start.Driver = api.DriverCodex })
			}
			f.launch.write("plan-"+string(record.Reservation.ID), record)
			_, err := f.service.planning(context.Background(), f.request, "start")
			expected := "original start differs from the reserved child pins"
			if field == "reservation-driver" {
				expected = "runner reservation selects a different driver"
			}
			launchReason(t, err, expected, "reserved child pin was not enforced: "+field)
		})
	}
}

func TestPinnedIdentitySurvivesTurns(t *testing.T) {
	f := runnerSetupWith(t, func(f *runnerFixture) {
		_, record := f.launchRecord(t)
		record.Reservation.Level, record.Reservation.Role = 4, "reviewer"
		f.editStart(t, &record, func(start *api.StartRequest) {
			start.Level, start.Role = record.Reservation.Level, record.Reservation.Role
		})
	})
	f.history(t)
	for index, method := range []string{"start", "resume", "turn"} {
		operation := f.service.Start
		if index > 0 {
			f.request.Target.Run++
			f.sourceLaunch(t, method)
			operation = f.service.Resume
			if method == "turn" {
				operation = f.service.Turn
			}
		}
		plan, err := operation(context.Background(), f.request)
		if err != nil {
			t.Fatal("pinned identity could not produce the reserved plan", method, err)
		}
		if index > 0 {
			f.opened(t, plan)
		}
		_, record := f.launchRecord(t)
		inputs, err := f.service.planning(context.Background(), f.request, method)
		if err != nil || inputs.record.Reservation.Level != record.Reservation.Level || inputs.record.Reservation.Role != record.Reservation.Role ||
			inputs.record.Reservation.Driver != record.Reservation.Driver || inputs.record.Reservation.Authority != record.Reservation.Authority {
			t.Fatal("planning replaced the retained child pins", method, err)
		}
		identity, err := f.launch.LaunchBinding(context.Background(), record.Reservation.LaunchID)
		if err != nil || record.Reservation.Level != 4 || record.Reservation.Role != "reviewer" || record.Reservation.Driver != api.DriverClaudock ||
			identity.Record.Kind != "agent" || identity.Record.Actor.Level != record.Reservation.Level || identity.Record.Actor.Role != record.Reservation.Role || plan.Driver != record.Reservation.Driver {
			t.Fatal("retained binding lost the reservation identity", method, err)
		}
	}
}

func TestContinuationChildPins(t *testing.T) {
	for _, method := range []string{"resume", "turn"} {
		for _, field := range []string{"level", "role"} {
			t.Run(method+"/"+field, func(t *testing.T) {
				f := runnerSetup(t)
				f.history(t)
				f.request.Target.Run = 2
				f.sourceLaunch(t, method)
				if _, err := f.service.planning(context.Background(), f.request, method); err != nil {
					t.Fatal("continuation pin control failed", err)
				}
				_, record := f.launchRecord(t)
				if field == "level" {
					record.Reservation.Level++
				} else {
					record.Reservation.Role = "reviewer"
				}
				f.launch.write("plan-"+string(record.Reservation.ID), record)
				_, err := f.service.planning(context.Background(), f.request, method)
				launchReason(t, err, "runner continuation changed its reserved level or role", "continuation changed the reserved child pin: "+field)
			})
		}
	}
}

func TestCaptureRefusalCurrentPolicy(t *testing.T) {
	for _, field := range []string{"disabled", "approval", "generation", "missing-approval"} {
		t.Run(field, func(t *testing.T) {
			f := refusalFixture(t)
			binding := f.refuseCapture(t)
			selector, _ := f.launchRecord(t)
			if err := f.service.refusalPolicy(context.Background(), selector.Scope, binding); err != nil {
				t.Fatal("approved refusal policy control failed", err)
			}
			if _, err := f.service.Start(context.Background(), f.request); err != nil {
				t.Fatal("approved isolated start was not retained", err)
			}
			policy, err := f.launch.Policy(context.Background(), selector.Scope)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "disabled":
				policy.AllowCaptureRefusal = false
			case "approval":
				policy.CaptureRefusalApprovalID = "other-approval"
			case "generation":
				policy.Generation++
			case "missing-approval":
				policy.CaptureRefusalApprovalID = ""
			}
			f.launch.write("policy", policy)
			err = f.service.refusalPolicy(context.Background(), selector.Scope, binding)
			launchReason(t, err, "capture refusal is not enabled by current D6 policy", "current capture refusal policy was bypassed: "+field)
			if _, err := f.service.planning(context.Background(), f.request, "start"); err == nil {
				t.Fatal("retained plan snapshot enabled an unauthorized refusal", field)
			}
		})
	}
}

func TestCaptureRefusalSnapshot(t *testing.T) {
	for _, field := range []string{"snapshot", "metadata", "allowed", "approval", "generation"} {
		t.Run(field, func(t *testing.T) {
			f := refusalFixture(t)
			f.refuseCapture(t)
			selector, record := f.launchRecord(t)
			if _, _, err := f.service.retainedLaunch(context.Background(), f.request.Target); err != nil {
				t.Fatal("retained refusal snapshot control failed", err)
			}
			switch field {
			case "snapshot":
				record.Plan.CapturePolicy = nil
			case "metadata":
				record.Plan.Capture.RefusalPolicy = nil
			case "allowed":
				record.Plan.Capture.RefusalPolicy.Allowed = false
			case "approval":
				record.Plan.Capture.RefusalPolicy.ApprovalID = ""
			case "generation":
				record.Plan.Capture.RefusalPolicy.PolicyGeneration = 0
			}
			f.launch.write("plan-"+string(selector.ReservationID), record)
			_, _, err := f.service.retainedLaunch(context.Background(), f.request.Target)
			if err == nil {
				t.Fatal("retained capture refusal omitted required metadata: " + field)
			}
		})
	}
}

func TestCapturePolicyReplaySeal(t *testing.T) {
	f := runnerSetup(t)
	if _, err := f.service.Start(context.Background(), f.request); err != nil {
		t.Fatal("capture policy replay control failed", err)
	}
	selector, _ := f.launchRecord(t)
	policy, err := f.launch.Policy(context.Background(), selector.Scope)
	if err != nil {
		t.Fatal(err)
	}
	policy.AllowCaptureRefusal, policy.CaptureRefusalApprovalID = true, "capture-approval"
	f.launch.write("policy", policy)
	_, err = f.service.Start(context.Background(), f.request)
	launchReason(t, err, "launch replay changed its immutable inputs", "replay discarded changed capture policy inputs")
}

func TestRefusedCaptureBlocksContinuation(t *testing.T) {
	for _, method := range []string{"resume", "turn"} {
		t.Run(method, func(t *testing.T) {
			f := refusalFixture(t)
			f.history(t)
			binding := f.refuseCapture(t)
			f.request.Target.Run = 2
			f.sourceLaunch(t, method)
			_, err := f.service.planning(context.Background(), f.request, method)
			launchReason(t, err, binding.Refusal.Message, "refused prior capture authorized continuation")
		})
	}
}

func TestCurrentRefusalBlocksContinuation(t *testing.T) {
	for _, method := range []string{"resume", "turn"} {
		t.Run(method, func(t *testing.T) {
			f := refusalFixture(t)
			f.history(t)
			f.request.Target.Run = 2
			f.sourceLaunch(t, method)
			operation := f.service.Resume
			if method == "turn" {
				operation = f.service.Turn
			}
			plan, err := operation(context.Background(), f.request)
			if err != nil {
				t.Fatal("registered continuation control failed", err)
			}
			f.opened(t, plan)
			binding := f.refuseCapture(t)
			_, err = f.service.planning(context.Background(), f.request, method)
			launchReason(t, err, binding.Refusal.Message, "current refused capture authorized continuation")
		})
	}
}

type policyBarrier struct {
	api.StateStore
	err error
}

func (p policyBarrier) Policy(context.Context, api.Scope) (api.EffectivePolicy, error) {
	return api.EffectivePolicy{}, p.err
}

func TestRefusalNeedsCurrentPolicyPort(t *testing.T) {
	f := refusalFixture(t)
	capture := f.setCapture(encodeEvent(t, f.initEvent()), "stdout")
	f.refuseCapture(t)
	refusal := api.NotImplemented("lb-v2-service", "store.Policy")
	f.service.deps.State = policyBarrier{StateStore: f.launch, err: refusal}
	_, err := f.service.SessionFromCapture(context.Background(), capture)
	if err != refusal {
		t.Fatal("capture refusal bypassed the current policy port", err)
	}
}

func TestRefusedCaptureRechecksPolicy(t *testing.T) {
	f := refusalFixture(t)
	capture := f.setCapture(encodeEvent(t, f.initEvent()), "stdout")
	binding := f.refuseCapture(t)
	_, err := f.service.SessionFromCapture(context.Background(), capture)
	launchReason(t, err, binding.Refusal.Message, "approved refused capture was not kept unavailable")
	selector, _ := f.launchRecord(t)
	policy, err := f.launch.Policy(context.Background(), selector.Scope)
	if err != nil {
		t.Fatal(err)
	}
	policy.AllowCaptureRefusal = false
	f.launch.write("policy", policy)
	_, err = f.service.SessionFromCapture(context.Background(), capture)
	launchReason(t, err, "capture refusal is not enabled by current D6 policy", "capture extraction used the stale refusal policy snapshot")
	signal, err := f.service.LimitFromCapture(context.Background(), capture, f.observation)
	if signal != nil {
		t.Fatal("disabled refusal policy produced a quota signal")
	}
	launchReason(t, err, "capture refusal is not enabled by current D6 policy", "quota extraction used the stale refusal policy snapshot")
}

func TestPreparedCaptureBindingRequired(t *testing.T) {
	for _, field := range []string{"kind", "worker", "level", "role", "recovery", "prepared", "missing-binding", "missing-plan"} {
		t.Run(field, func(t *testing.T) {
			f := runnerSetup(t)
			capture := f.setCapture(encodeEvent(t, f.initEvent()), "stdout")
			if _, err := f.service.SessionFromCapture(context.Background(), capture); err != nil {
				t.Fatal("prepared binding control failed", err)
			}
			selector, record := f.launchRecord(t)
			identity, err := f.launch.LaunchBinding(context.Background(), record.Reservation.LaunchID)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "kind":
				identity.Record.Kind = ""
			case "worker":
				identity.Record.Kind = "worker"
			case "level":
				identity.Record.Actor.Level++
			case "role":
				identity.Record.Actor.Role = "reviewer"
			case "recovery":
				identity.Recovery = nil
			case "prepared":
				identity.Prepared.SpecSHA256 = contentDigest([]byte("different prepared spec"))
			case "missing-plan":
				record.Phase, record.Plan, record.Handoff = "sourced", nil, nil
				f.launch.write("plan-"+string(selector.ReservationID), record)
			}
			identity.Identity.RecordSHA256, _ = fixtureHash(t, identity.Record)
			f.launch.write("binding-"+string(record.Reservation.LaunchID), identity)
			if field == "missing-binding" {
				if err := os.Remove(filepath.Join(f.launch.dir, "binding-"+string(record.Reservation.LaunchID)+".json")); err != nil {
					t.Fatal(err)
				}
			}
			_, err = f.service.SessionFromCapture(context.Background(), capture)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code == api.CodeNotImplemented {
				t.Fatal("capture accepted an unbound prepared identity: "+field, err)
			}
			signal, limitErr := f.service.LimitFromCapture(context.Background(), capture, f.observation)
			if signal != nil || !reflect.DeepEqual(limitErr, err) {
				t.Fatal("session and quota disagreed on the prepared binding", field, limitErr)
			}
		})
	}
}
