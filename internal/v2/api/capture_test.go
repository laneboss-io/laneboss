package api

import "testing"

func refusedCapture(binding CaptureBinding) CaptureBinding {
	binding.RefusalPolicy = &CaptureRefusalPolicy{Allowed: true, PolicyGeneration: 3, ApprovalID: "capture-approval"}
	binding.Status = "refused"
	binding.WorkerLeaseID, binding.EffectID, binding.ProducerID, binding.ProducerGeneration, binding.BootID = "", "", "", "", ""
	binding.Supervisor, binding.Streams = nil, []CaptureStreamBinding{}
	binding.Refusal = NotImplemented("lb-v2-admin", "capture registration")
	binding.Refusal.OperationID = binding.OperationID
	return binding
}

func TestCaptureBindingShape(t *testing.T) {
	registered := launchFixture(t).Capture
	if err := ValidateCaptureBinding(registered); err != nil {
		t.Fatal(err)
	}
	refused := refusedCapture(registered)
	if err := ValidateCaptureBinding(refused); err != nil {
		t.Fatal(err)
	}
	for _, code := range []ErrorCode{CodeUnavailable, CodeUnsupported} {
		changed := refusedCapture(registered)
		changed.Refusal.Code = code
		if err := ValidateCaptureBinding(changed); err != nil {
			t.Fatal(err)
		}
	}
	p := launchFixture(t)
	p.Capture = refused
	p.CapturePolicy = &EffectivePolicy{Generation: 3, AllowCaptureRefusal: true, CaptureRefusalApprovalID: "capture-approval"}
	if err := ValidateLaunchPlan(p); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CaptureBinding){
		"missing_status":       func(b *CaptureBinding) { b.Status = "" },
		"missing_producer":     func(b *CaptureBinding) { b.ProducerID = "" },
		"missing_boot":         func(b *CaptureBinding) { b.BootID = "" },
		"missing_lease":        func(b *CaptureBinding) { b.WorkerLeaseID = "" },
		"missing_supervisor":   func(b *CaptureBinding) { b.Supervisor = nil },
		"missing_stderr":       func(b *CaptureBinding) { b.Streams = b.Streams[:1] },
		"shared_pipe":          func(b *CaptureBinding) { b.Streams[1].PipeID = b.Streams[0].PipeID },
		"duplicate_stream":     func(b *CaptureBinding) { b.Streams[1].Stream = "stdout" },
		"unknown_stream":       func(b *CaptureBinding) { b.Streams[1].Stream = "caller-fd" },
		"false_refusal":        func(b *CaptureBinding) { *b = refusedCapture(*b); b.Refusal = nil },
		"fallback":             func(b *CaptureBinding) { *b = refusedCapture(*b); b.Refusal.Code = CodeIntegrity },
		"no_policy":            func(b *CaptureBinding) { *b = refusedCapture(*b); b.RefusalPolicy = nil },
		"foreign_refusal":      func(b *CaptureBinding) { *b = refusedCapture(*b); b.Refusal.OperationID = "other-operation" },
		"refused_with_streams": func(b *CaptureBinding) { *b = refusedCapture(*b); b.Streams = registered.Streams },
	} {
		t.Run(name, func(t *testing.T) {
			b := launchFixture(t).Capture
			change(&b)
			requireLaunchInvalid(t, ValidateCaptureBinding(b), "invalid capture disposition accepted")
		})
	}
}

func TestCaptureRefusalPolicy(t *testing.T) {
	b := refusedCapture(launchFixture(t).Capture)
	policy := EffectivePolicy{Generation: 3, AllowCaptureRefusal: true, CaptureRefusalApprovalID: "capture-approval"}
	if err := ValidateCapturePolicy(b, policy); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"disabled", "approval", "generation"} {
		t.Run(fault, func(t *testing.T) {
			changed := policy
			switch fault {
			case "disabled":
				changed.AllowCaptureRefusal = false
			case "approval":
				changed.CaptureRefusalApprovalID = "other-approval"
			case "generation":
				changed.Generation++
			}
			requireLaunchInvalid(t, ValidateCapturePolicy(b, changed), "unapproved capture refusal accepted")
		})
	}
}

func TestCaptureProducerGate(t *testing.T) {
	b, r := captureAppendFixture(t)
	if !validCaptureProducer(b, r) {
		t.Fatal("registered producer was refused")
	}
	b.Status = "refused"
	if validCaptureProducer(b, r) {
		t.Fatal("refused capture producer was admitted")
	}
}

func captureAppendFixture(t *testing.T) (CaptureBinding, CaptureAppendRequest) {
	t.Helper()
	b := launchFixture(t).Capture
	data := launchFixtureBlob("capture-chunk", "capture")
	return b, CaptureAppendRequest{BindingID: b.ID, ExpectedGeneration: 1, StreamID: b.Streams[0].ID, Data: &data,
		Intent: InternalIntent{ID: "append-intent", Kind: InternalCaptureAppend, Config: b.Config,
			Actor: Actor{Kind: "worker", ID: b.ProducerID}, RequestedBy: b.RequestedBy, Target: b.Target,
			CauseOperationID: b.OperationID, CauseRequestID: b.RequestID, EffectID: b.EffectID}}
}

func TestCaptureAppendCorrelation(t *testing.T) {
	b, request := captureAppendFixture(t)
	if err := ValidateCaptureAppend(b, request); err != nil {
		t.Fatal(err)
	}
	eof := request
	eof.Data, eof.EOF = nil, true
	if err := ValidateCaptureAppend(b, eof); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CaptureAppendRequest){
		"binding":              func(r *CaptureAppendRequest) { r.BindingID = "foreign-binding" },
		"producer":             func(r *CaptureAppendRequest) { r.Intent.Actor.ID = "foreign-producer" },
		"lane_actor":           func(r *CaptureAppendRequest) { r.Intent.Actor.Kind = "lane" },
		"requester":            func(r *CaptureAppendRequest) { r.Intent.RequestedBy.ID = "foreign-requester" },
		"operation":            func(r *CaptureAppendRequest) { r.Intent.CauseOperationID = "foreign-operation" },
		"request":              func(r *CaptureAppendRequest) { r.Intent.CauseRequestID = "foreign-request" },
		"run":                  func(r *CaptureAppendRequest) { r.Intent.Target.Run++ },
		"effect":               func(r *CaptureAppendRequest) { r.Intent.EffectID = "foreign-effect" },
		"stream":               func(r *CaptureAppendRequest) { r.StreamID = "foreign-stream" },
		"generation":           func(r *CaptureAppendRequest) { r.ExpectedGeneration = 0 },
		"negative_offset":      func(r *CaptureAppendRequest) { r.Offset = -1 },
		"range_overflow":       func(r *CaptureAppendRequest) { r.Offset = launchMaxInteger },
		"wrong_class":          func(r *CaptureAppendRequest) { r.Data.Class = "report" },
		"empty_chunk":          func(r *CaptureAppendRequest) { r.Data.Bytes = 0 },
		"unbounded_chunk":      func(r *CaptureAppendRequest) { r.Data.Bytes = MaxChunkBytes + 1 },
		"eof_data":             func(r *CaptureAppendRequest) { r.EOF = true },
		"neither_eof_nor_data": func(r *CaptureAppendRequest) { r.Data = nil },
	} {
		t.Run(name, func(t *testing.T) {
			binding, r := captureAppendFixture(t)
			change(&r)
			requireLaunchInvalid(t, ValidateCaptureAppend(binding, r), "uncorrelated capture append accepted")
		})
	}
	t.Run("refused", func(t *testing.T) {
		requireLaunchInvalid(t, ValidateCaptureAppend(refusedCapture(b), request), "refused capture accepted primary bytes")
	})
}

func TestLaunchPlanEffectUnion(t *testing.T) {
	p := launchFixture(t)
	cause := InternalIntent{ID: "plan-intent", Kind: InternalLaunchPlan, Config: p.Reservation.Config, Target: p.Reservation.Target,
		EffectID: "plan-effect", CauseOperationID: p.Reservation.OperationID}
	tx := Transaction{Scope: Scope{Config: cause.Config}, Internal: &cause,
		Effects: []Effect{{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, PlanLaunch: &LaunchPlanEffect{ReservationID: p.Reservation.ID}}}}
	if err := ValidateTransactionShape(tx); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"empty_reservation", "other_kind", "second_payload"} {
		t.Run(fault, func(t *testing.T) {
			changedCause := cause
			changedEffect := tx.Effects[0]
			changedEffect.Context = &changedCause
			switch fault {
			case "empty_reservation":
				changedEffect.PlanLaunch = &LaunchPlanEffect{}
			case "other_kind":
				changedCause.Kind = InternalObjectRetain
			case "second_payload":
				changedEffect.Worker = &WorkerPlan{}
			}
			changed := tx
			changed.Effects = []Effect{changedEffect}
			if ValidateTransactionShape(changed) == nil {
				t.Fatal("invalid launch-plan effect union accepted")
			}
		})
	}
}
