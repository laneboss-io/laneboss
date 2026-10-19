package admin

import (
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func capturePlanFixture() (captureRegistration, api.HelperLease) {
	cause := testCause(api.InternalLaunchPlan, "life-a")
	cause.CancellationEpoch = 1
	r := api.LaunchReservation{ID: "reservation-a", Config: "admin-case", Mode: "start", Target: cause.Target,
		Level: 3, Role: "executor", Driver: api.DriverCodex, Authority: api.LaunchAuthority{Kind: "ticket", ID: "root-ticket"},
		LaunchID: "launch-a", SpecID: "spec-a", GrantSetID: "grants-a", Generation: 1, PolicyGeneration: 1, CancellationEpoch: 1,
		RootLifeID: "life-a", StarterChain: []api.ID{}, OperationID: cause.CauseOperationID, RequestID: cause.CauseRequestID,
		RequestSHA256: testDigest("request"), RequestedBy: cause.RequestedBy,
		OriginalRequest: api.BlobRef{ID: "request-object", Class: "launch_request", Bytes: 7, SHA256: testDigest("request")}}
	input := []byte(`{"kind":"capture_supervisor"}`)
	worker := api.WorkerLease{ID: "capture-worker", Kind: "capture_supervisor", Target: r.Target, OperationID: r.OperationID,
		EffectID: cause.EffectID, Input: api.BlobRef{ID: "capture-input", Class: "manifest", Bytes: int64(len(input)), SHA256: digestBytes(input)},
		RuntimeManifest: api.BlobRef{ID: "runtime", Class: "manifest", Bytes: 7, SHA256: testDigest("runtime")},
		GrantSetID:      r.GrantSetID, Generation: 1, ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))}
	lease := api.HelperLease{ID: "helper-lease", EndpointGeneration: 1}
	return captureRegistration{Request: api.CaptureRegistrationRequest{Cause: cause, ReservationID: r.ID,
		HelperLeaseID: lease.ID, WorkerLeaseID: worker.ID}, Reservation: r, Worker: worker,
		Policy: api.EffectivePolicy{Generation: 1, AllowCaptureRefusal: true, CaptureRefusalApprovalID: "approved-d6", ProfileExclusions: []api.ID{}, Rules: []api.Rule{}, Skip: []api.SkipEntry{}, Sources: []api.SourceRef{}}}, lease
}

func TestExplicitRefusal(t *testing.T) {
	registration, lease := capturePlanFixture()
	binding, err := refusedCaptureBinding(registration, lease)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Status != "refused" || binding.Refusal == nil || binding.Refusal.OperationID != registration.Reservation.OperationID ||
		len(binding.Streams) != 0 || binding.ProducerID != "" || binding.Supervisor != nil || binding.WorkerLeaseID != "" {
		t.Fatal("acceptance: capture refusal fabricated a producer or omitted its cause")
	}
	if err := api.ValidateCaptureBinding(binding); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"worker", "operation", "requester", "target", "expired", "consumed", "kind", "input", "allocation", "disabled-policy", "approval", "policy-generation"} {
		t.Run(fault, func(t *testing.T) {
			changed, selected := capturePlanFixture()
			switch fault {
			case "worker":
				changed.Request.WorkerLeaseID = "foreign-worker"
			case "operation":
				changed.Worker.OperationID = "foreign-operation"
			case "requester":
				changed.Request.Cause.RequestedBy.ID = "foreign-human"
			case "target":
				changed.Worker.Target.Run++
			case "expired":
				changed.Worker.ExpiresAt = "2000-01-01T00:00:00Z"
			case "consumed":
				changed.Worker.ConsumedBy = "another-job"
			case "kind":
				changed.Worker.Kind = "caller-job"
			case "input":
				changed.Worker.Input.SHA256 = ""
			case "allocation":
				selected.ID = "foreign-lease"
			case "disabled-policy":
				changed.Policy.AllowCaptureRefusal = false
			case "approval":
				changed.Policy.CaptureRefusalApprovalID = ""
			case "policy-generation":
				changed.Policy.Generation++
			}
			result, err := refusedCaptureBinding(changed, selected)
			if err == nil || result.ID != "" {
				t.Fatal("acceptance: capture fallback laundered a guard failure")
			}
		})
	}
}
