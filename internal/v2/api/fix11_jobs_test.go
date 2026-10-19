package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func workerFixture(t *testing.T) WorkerPrincipal {
	t.Helper()
	p := launchFixture(t)
	target := p.Reservation.Target
	lease := WorkerLease{ID: "job-lease", Kind: "materialize", Target: target, OperationID: p.Reservation.OperationID, EffectID: "job-effect",
		Input: contractBlob("job-input", "worker_input", []byte("sealed worker input fixture")), RuntimeManifest: p.Inputs.Sources.Runtime.Manifest, GrantSetID: p.Inputs.Grants.ID,
		Generation: 1, ExpiresAt: contractStamp(contractNow().Add(5 * time.Minute)), ConsumedBy: "worker-launch"}
	record := LaunchRecord{Kind: "worker", ID: lease.ConsumedBy, Config: "demo", Target: target, Actor: Actor{Kind: "worker", ID: "job-principal", LifeID: target.LifeID},
		HostUID: 12002, UIDLeaseID: "worker-uid", ContainmentID: "worker-containment", ProcessGeneration: "worker-leader-generation", GrantSetID: lease.GrantSetID,
		EndpointGeneration: 1, PolicyGeneration: 3, GrantsSHA256: p.Inputs.Grants.SHA256}
	endpoint := InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: ContractRevision, Protocol: Protocol, APISchema: SchemaVersion, Config: "demo",
		Class: EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: 11000, ServiceGID: 11000, Socket: "/runtime/worker.sock",
		ArtifactSHA256: p.Inputs.Sources.Runtime.Manifest.SHA256, ServiceVersion: "fixture", Backend: "linux-bwrap-landlock", LaunchID: record.ID, Target: &target, WorkerLeaseID: lease.ID}
	cause := InternalIntent{ID: "job-cause", Kind: InternalObjectRetain, Config: "demo", Actor: Actor{Kind: "service", ID: "outbox"}, RequestedBy: p.Reservation.RequestedBy,
		Target: target, CauseOperationID: lease.OperationID, CauseRequestID: p.Reservation.RequestID, EffectID: lease.EffectID, CancellationEpoch: 1}
	expiry := contractStamp(contractNow().Add(time.Minute))
	return WorkerPrincipal{StageID: "data-stage", Lease: lease, Record: record, Endpoint: endpoint, Peer: PeerFacts{HostUID: record.HostUID, HostGID: 12002, HostPID: 100, ProcessGeneration: "worker-connector-generation", ContainmentID: record.ContainmentID},
		BootID: "boot-one", AllocationGeneration: 1, CancellationEpoch: 1,
		Claim: EffectLease{ClaimID: "job-claim", ExpiresAt: expiry, Record: EffectRecord{State: "claimed", Generation: 1, ClaimID: "job-claim", ClaimantID: "outbox", ClaimExpiresAt: expiry,
			Effect: Effect{ID: lease.EffectID, OperationID: lease.OperationID, Context: &cause}}}}
}

func TestWorkerBinding(t *testing.T) {
	p := workerFixture(t)
	if err := ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, WorkerInputRead, contractNow()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"lease", "peer", "principal", "endpoint", "expired", "claim", "permission", "capture"} {
		t.Run(fault, func(t *testing.T) {
			p := workerFixture(t)
			e, peer, operation := p.Endpoint, p.Peer, WorkerInputRead
			switch fault {
			case "lease":
				p.Lease.ID = "foreign-lease"
			case "peer":
				p.Peer.ProcessGeneration = "foreign-generation"
			case "principal":
				p.Record.Actor.Kind = "lane"
			case "endpoint":
				p.Record.EndpointGeneration++
			case "expired":
				p.Lease.ExpiresAt = contractStamp(contractNow())
			case "claim":
				p.Claim.ClaimID = "foreign-claim"
			case "permission":
				operation = WorkerCaptureAppend
			case "capture":
				p.Lease.Kind = "capture"
				operation = WorkerCaptureAppend
			}
			requireLaunchInvalid(t, ValidateWorkerPrincipal(p, e, peer, operation, contractNow()), "worker principal mapping was bypassed")
		})
	}
}

func TestWorkerResult(t *testing.T) {
	p := workerFixture(t)
	bytes := []byte("actual bounded worker result bytes")
	// Use the actual result bytes, with the same hashing helper as real objects.
	ref := contractBlob("worker-result", "worker_result", bytes)
	request := WorkerResultSubmission{LeaseID: p.Lease.ID, ExpectedGeneration: 1, InputSHA256: p.Lease.Input.SHA256, Result: bytes}
	receipt := WorkerResultReceipt{LeaseID: p.Lease.ID, StageID: "data-stage", Generation: 2, Result: ref, CommittedSeq: 5}
	if err := ValidateWorkerResult(p, request, receipt, contractNow()); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"input", "bytes", "revision"} {
		t.Run(fault, func(t *testing.T) {
			r, s := request, receipt
			switch fault {
			case "input":
				r.InputSHA256 = launchFixtureBlob("other-input", "worker_input").SHA256
			case "bytes":
				s.Result.SHA256 = launchFixtureBlob("other-result", "worker_result").SHA256
			case "revision":
				s.Generation = 1
			}
			requireLaunchInvalid(t, ValidateWorkerResult(p, r, s, contractNow()), "worker result correlation was bypassed")
		})
	}
}

func TestWorkerInput(t *testing.T) {
	p := workerFixture(t)
	input := WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: p.StageID, LeaseID: p.Lease.ID, Kind: p.Lease.Kind,
		OperationID: p.Lease.OperationID, EffectID: p.Lease.EffectID, Input: p.Lease.Input, Bytes: []byte("sealed worker input fixture")}
	if err := ValidateWorkerInput(p, input, contractNow()); err != nil {
		t.Fatal(err)
	}
	input.StageID = "foreign-stage"
	requireLaunchInvalid(t, ValidateWorkerInput(p, input, contractNow()), "worker input stage was replaced")
}

func revocationFixture(t *testing.T) (LaunchRevocation, TransportInvalidationReceipt) {
	t.Helper()
	p := launchFixture(t)
	record := launchFixtureBinding(t, p).Record
	record.Revoked = true
	_, digest := launchFixtureHash(t, record)
	cause := InternalIntent{ID: "revoke-cause", Kind: InternalLifecycleEffect, Config: record.Config, Actor: Actor{Kind: "service", ID: "lifecycle"}, RequestedBy: p.Reservation.RequestedBy,
		Target: record.Target, CauseOperationID: "stop-operation", CauseRequestID: "stop-request", CancellationEpoch: 2}
	r := LaunchRevocation{Record: record, RecordSHA256: digest, Cause: cause, EventID: "revoke-event", CommittedSeq: 12}
	zero := uint64(0)
	return r, TransportInvalidationReceipt{LaunchID: record.ID, RevocationEventID: r.EventID, OperationID: cause.CauseOperationID,
		RemainingConnections: &zero, RemainingDeliveries: &zero, CompletedAt: contractStamp(contractNow())}
}

func TestRevocationGate(t *testing.T) {
	r, c := revocationFixture(t)
	if err := ValidateTransportInvalidation(r, c); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"record", "operation", "unknown", "survivor", "event"} {
		t.Run(fault, func(t *testing.T) {
			r, c := revocationFixture(t)
			switch fault {
			case "record":
				r.Record.Revoked = false
				_, r.RecordSHA256 = launchFixtureHash(t, r.Record)
			case "operation":
				c.OperationID = "foreign-operation"
			case "unknown":
				c.RemainingConnections = nil
			case "survivor":
				one := uint64(1)
				c.RemainingConnections = &one
			case "event":
				c.RevocationEventID = "foreign-event"
			}
			requireLaunchInvalid(t, ValidateTransportInvalidation(r, c), "causal revocation close gate was bypassed")
		})
	}
}

type retainedPlanSource struct {
	LaunchControlSource
	record LaunchPlanRecord
	err    error
	calls  int
}

func (s *retainedPlanSource) Plan(context.Context, ID) (LaunchPlanRecord, error) {
	s.calls++
	return s.record, s.err
}

func TestPlanReadGate(t *testing.T) {
	p := launchFixture(t)
	s := &retainedPlanSource{record: LaunchPlanRecord{Reservation: p.Reservation, Generation: 1, Phase: "reserved"}}
	if _, err := ReadLaunchPlan(context.Background(), s, p.Reservation.ID); err != nil || s.calls != 1 {
		t.Fatalf("retained source was not called: %v", err)
	}
	s.record.Reservation.ID = "foreign-reservation"
	_, err := ReadLaunchPlan(context.Background(), s, p.Reservation.ID)
	requireLaunchInvalid(t, err, "retained lookup returned a foreign plan")
	sentinel := errors.New("current claim unavailable")
	s.err = sentinel
	if _, err := ReadLaunchPlan(context.Background(), s, p.Reservation.ID); !errors.Is(err, sentinel) {
		t.Fatalf("plan source error was replaced: %v", err)
	}
}

func guidanceClaimFixture(t *testing.T) (GuidanceReservationRequest, GuidanceReservation, GuidanceSelection, InternalIntent) {
	t.Helper()
	p := launchFixture(t)
	r := GuidanceReservation{Config: "demo", ID: "guidance-reservation", Target: p.Reservation.Target, LogicalTurnID: "logical-turn", Task: launchFixtureBlob("guidance-task", "task"),
		PolicyGeneration: 3, CandidateSnapshotID: "candidate-snapshot", TurnGeneration: 1, Generation: 1, ClaimID: "guidance-claim", Status: "pending", Acquired: true,
		OwnerAttemptID: "attempt-a", OwnerOperationID: "guidance-operation", OwnerRequestID: "guidance-request", RequestedBy: p.Reservation.RequestedBy,
		OwnerKey: RequestKey{Method: "guidance.select", IdempotencyKey: "key-a", RequestSHA256: p.Reservation.RequestSHA256}, CancellationEpoch: 1, MaxCostMicros: 100,
		BindingItems: []GuidanceItem{{DecisionID: "binding-one", Binding: true}}, ReservedAt: contractStamp(contractNow()), Deadline: contractStamp(contractNow().Add(5 * time.Second))}
	request := GuidanceReservationRequest{AttemptID: r.OwnerAttemptID, ExpectedTurnGeneration: 1, CancellationEpoch: 1, MaxCostMicros: 100,
		Target: r.Target, LogicalTurnID: r.LogicalTurnID, ExpectedTask: r.Task, PolicyGeneration: 3, CandidateSnapshotID: r.CandidateSnapshotID, Deadline: r.Deadline}
	result := Guidance{ID: "guidance-result", ReservationID: r.ID, Target: r.Target, LogicalTurnID: r.LogicalTurnID, Task: r.Task, PolicyGeneration: 3, CandidateSnapshotID: r.CandidateSnapshotID,
		AsOf: contractStamp(contractNow()), Items: r.BindingItems, Status: "empty"}
	selection := GuidanceSelection{AttemptID: r.OwnerAttemptID, ReservationID: r.ID, ClaimID: r.ClaimID, ExpectedGeneration: 1, Result: result}
	cause := InternalIntent{ID: "guidance-complete", Kind: InternalGuidanceComplete, Config: "demo", Actor: Actor{Kind: "service", ID: "guidance"}, RequestedBy: r.RequestedBy,
		Target: r.Target, LogicalTurnID: r.LogicalTurnID, CauseOperationID: r.OwnerOperationID, CauseRequestID: r.OwnerRequestID, CancellationEpoch: r.CancellationEpoch}
	return request, r, selection, cause
}

func TestGuidanceOwner(t *testing.T) {
	request, r, _, _ := guidanceClaimFixture(t)
	if !GuidanceCanEvaluate(request, r, contractNow()) {
		t.Fatal("atomic winning caller was refused")
	}
	for _, fault := range []string{"replay", "owner", "two_keys"} {
		t.Run(fault, func(t *testing.T) {
			request, r, _, _ := guidanceClaimFixture(t)
			switch fault {
			case "replay":
				r.Acquired = false
			case "owner":
				request.AttemptID = "attempt-b"
			case "two_keys":
				r.Acquired = false
				request.AttemptID = "attempt-b"
			}
			if GuidanceCanEvaluate(request, r, contractNow()) {
				t.Fatal("observed claim became a second evaluator")
			}
		})
	}
}

func TestGuidanceRecovery(t *testing.T) {
	_, r, selection, cause := guidanceClaimFixture(t)
	if err := ValidateGuidanceCompletion(r, selection, cause, contractNow().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	cause.Kind = InternalGuidanceRecover
	selection.Result.Status, selection.Result.Notice = "unavailable", "original evaluator interrupted"
	if err := ValidateGuidanceCompletion(r, selection, cause, contractNow().Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"rejudge", "operation", "early", "binding", "status"} {
		t.Run(fault, func(t *testing.T) {
			_, r, s, c := guidanceClaimFixture(t)
			c.Kind = InternalGuidanceRecover
			s.Result.Status, s.Result.Notice = "unavailable", "original evaluator interrupted"
			now := contractNow().Add(6 * time.Second)
			switch fault {
			case "rejudge":
				s.Result.JudgmentIDs = []ID{"second-judgment"}
			case "operation":
				c.CauseOperationID = "foreign-operation"
			case "early":
				now = contractNow().Add(time.Second)
			case "binding":
				s.Result.Items = nil
			case "status":
				r.Status = "invented"
			}
			requireLaunchInvalid(t, ValidateGuidanceCompletion(r, s, c, now), "guidance recovery boundary was bypassed")
		})
	}
}

func TestGuidanceWrite(t *testing.T) {
	_, r, s, c := guidanceClaimFixture(t)
	raw, err := json.Marshal(s.Result)
	if err != nil {
		t.Fatal(err)
	}
	tx := Transaction{Scope: Scope{Config: "demo"}, Internal: &c, Writes: StateWrites{Guidance: []GuidanceSelection{s}}, Events: []Event{{Kind: "guidance.selected", Payload: raw}},
		Compare: []Compare{{Kind: CompareGuidance, ID: r.ID, Generation: 1}}, Guards: []TransactionGuard{{Cancellation: &CancellationCheck{LifeID: r.Target.LifeID, Epoch: 1}}}}
	if err := ValidateTransactionShape(tx); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"cas", "epoch"} {
		t.Run(fault, func(t *testing.T) {
			changed := tx
			if fault == "cas" {
				changed.Compare = nil
			} else {
				changed.Guards = nil
			}
			var typed *Error
			if err := ValidateTransactionShape(changed); !errors.As(err, &typed) || typed.Code != CodeInvalid {
				t.Fatalf("guidance write lost its claim fence: %v", err)
			}
		})
	}
}
