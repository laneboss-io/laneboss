package identity

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func workerConsumerFixture(t *testing.T) (*Service, *fixtureStore, *fixtureConnection) {
	t.Helper()
	s, store, _ := serviceFixture(t)
	record := store.record
	record.Kind = "worker"
	record.Actor = api.Actor{Kind: "worker", ID: "job-principal"}
	store.record = record
	endpoint := fixtureHumanBinding()
	endpoint.Class = api.EndpointWorker
	endpoint.LaunchID = record.ID
	endpoint.Target = &record.Target
	endpoint.WorkerLeaseID = "job-lease"
	connection := fixtureUnboundConnection(t, endpoint)
	facts := api.PeerFacts{HostUID: record.HostUID, HostGID: record.HostUID, HostPID: 42, ProcessGeneration: "boot:descendant", ContainmentID: record.ContainmentID}
	s.deps.Peers = &fixturePeers{peer: &fixturePeer{facts: facts}}
	expiry := timestamp(s.deps.Clock.Now().Add(time.Minute))
	cause := &api.InternalIntent{ID: "job-cause", Kind: api.InternalObjectRetain, Config: record.Config, Actor: api.Actor{Kind: "service", ID: "outbox"}, RequestedBy: api.Actor{Kind: "lane", ID: "requester", LifeID: record.Target.LifeID, Level: 5, Role: "supervisor"},
		Target: record.Target, CauseOperationID: "job-operation", CauseRequestID: "job-request", EffectID: "job-effect", CancellationEpoch: 1}
	lease := api.WorkerLease{ID: endpoint.WorkerLeaseID, Kind: "materialize", Target: record.Target, OperationID: cause.CauseOperationID, EffectID: cause.EffectID, GrantSetID: record.GrantSetID,
		Generation: 1, ExpiresAt: expiry, ConsumedBy: record.ID, Input: api.BlobRef{ID: "job-input", Class: "materialize_input", SHA256: digestBytes([]byte("sealed fixture job")), Bytes: 18}}
	p := api.WorkerPrincipal{StageID: "job-stage", Lease: lease, Record: record, Endpoint: endpoint, Peer: facts, BootID: "boot", AllocationGeneration: 1, CancellationEpoch: 1,
		Claim: api.EffectLease{ClaimID: "job-claim", ExpiresAt: expiry, Record: api.EffectRecord{State: "claimed", Generation: 1, ClaimID: "job-claim", ClaimantID: cause.Actor.ID, ClaimExpiresAt: expiry,
			Effect: api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: cause}}}}
	store.worker = &p
	s.deps.Registry.(*fixtureContainmentRegistry).binding = api.ContainmentBinding{Config: record.Config, Target: record.Target, Backend: endpoint.Backend, BootID: p.BootID, Generation: 1,
		Lease: api.HelperLease{ID: record.UIDLeaseID, UID: facts.HostUID, GID: facts.HostGID, ContainmentID: record.ContainmentID, EndpointGeneration: record.EndpointGeneration}}
	return s, store, connection
}

func TestWorkerConsumerFixture(t *testing.T) {
	for _, rule := range []string{"valid", "lease", "peer", "claim", "boot", "registry", "revoked", "life-label"} {
		t.Run(rule, func(t *testing.T) {
			s, store, connection := workerConsumerFixture(t)
			want := api.CodeInvalid
			switch rule {
			case "lease":
				store.worker.Lease.ID = "foreign-lease"
			case "peer":
				store.worker.Peer.ProcessGeneration = "foreign-generation"
			case "claim":
				store.worker.Claim.ClaimID = "foreign-claim"
			case "boot":
				store.worker.BootID = "foreign-boot"
				want = api.CodeContainmentUnknown
			case "registry":
				s.deps.Registry.(*fixtureContainmentRegistry).binding.Lease.UID++
				want = api.CodeContainmentUnknown
			case "revoked":
				store.worker.Record.Revoked = true
			case "life-label":
				store.worker.Record.Actor.LifeID = store.worker.Lease.Target.LifeID
				want = api.CodeContainmentUnknown
			}
			scope, err := s.Authenticate(context.Background(), connection)
			if rule != "valid" {
				fixtureCode(t, err, want)
				if !reflect.DeepEqual(scope, api.Scope{}) || connection.closes != 1 {
					t.Fatal("fixture check: refused worker retained authority or connection")
				}
				return
			}
			if err != nil || scope.Actor != store.worker.Record.Actor || scope.Actor.Kind != "worker" || scope.Actor.Level != 0 || scope.Actor.Role != "" || scope.Actor == store.worker.Claim.Record.Effect.Context.RequestedBy || scope.Connection != connection {
				t.Fatalf("fixture check: protected worker mapping was refused or relabelled: %v", err)
			}
		})
	}
}

func TestWorkerOperationFixture(t *testing.T) {
	for _, rule := range []string{"input", "input-lease", "inject", "public", "proof", "frame", "result-frame", "result-hash", "claim-drift"} {
		t.Run(rule, func(t *testing.T) {
			s, store, connection := workerConsumerFixture(t)
			scope, err := s.Authenticate(context.Background(), connection)
			if err != nil {
				t.Fatalf("fixture setup: worker connection refused: %v", err)
			}
			method := api.Method(api.WorkerInputRead)
			body := any(api.WorkerInputRequest{LeaseID: store.worker.Lease.ID})
			if rule == "inject" {
				method = api.Method(api.WorkerCredentialInject)
			}
			if rule == "public" {
				method = "records.list"
			}
			if rule == "input-lease" {
				body = api.WorkerInputRequest{LeaseID: "foreign-lease"}
			}
			if rule == "result-frame" || rule == "result-hash" {
				method = api.Method(api.WorkerResultAppend)
				body = api.WorkerResultSubmission{LeaseID: store.worker.Lease.ID, ExpectedGeneration: 1, InputSHA256: store.worker.Lease.Input.SHA256, Result: []byte("actual output fixture")}
				if rule == "result-hash" {
					altered := body.(api.WorkerResultSubmission)
					altered.InputSHA256 = digestBytes([]byte("foreign sealed input"))
					body = altered
				}
			}
			scope = fixtureRequest(t, scope, method, body)
			if rule == "proof" {
				scope.Request.Proof = &api.ProofRef{ID: "borrowed-proof", RequestSHA256: scope.Request.RequestSHA256}
				scope.Frame = &fixtureFrame{raw: launchJSON(t, scope.Request)}
			}
			if rule == "frame" || rule == "result-frame" {
				changed := scope.Request
				changed.Params = launchJSON(t, api.WorkerInputRequest{LeaseID: "foreign-lease"})
				scope.Frame = &fixtureFrame{raw: launchJSON(t, changed)}
			}
			if rule == "claim-drift" {
				store.worker.Claim.ClaimID = "changed-claim"
			}
			err = s.Authorize(context.Background(), scope, scope.Request)
			switch rule {
			case "inject", "claim-drift":
				fixtureCode(t, err, api.CodeInvalid)
			case "public", "proof", "input-lease", "result-hash":
				fixtureCode(t, err, api.CodeForbidden)
			case "frame", "result-frame":
				fixtureCode(t, err, api.CodeIntegrity)
			default:
				if err != nil || scope.Actor.Kind != "worker" || scope.Frame.(*fixtureFrame).verifies != 1 {
					t.Fatalf("fixture check: current private worker operation refused: %v", err)
				}
			}
		})
	}
}
