package identity

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func runningPolicyFixture(t *testing.T) (*Service, *fixtureStore, api.Scope) {
	t.Helper()
	s, store, _ := serviceFixture(t)
	store.record.PolicyGeneration, store.lane.PolicyGeneration = 3, 3
	store.lane.State, store.lane.Generation, store.lane.CancellationEpoch = "running", 7, 1
	store.policy = &api.EffectivePolicy{Generation: 3, SHA256: digestBytes([]byte("approved initial policy"))}
	grants, err := store.Grants(context.Background(), store.record.GrantSetID)
	if err != nil {
		t.Fatal(err)
	}
	store.grants = &grants
	return s, store, fixtureLaneScope(t, s, store, store.record.Actor.Level)
}

func TestLanePolicyAdvanceFixture(t *testing.T) {
	ctx := context.Background()
	s, store, original := runningPolicyFixture(t)
	connection := original.Connection.(*fixtureConnection)
	peer := connection.Peer()
	recordBytes, grantBytes := launchJSON(t, store.record), launchJSON(t, *store.grants)
	bindingBytes := launchJSON(t, connection.Binding())
	assertRunning := func(scope api.Scope) {
		t.Helper()
		requestScope := fixtureRequest(t, scope, "identity.self", api.Empty{})
		if err := s.Authorize(ctx, requestScope, requestScope.Request); err != nil {
			t.Fatalf("fixture check: running lane request refused under current policy: %v", err)
		}
		projection, err := s.IdentitySelf(ctx, requestScope, api.Empty{})
		if err != nil || projection.PolicyGeneration != store.policy.Generation || projection.Actor != original.Actor ||
			projection.LaunchID != original.LaunchID || projection.Connection != nil || projection.Frame != nil {
			t.Fatalf("fixture check: running lane self lost the current policy: %v", err)
		}
	}
	assertRunning(original)

	// The approved D6 policy advances while the same authenticated process and
	// connection still run under their immutable generation-3 launch and grants.
	store.policy = &api.EffectivePolicy{Generation: store.policy.Generation + 1,
		SHA256: digestBytes([]byte("approved D6 policy change"))}
	current, err := s.connectionScope(ctx, connection)
	if err != nil || current.PolicyGeneration != store.policy.Generation || current.Connection != connection {
		t.Fatalf("fixture check: running lane did not resolve the advanced policy: %v", err)
	}
	assertRunning(current)
	stale := fixtureRequest(t, original, "identity.self", api.Empty{})
	fixtureCode(t, s.Authorize(ctx, stale, stale.Request), api.CodeConflict)

	// Model only the coordinator's protected projection update, and validate
	// its actual shared contract before presenting it to the identity consumer.
	before := cloneLaunchValue(t, store.lane)
	request := api.PolicyAdvanceRequest{Target: store.record.Target, ExpectedLaneGeneration: before.Generation,
		FromGeneration: before.PolicyGeneration, ToGeneration: store.policy.Generation, CancellationEpoch: before.CancellationEpoch}
	after := cloneLaunchValue(t, before)
	after.Generation++
	after.PolicyGeneration = store.policy.Generation
	after.LastSeq = before.LastSeq + 1
	receipt := api.PolicyAdvanceReceipt{Changed: true, Lane: after, EventID: "policy-event", CommittedSeq: after.LastSeq,
		Event: api.PolicyAdvanceEvent{FromGeneration: before.PolicyGeneration, ToGeneration: after.PolicyGeneration,
			LaneGeneration: after.Generation, PolicySHA256: store.policy.SHA256, GrantSetID: before.GrantSetID}}
	if err := api.ValidatePolicyAdvance(before, request, *store.policy, receipt); err != nil {
		t.Fatalf("fixture setup: coordinator policy projection is invalid: %v", err)
	}
	store.lane = receipt.Lane
	refreshed, err := s.connectionScope(ctx, connection)
	if err != nil || refreshed.PolicyGeneration != current.PolicyGeneration || refreshed.Actor != current.Actor {
		t.Fatalf("fixture check: refreshed lane projection invalidated its running launch: %v", err)
	}
	assertRunning(refreshed)
	if !bytes.Equal(recordBytes, launchJSON(t, store.record)) || !bytes.Equal(grantBytes, launchJSON(t, *store.grants)) ||
		!bytes.Equal(bindingBytes, launchJSON(t, connection.Binding())) || connection.Peer() != peer || connection.closes != 0 ||
		store.transaction != nil {
		t.Fatal("fixture check: policy advance rewrote historical authority or replaced the running connection")
	}
}

func TestLanePolicyBoundsFixture(t *testing.T) {
	for _, rule := range []string{"record-future", "record-zero", "projection-before-record", "projection-future", "missing-policy", "revoked-grants", "issued-generation", "grant-digest", "expired-grants"} {
		t.Run(rule, func(t *testing.T) {
			s, store, scope := runningPolicyFixture(t)
			store.policy.Generation++
			want := api.CodeUnauthenticated
			switch rule {
			case "record-future":
				store.record.PolicyGeneration = store.policy.Generation + 1
				store.grants.PolicyGeneration = store.record.PolicyGeneration
			case "record-zero":
				store.record.PolicyGeneration, store.grants.PolicyGeneration = 0, 0
			case "projection-before-record":
				store.lane.PolicyGeneration = store.record.PolicyGeneration - 1
			case "projection-future":
				store.lane.PolicyGeneration = store.policy.Generation + 1
			case "missing-policy":
				store.policy.Generation = 0
			case "revoked-grants":
				store.grants.Revoked, want = true, api.CodeForbidden
			case "issued-generation":
				store.grants.PolicyGeneration, want = store.policy.Generation, api.CodeForbidden
			case "grant-digest":
				store.grants.SHA256, want = digestBytes([]byte("changed issued grants")), api.CodeForbidden
			case "expired-grants":
				store.grants.ExpiresAt, want = timestamp(s.deps.Clock.Now()), api.CodeForbidden
			}
			got, err := s.connectionScope(context.Background(), scope.Connection)
			fixtureCode(t, err, want)
			if !reflect.DeepEqual(got, api.Scope{}) {
				t.Fatal("fixture check: invalid historical or current policy retained lane authority")
			}
		})
	}
}

// This isolated consumer check keeps an independent currentLaunch bound from
// concealing a missing grant/current-policy check in an omission control.
func TestIssuedGrantPolicyFixture(t *testing.T) {
	for _, rule := range []string{"current", "advanced", "future", "missing", "revoked", "expired", "issued-generation"} {
		t.Run(rule, func(t *testing.T) {
			s, store, scope := serviceFixture(t)
			store.record.PolicyGeneration, scope.PolicyGeneration = 3, 3
			store.policy = &api.EffectivePolicy{Generation: store.record.PolicyGeneration}
			grants, err := store.Grants(context.Background(), store.record.GrantSetID)
			if err != nil {
				t.Fatal(err)
			}
			store.grants = &grants
			switch rule {
			case "advanced":
				store.policy.Generation++
			case "future":
				store.policy.Generation--
			case "missing":
				store.policy.Generation = 0
			case "revoked":
				store.grants.Revoked = true
			case "expired":
				store.grants.ExpiresAt = timestamp(s.deps.Clock.Now().Add(-time.Second))
			case "issued-generation":
				store.grants.PolicyGeneration++
			}
			err = s.checkGrants(context.Background(), scope, store.record)
			if rule == "current" || rule == "advanced" {
				if err != nil {
					t.Fatalf("fixture check: historical issued grants were refused under current policy: %v", err)
				}
				return
			}
			errorCode(t, err, api.CodeForbidden)
		})
	}
}

func TestScopePolicyChangeFixture(t *testing.T) {
	for _, kind := range []string{"human", "worker"} {
		t.Run(kind, func(t *testing.T) {
			for _, change := range []string{"generation", "identity-and-generation"} {
				t.Run(change, func(t *testing.T) {
					s, store, _ := serviceFixture(t)
					var scope api.Scope
					method, body := api.Method("human.challenge"), any(api.HumanChallengeRequest{})
					if kind == "worker" {
						var connection *fixtureConnection
						s, store, connection = workerConsumerFixture(t)
						store.policy = &api.EffectivePolicy{Generation: 3}
						var err error
						scope, err = s.Authenticate(context.Background(), connection)
						if err != nil {
							t.Fatalf("fixture setup: worker policy scope failed: %v", err)
						}
						method, body = api.Method(api.WorkerInputRead), api.WorkerInputRequest{LeaseID: store.worker.Lease.ID}
					} else {
						store.policy = &api.EffectivePolicy{Generation: 3}
						scope = fixtureHumanScope(t, s, store)
					}
					scope = fixtureRequest(t, scope, method, body)
					if err := s.Authorize(context.Background(), scope, scope.Request); err != nil {
						t.Fatalf("fixture setup: current policy request failed: %v", err)
					}
					store.policy.Generation++
					want := api.CodeConflict
					if change == "identity-and-generation" {
						scope.Actor.ID, want = "foreign-principal", api.CodeUnauthenticated
					}
					fixtureCode(t, s.Authorize(context.Background(), scope, scope.Request), want)
					current, err := s.connectionScope(context.Background(), scope.Connection)
					if err != nil || current.PolicyGeneration != store.policy.Generation || current.Connection != scope.Connection {
						t.Fatalf("fixture check: current human or worker policy could not reload: %v", err)
					}
					current = fixtureRequest(t, current, method, body)
					if err := s.Authorize(context.Background(), current, current.Request); err != nil {
						t.Fatalf("fixture check: reloaded human or worker policy request failed: %v", err)
					}
				})
			}
		})
	}
}

func TestSealedPlanPolicyChangeFixture(t *testing.T) {
	for _, projection := range []string{"historical", "advanced"} {
		t.Run(projection, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			store.record.PolicyGeneration, store.lane.PolicyGeneration = 3, 3
			plan := fixtureLaunchPlan(t, store.record)
			// A registered capture must not hide the launch-policy guard behind
			// the separate capture-refusal policy validator.
			plan.Capture.Status, plan.Capture.Refusal, plan.Capture.RefusalPolicy, plan.CapturePolicy = "registered", nil, nil, nil
			plan.Capture.WorkerLeaseID, plan.Capture.EffectID, plan.Capture.ProducerID = "capture-worker", "capture-effect", "capture-producer"
			plan.Capture.ProducerGeneration, plan.Capture.BootID = "kernel-generation", "boot"
			plan.Capture.Supervisor = &api.Executable{ID: "supervisor", SHA256: digestBytes([]byte("fixed supervisor")), Version: "fixture-v1"}
			plan.Capture.Streams = []api.CaptureStreamBinding{{ID: "stdout", Stream: "stdout", PipeID: "pipe-out"}, {ID: "stderr", Stream: "stderr", PipeID: "pipe-err"}}
			request := plannedFixtureBinding(t, store.record, plan)
			retainCustomPlan(t, store, request, plan)
			store.policy = &api.EffectivePolicy{Generation: plan.Reservation.PolicyGeneration}
			if permit, err := s.BindLaunch(context.Background(), request); err != nil || permit.PreparedID != request.Prepared.ID {
				t.Fatalf("fixture setup: current sealed plan was refused: %v", err)
			}
			historical := launchJSON(t, *store.binding)
			store.policy.Generation++
			if projection == "advanced" {
				store.lane.PolicyGeneration = store.policy.Generation
				store.lane.Generation++
			}
			permit, err := s.BindLaunch(context.Background(), request)
			fixtureCode(t, err, api.CodeConflict)
			if permit != (api.LaunchPermit{}) || !bytes.Equal(historical, launchJSON(t, *store.binding)) {
				t.Fatal("fixture check: stale sealed plan returned a permit or rewrote its retained binding")
			}
		})
	}
}
