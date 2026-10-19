package lifecycle

import (
	"context"
	"net"
	"reflect"
	"testing"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
)

type revocationStore struct {
	*launchFixtureStore
	endpoints   map[api.ID]api.EndpointProjection
	revocations map[api.ID]api.LaunchRevocation
	commits     int
	commitErr   error
	readHook    func(*api.LaunchRevocation)
}

func (store *revocationStore) RevocationEndpoint(_ context.Context, _ api.Scope, id api.ID) (api.EndpointProjection, error) {
	value, ok := store.endpoints[id]
	if !ok {
		return api.EndpointProjection{}, launchMissing()
	}
	return value, nil
}

func (store *revocationStore) LaunchRevocation(_ context.Context, id api.ID) (api.LaunchRevocation, error) {
	value, ok := store.revocations[id]
	if !ok {
		return api.LaunchRevocation{}, launchMissing()
	}
	if store.readHook != nil {
		store.readHook(&value)
	}
	return value, nil
}

func (store *revocationStore) Transact(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	if len(tx.Events) != 1 || tx.Events[0].Kind != "identity.revoked" {
		return store.launchFixtureStore.Transact(ctx, tx)
	}
	if store.commitErr != nil {
		return api.Commit{}, store.commitErr
	}
	if err := api.ValidateTransactionShape(tx); err != nil {
		return api.Commit{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if tx.Internal == nil || store.checkIntent(tx.Scope, *tx.Internal) != nil || len(tx.Events) != 1 || tx.Events[0].Kind != "identity.revoked" || len(tx.Writes.Endpoints) != 1 {
		return api.Commit{}, launchConflict()
	}
	var record api.LaunchRecord
	if err := api.DecodeObject(tx.Events[0].Payload, &record); err != nil || !record.Revoked {
		return api.Commit{}, launchConflict()
	}
	binding := store.bindings[record.ID]
	binding.Record = record
	endpoint := tx.Writes.Endpoints[0]
	laneCAS, endpointCAS, epoch := false, false, false
	for _, compare := range tx.Compare {
		laneCAS = laneCAS || compare.Kind == api.CompareLane && compare.ID == binding.Record.Target.LifeID && compare.Generation == store.lanes[compare.ID].Generation
		endpointCAS = endpointCAS || compare.Kind == api.CompareEndpoint && compare.ID == binding.Record.ID && compare.Generation == store.endpoints[compare.ID].Generation
	}
	for _, guard := range tx.Guards {
		epoch = epoch || guard.Cancellation != nil && guard.Cancellation.LifeID == binding.Record.Target.LifeID && guard.Cancellation.Epoch == store.lanes[binding.Record.Target.LifeID].CancellationEpoch
	}
	if !laneCAS || !endpointCAS || !epoch || !endpoint.Revoked || endpoint.Generation != store.endpoints[binding.Record.ID].Generation+1 {
		return api.Commit{}, launchConflict()
	}
	var payload api.LaunchRecord
	if api.DecodeObject(tx.Events[0].Payload, &payload) != nil || !reflect.DeepEqual(payload, binding.Record) {
		return api.Commit{}, launchConflict()
	}
	digest, err := revokedDigest(binding.Record)
	if err != nil {
		return api.Commit{}, err
	}
	store.seq++
	event := tx.Events[0]
	event.Seq = store.seq
	revoked := api.LaunchRevocation{Record: binding.Record, RecordSHA256: digest, Cause: *tx.Internal, EventID: event.ID, CommittedSeq: event.Seq}
	if err := api.ValidateLaunchRevocation(revoked); err != nil {
		return api.Commit{}, err
	}
	store.revocations[binding.Record.ID] = revoked
	// The original binding is immutable recovery evidence. Current identity
	// revocation is the separate causal record and launch projection.
	store.launches[binding.Record.ID] = binding.Record
	store.endpoints[binding.Record.ID] = endpoint
	store.events = append(store.events, event)
	store.transactions = append(store.transactions, tx)
	store.commits++
	return api.Commit{Operation: store.operations[tx.Internal.CauseOperationID], FirstSeq: event.Seq, LastSeq: event.Seq}, nil
}

type revocationIdentity struct {
	api.Authenticator
	store       *revocationStore
	connections map[api.ID][]net.Conn
	closed      map[net.Conn]bool
	deliveries  map[api.ID][]chan struct{}
	blocked     bool
	unknown     bool
	calls       int
}

func (identity *revocationIdentity) RevokeLaunch(ctx context.Context, id api.ID) error {
	identity.calls++
	revoked, err := identity.store.LaunchRevocation(ctx, id)
	if err != nil {
		return err
	}
	if identity.store.commits == 0 {
		return integrity("transport was called before causal revocation commit")
	}
	if !identity.blocked {
		for _, connection := range identity.connections[id] {
			if err := connection.Close(); err != nil {
				return err
			}
			identity.closed[connection] = true
		}
		for _, delivery := range identity.deliveries[id] {
			select {
			case <-delivery:
			default:
				close(delivery)
			}
		}
	}
	connections, deliveries := identity.remaining(id)
	receipt := api.TransportInvalidationReceipt{LaunchID: id, RevocationEventID: revoked.EventID, OperationID: revoked.Cause.CauseOperationID,
		RemainingConnections: &connections, RemainingDeliveries: &deliveries, CompletedAt: "2030-01-02T03:04:05Z"}
	if identity.unknown {
		receipt.RemainingDeliveries = nil
	}
	return api.ValidateTransportInvalidation(revoked, receipt)
}

func (identity *revocationIdentity) remaining(id api.ID) (uint64, uint64) {
	var connections, deliveries uint64
	for _, connection := range identity.connections[id] {
		if !identity.closed[connection] {
			connections++
		}
	}
	for _, delivery := range identity.deliveries[id] {
		select {
		case <-delivery:
		default:
			deliveries++
		}
	}
	return connections, deliveries
}

func newRevocationFixture(t *testing.T) (*launchFixture, *revocationStore, *revocationIdentity, api.Scope, api.EffectLease) {
	t.Helper()
	f := newLaunchFixture(t)
	_, reservation := f.reserve(t)
	planningScope, planningRequest := f.claim(t, reservation)
	plan, err := f.service.PlanLaunch(context.Background(), planningScope, planningRequest)
	if err != nil {
		t.Fatal(err)
	}
	lane := f.bindPrepared(t, planningScope, planningRequest, plan)
	// Model an opened run's retained read state; actual kernel/permit opening
	// remains an installed-service gate, not a unit-fixture measurement.
	lane.State = "running"
	f.store.lanes[lane.LifeID] = lane
	opened := f.store.plans[plan.Reservation.ID]
	opened.Phase = "opened"
	opened.Generation++
	f.store.plans[plan.Reservation.ID] = opened
	binding := f.store.bindings[lane.LaunchID]
	one := uint64(1)
	observation := api.ProcessObservation{Handle: api.ProcessHandle{ID: launchIDForTest(), Target: plan.Reservation.Target,
		ContainmentID: binding.Record.ContainmentID, Generation: binding.Record.ProcessGeneration}, State: "running", Survivors: &one, PromptStatus: "written", ObservedAt: "2030-01-02T03:04:05Z"}
	f.launcher.observation = observation
	f.fixture.addTo(lane, "run.observed", observation, "service", f.parent)
	request := api.StopRequest{Target: plan.Reservation.Target, ExpectedGeneration: lane.Generation, Reason: f.fixture.blob("revoke-reason", "task", []byte("stop the actual contained run"))}
	if _, err := f.service.LaneStop(context.Background(), f.fixture.scope("lane.stop", request, f.parent), request); err != nil {
		t.Fatal(err)
	}
	tx := f.fixture.store.transactions[len(f.fixture.store.transactions)-1]
	effect := tx.Effects[0]
	scope := api.Scope{Config: "example", Actor: effect.Context.Actor, Source: "outbox", PolicyGeneration: f.store.policy.Generation}
	record := api.EffectRecord{Effect: effect, Generation: 2, State: api.EffectClaimed, ClaimID: launchIDForTest(), ClaimantID: scope.Actor.ID, ClaimExpiresAt: "2030-01-02T03:09:05Z"}
	f.store.effects[effect.ID] = record
	target := plan.Reservation.Target
	endpoint := api.EndpointProjection{Generation: 1, Binding: api.InstalledBinding{Schema: "laneboss.binding.v2", Protocol: api.Protocol, APISchema: api.SchemaVersion,
		ContractRevision: api.ContractRevision, Config: "example", Class: api.EndpointLane, InstallationGeneration: 1, EndpointGeneration: plan.Lease.EndpointGeneration,
		ServiceUID: 9001, ServiceGID: 9001, Socket: "/runtime/agent.sock", ArtifactSHA256: digestOf([]byte("installed service artifact")), ServiceVersion: release.Version,
		Backend: plan.Inputs.Sources.Runtime.Backend, LaunchID: lane.LaunchID, Target: &target}}
	store := &revocationStore{launchFixtureStore: f.store, endpoints: map[api.ID]api.EndpointProjection{lane.LaunchID: endpoint}, revocations: map[api.ID]api.LaunchRevocation{}}
	first, firstPeer := net.Pipe()
	second, secondPeer := net.Pipe()
	t.Cleanup(func() {
		for _, connection := range []net.Conn{first, firstPeer, second, secondPeer} {
			if err := connection.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	identity := &revocationIdentity{Authenticator: f.identity, store: store, connections: map[api.ID][]net.Conn{lane.LaunchID: {first, second}},
		closed: map[net.Conn]bool{}, deliveries: map[api.ID][]chan struct{}{lane.LaunchID: {make(chan struct{})}}}
	f.service.deps.Store, f.service.deps.Identity = store, identity
	return f, store, identity, scope, api.EffectLease{Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt}
}

func TestRevocationCommitBeforeClose(t *testing.T) {
	f, store, identity, scope, lease := newRevocationFixture(t)
	if err := f.service.RevokeLaunch(context.Background(), scope, lease); err != nil {
		t.Fatal(err)
	}
	if store.commits != 1 || identity.calls != 1 || len(store.revocations) != 1 || f.launcher.stopped.Load() != 0 || store.effects[lease.Record.Effect.ID].Outcome != nil {
		t.Fatal("revocation did not retain its decision before transport close")
	}
	for _, revoked := range store.revocations {
		connections, deliveries := identity.remaining(revoked.Record.ID)
		if revoked.Cause.CauseOperationID != lease.Record.Effect.OperationID || revoked.Cause.RequestedBy != f.parent ||
			!store.endpoints[revoked.Record.ID].Revoked || connections != 0 || deliveries != 0 {
			t.Fatal("revocation lost its causal event or actual close completion")
		}
		for _, connection := range identity.connections[revoked.Record.ID] {
			if _, err := connection.Write([]byte("close probe")); err == nil {
				t.Fatal("revoked transport retained a writable connection")
			}
		}
	}
	if err := f.service.RevokeLaunch(context.Background(), scope, lease); err != nil || store.commits != 1 {
		t.Fatalf("revocation retry created another manual decision: %v", err)
	}
}

func TestRevocationClosePending(t *testing.T) {
	for _, mode := range []string{"blocked", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			f, store, identity, scope, lease := newRevocationFixture(t)
			identity.blocked, identity.unknown = mode == "blocked", mode == "unknown"
			if err := f.service.RevokeLaunch(context.Background(), scope, lease); err == nil || store.commits != 1 || store.effects[lease.Record.Effect.ID].Outcome != nil {
				t.Fatalf("incomplete close was reported as a completed stop: %v", err)
			}
			identity.blocked, identity.unknown = false, false
			if err := f.service.RevokeLaunch(context.Background(), scope, lease); err != nil || store.commits != 1 {
				t.Fatalf("close recovery replaced its original revocation: %v", err)
			}
		})
	}
}

func TestRevocationRefuses(t *testing.T) {
	for _, mode := range []string{"claim", "epoch", "endpoint", "commit", "cause", "event"} {
		t.Run(mode, func(t *testing.T) {
			f, store, identity, scope, lease := newRevocationFixture(t)
			switch mode {
			case "claim":
				lease.ClaimID = "foreign-claim"
			case "epoch":
				lane := store.lanes[lease.Record.Effect.Context.Target.LifeID]
				lane.CancellationEpoch++
				store.lanes[lane.LifeID] = lane
			case "endpoint":
				for id, value := range store.endpoints {
					value.Binding.EndpointGeneration++
					store.endpoints[id] = value
				}
			case "commit":
				store.commitErr = api.NotImplemented("lb-v2-service", "fixture causal revocation commit")
			case "cause":
				store.readHook = func(r *api.LaunchRevocation) { r.Cause.CauseRequestID = "foreign-request" }
			case "event":
				store.readHook = func(r *api.LaunchRevocation) { r.EventID = "" }
			}
			err := f.service.RevokeLaunch(context.Background(), scope, lease)
			if err == nil || identity.calls != 0 {
				t.Fatalf("invalid revocation reached transport invalidation: %s: %v", mode, err)
			}
		})
	}
}

func TestRevokedHistoryRead(t *testing.T) {
	for _, mode := range []string{"valid", "event", "record"} {
		t.Run(mode, func(t *testing.T) {
			f, store, _, scope, lease := newRevocationFixture(t)
			if err := f.service.RevokeLaunch(context.Background(), scope, lease); err != nil {
				t.Fatal(err)
			}
			lane := store.lanes[lease.Record.Effect.Context.Target.LifeID]
			binding := store.bindings[lane.LaunchID]
			if mode == "event" {
				binding.Identity.EventID = "foreign-event"
			}
			if mode == "record" {
				binding.Record.Actor.Role = "foreign-role"
			}
			historical, err := f.service.historicalBinding(context.Background(), scope, lane, binding)
			if mode == "valid" {
				if err != nil || historical.Record.Revoked || !store.launches[lane.LaunchID].Revoked || store.bindings[lane.LaunchID].Record.Revoked || historical.Identity != binding.Identity {
					t.Fatalf("historical read rewrote or lost the revoked live identity: %v", err)
				}
			} else if err == nil {
				t.Fatal("foreign history authorized reuse of a revoked binding")
			}
		})
	}
}
