package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This fixture journals exact captured bytes/ranges and actual EOF from owned
// readers. Native principal facts are a declared model, not an OS attestation.
type captureFixtureStore struct {
	*fixtureStore
	f         *fixture
	state     api.CaptureState
	root      api.LaunchReservation
	ticket    api.Ticket
	redeemed  api.ID
	sessions  map[api.ID]api.StoredReadSession
	retained  map[api.ID][]byte
	accepted  map[api.ID][]byte
	appends   []api.CaptureAppendRequest
	gaps      []api.CaptureGap
	dropEOF   bool
	badAck    bool
	stateRead chan struct{}
}

func newIOFixture(t *testing.T) (*fixture, *captureFixtureStore) {
	f := newFixture(t)
	binding := api.CaptureBinding{ID: "capture-binding", Config: "example", ReservationID: "capture-reservation", Target: f.target,
		LaunchID: f.child.LaunchID, HelperLeaseID: "capture-helper", OperationID: "capture-operation", RequestID: "capture-request", RequestedBy: f.parent,
		Generation: 1, Status: "registered", WorkerLeaseID: "capture-lease", EffectID: "capture-effect", ProducerID: "capture-producer",
		ProducerGeneration: "capture-generation", BootID: "capture-boot", Supervisor: &api.Executable{ID: "capture-supervisor", Version: "fixture-1", SHA256: digestOf([]byte("installed supervisor bytes"))},
		Streams: []api.CaptureStreamBinding{{ID: "stdout-stream", Stream: "stdout", PipeID: "stdout-pipe"}, {ID: "stderr-stream", Stream: "stderr", PipeID: "stderr-pipe"}}}
	if err := api.ValidateCaptureBinding(binding); err != nil {
		t.Fatal(err)
	}
	bound := f.add("capture.bound", binding, f.target.Run, "service", api.Actor{Kind: "service", ID: "lifecycle"})
	store := &captureFixtureStore{fixtureStore: f.store, f: f, retained: map[api.ID][]byte{}, accepted: map[api.ID][]byte{},
		root: api.LaunchReservation{Config: binding.Config, Mode: "start", Target: api.LifeRef{LifeID: f.child.RootLifeID, Run: 1},
			RootLifeID: f.child.RootLifeID, Authority: api.LaunchAuthority{Kind: "ticket", ID: "capture-root-ticket"},
			RequestedBy: api.Actor{Kind: "human", ID: "capture-owner"}, OperationID: "capture-root-op"},
		ticket:   api.Ticket{ID: "capture-root-ticket", Config: binding.Config, PrincipalID: "capture-owner", Redeemed: true},
		redeemed: "capture-root-op", sessions: map[api.ID]api.StoredReadSession{},
		state: api.CaptureState{Binding: binding, Generation: 1, LastSeq: bound.Seq, Positions: []api.CapturePosition{{StreamID: "stdout-stream"}, {StreamID: "stderr-stream"}}}}
	f.service.deps.Store = store
	return f, store
}

func (store *captureFixtureStore) CaptureState(ctx context.Context, scope api.Scope, binding api.ID) (api.CaptureState, error) {
	store.mu.Lock()
	allowed := store.captureReader(ctx, scope)
	store.mu.Unlock()
	if !allowed {
		return api.CaptureState{}, launchMissing()
	}
	return store.State(ctx, binding)
}

// The fixture's protected launch, consumed ticket and session are explicit
// inputs. It must never expose capture bytes merely because a caller has IDs.
func (store *captureFixtureStore) captureReader(ctx context.Context, scope api.Scope) bool {
	b := store.state.Binding
	if ctx.Err() != nil || scope.Config != b.Config || scope.Connection == nil ||
		scope.Connection.Binding().Config != scope.Config || scope.EndpointGeneration != scope.Connection.Binding().EndpointGeneration {
		return false
	}
	if scope.Actor.Kind == "lane" {
		launch, ok := store.launches[scope.LaunchID]
		return ok && !launch.Revoked && launch.Actor == scope.Actor && launch.Config == scope.Config &&
			launch.EndpointGeneration == scope.EndpointGeneration && launch.Target.LifeID == scope.Actor.LifeID &&
			scope.Connection.Binding().Class == api.EndpointLane && store.f.child.ParentLifeID != "" &&
			scope.Actor.LifeID == store.f.child.ParentLifeID
	}
	r, ticket := store.root, store.ticket
	if scope.Actor.Kind != "human" || scope.Connection.Binding().Class != api.EndpointHuman ||
		r.Config != scope.Config || r.Target.LifeID != store.f.child.RootLifeID || r.RootLifeID != r.Target.LifeID ||
		r.ParentLifeID != "" || r.RequestedBy != scope.Actor || r.Authority.Kind != "ticket" ||
		r.Authority.ID != ticket.ID || !ticket.Redeemed || store.redeemed != r.OperationID ||
		ticket.PrincipalID != scope.Actor.ID || ticket.Config != scope.Config {
		return false
	}
	authority, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return false
	}
	session, ok := store.sessions[authority.SessionID]
	return ok && !session.Revoked && authority == api.ReadAuthorityFromSession(session) &&
		session.ConnectionID == scope.Connection.ID() && session.PrincipalID == scope.Actor.ID &&
		session.EndpointGeneration == scope.EndpointGeneration && session.Session.Config == scope.Config &&
		futureFixture(session.Session.ExpiresAt) && futureFixture(session.Session.IdleExpiresAt)
}

func futureFixture(value api.Timestamp) bool {
	parsed, err := time.Parse(time.RFC3339Nano, string(value))
	return err == nil && parsed.After(fixtureClock{}.Now())
}

func (store *captureFixtureStore) captureObject(ctx context.Context, scope api.Scope, metadata api.ObjectMetadata) bool {
	b, acl := store.state.Binding, metadata.ACL
	return store.captureReader(ctx, scope) && acl.Config == scope.Config && acl.LifeID == b.Target.LifeID &&
		acl.Owner == (api.Actor{Kind: "worker", ID: b.ProducerID}) && acl.Audience == "owner" &&
		acl.Generation == 1 && len(acl.Participants) == 0 && metadata.SourceOperationID == b.OperationID
}

func (store *captureFixtureStore) ObjectMetadata(ctx context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	metadata, err := store.fixtureStore.ObjectMetadata(ctx, scope, id)
	if err != nil || metadata.Ref.Class != "capture" {
		return metadata, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.captureObject(ctx, scope, metadata) {
		return api.ObjectMetadata{}, launchMissing()
	}
	return metadata, nil
}

func (store *captureFixtureStore) Blob(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	if _, err := store.ObjectMetadata(ctx, scope, request.ObjectID); err != nil {
		return api.BlobChunk{}, err
	}
	return store.fixtureStore.Blob(ctx, scope, request)
}

func (store *captureFixtureStore) State(ctx context.Context, binding api.ID) (api.CaptureState, error) {
	if err := ctx.Err(); err != nil {
		return api.CaptureState{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.stateRead != nil {
		select {
		case store.stateRead <- struct{}{}:
		default:
		}
	}
	if binding != store.state.Binding.ID {
		return api.CaptureState{}, launchMissing()
	}
	state := store.state
	state.Positions = append([]api.CapturePosition{}, state.Positions...)
	return state, nil
}

func (store *captureFixtureStore) RetainCapture(ctx context.Context, binding, stream api.ID, offset int64, raw []byte) (api.BlobRef, error) {
	if err := ctx.Err(); err != nil {
		return api.BlobRef{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	position, ok := capturePosition(store.state, stream)
	if binding != store.state.Binding.ID || !ok || position.NextOffset != offset || position.EOF {
		return api.BlobRef{}, launchConflict()
	}
	ref := api.BlobRef{ID: launchIDForTest(), Class: "capture", SHA256: digestOfBytes(raw), Bytes: int64(len(raw))}
	store.retained[ref.ID], store.blobs[ref.ID] = append([]byte{}, raw...), append([]byte{}, raw...)
	store.metadata[ref.ID] = api.ObjectMetadata{Ref: ref, Origin: "worker", SourceOperationID: store.state.Binding.OperationID,
		ACL: api.ObjectACL{Config: "example", LifeID: store.state.Binding.Target.LifeID,
			Owner: api.Actor{Kind: "worker", ID: store.state.Binding.ProducerID}, Audience: "owner", Generation: 1}}
	return ref, nil
}

func (store *captureFixtureStore) Append(ctx context.Context, request api.CaptureAppendRequest) (api.CaptureAppendReceipt, error) {
	if err := ctx.Err(); err != nil {
		return api.CaptureAppendReceipt{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	binding := store.state.Binding
	if err := api.ValidateCaptureAppend(binding, request); err != nil {
		return api.CaptureAppendReceipt{}, err
	}
	if request.ExpectedGeneration != store.state.Generation {
		return api.CaptureAppendReceipt{}, launchConflict()
	}
	index := -1
	for i, position := range store.state.Positions {
		if position.StreamID == request.StreamID {
			index = i
		}
	}
	if index < 0 || store.state.Positions[index].NextOffset != request.Offset || store.state.Positions[index].EOF {
		return api.CaptureAppendReceipt{}, launchConflict()
	}
	length := int64(0)
	if request.Data != nil {
		raw := store.retained[request.Data.ID]
		if digestOfBytes(raw) != request.Data.SHA256 || int64(len(raw)) != request.Data.Bytes {
			return api.CaptureAppendReceipt{}, launchConflict()
		}
		length = int64(len(raw))
		store.accepted[request.StreamID] = append(store.accepted[request.StreamID], raw...)
	}
	store.state.Generation++
	store.state.Positions[index].NextOffset += length
	if request.EOF && !store.dropEOF {
		store.state.Positions[index].EOF = true
	}
	store.seq++
	store.state.LastSeq = store.seq
	receipt := api.CaptureAppendReceipt{BindingID: binding.ID, RecordID: launchIDForTest(), StreamID: request.StreamID, Offset: request.Offset,
		NextOffset: request.Offset + length, Generation: store.state.Generation, LastSeq: store.seq, EOF: request.EOF}
	var kind api.EventKind = "capture.closed"
	var payload any = receipt
	if request.Data != nil {
		kind = "capture.appended"
		name := ""
		for _, stream := range binding.Streams {
			if stream.ID == request.StreamID {
				name = stream.Stream
			}
		}
		payload = api.CaptureRecord{BindingID: binding.ID, ID: receipt.RecordID, Target: binding.Target, Stream: name, Offset: request.Offset,
			Data: *request.Data, Primary: true, Coverage: "raw", ObservedAt: "2030-01-02T03:04:05Z"}
	}
	scope := api.Scope{Config: binding.Config, Actor: binding.RequestedBy, Request: api.Request{RequestID: binding.RequestID}}
	event, err := store.f.service.event(scope, store.f.child, kind, payload, request.Intent.Actor)
	if err != nil {
		return api.CaptureAppendReceipt{}, err
	}
	event.Seq, event.OperationID = store.seq, binding.OperationID
	store.events = append(store.events, event)
	store.appends = append(store.appends, request)
	if store.badAck {
		receipt.NextOffset++
	}
	return receipt, nil
}

func (store *captureFixtureStore) Gap(ctx context.Context, gap api.CaptureGap) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if gap.BindingID != store.state.Binding.ID {
		return launchConflict()
	}
	store.gaps = append(store.gaps, gap)
	return nil
}

func captureCommit(t *testing.T, store *captureFixtureStore, stream api.ID, raw []byte, eof bool) api.CaptureAppendReceipt {
	t.Helper()
	state, err := store.State(context.Background(), store.state.Binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	position, ok := capturePosition(state, stream)
	if !ok {
		t.Fatal("capture fixture selected an unregistered stream")
	}
	binding := state.Binding
	cause := api.InternalIntent{ID: launchIDForTest(), Kind: api.InternalCaptureAppend, Config: binding.Config,
		Actor: api.Actor{Kind: "worker", ID: binding.ProducerID}, RequestedBy: binding.RequestedBy,
		CauseOperationID: binding.OperationID, CauseRequestID: binding.RequestID, EffectID: binding.EffectID, Target: binding.Target}
	request := api.CaptureAppendRequest{Intent: cause, BindingID: binding.ID, ExpectedGeneration: state.Generation, StreamID: stream, Offset: position.NextOffset, EOF: eof}
	if !eof {
		ref, err := store.RetainCapture(context.Background(), binding.ID, stream, position.NextOffset, raw)
		if err != nil {
			t.Fatal(err)
		}
		request.Data = &ref
	}
	receipt, err := store.Append(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	store.f.service.NotifyCommit()
	return receipt
}

type supervisorFixture struct {
	job      SupervisorJob
	opens    int
	closes   int
	closeErr error
}

func (bootstrap *supervisorFixture) OpenSupervisor(_ context.Context, config string, lease api.ID) (SupervisorJob, error) {
	bootstrap.opens++
	if config != bootstrap.job.Binding.Config || lease != bootstrap.job.Principal.Lease.ID {
		return SupervisorJob{}, launchMissing()
	}
	return bootstrap.job, nil
}

func supervisorJob(t *testing.T, store *captureFixtureStore, stdout, stderr []byte) *supervisorFixture {
	t.Helper()
	b := store.state.Binding
	endpoint := api.InstalledBinding{Config: b.Config, Class: api.EndpointWorker, Target: &b.Target,
		WorkerLeaseID: b.WorkerLeaseID, LaunchID: "capture-worker-launch", EndpointGeneration: 1}
	peer := api.PeerFacts{HostUID: 60001, HostGID: 60001, HostPID: 77, ProcessGeneration: b.ProducerGeneration, ContainmentID: "capture-containment"}
	lease := api.WorkerLease{ID: b.WorkerLeaseID, Kind: "capture", Target: b.Target, OperationID: b.OperationID,
		EffectID: b.EffectID, GrantSetID: "capture-grants", Generation: 1, ExpiresAt: "2031-01-01T00:00:00Z", ConsumedBy: endpoint.LaunchID}
	record := api.LaunchRecord{ID: endpoint.LaunchID, Config: b.Config, Kind: "worker", Target: b.Target, Actor: api.Actor{Kind: "worker", ID: b.ProducerID},
		HostUID: peer.HostUID, ContainmentID: peer.ContainmentID, ProcessGeneration: b.ProducerGeneration, GrantSetID: lease.GrantSetID, EndpointGeneration: 1}
	cause := api.InternalIntent{ID: "capture-cause", Kind: api.InternalLifecycleEffect, Config: b.Config, Actor: api.Actor{Kind: "service", ID: "lifecycle"},
		RequestedBy: b.RequestedBy, CauseOperationID: b.OperationID, CauseRequestID: b.RequestID, EffectID: b.EffectID, Target: b.Target}
	effect := api.EffectRecord{Effect: api.Effect{ID: b.EffectID, OperationID: b.OperationID, Context: &cause}, Generation: 2,
		State: api.EffectClaimed, ClaimID: "capture-claim", ClaimantID: "capture-executor", ClaimExpiresAt: lease.ExpiresAt}
	principal := api.WorkerPrincipal{StageID: "capture-stage", Lease: lease, Record: record, Endpoint: endpoint, Peer: peer,
		BootID: b.BootID, AllocationGeneration: 1, CaptureBindingID: b.ID,
		Claim: api.EffectLease{Record: effect, ClaimID: effect.ClaimID, ExpiresAt: effect.ClaimExpiresAt}}
	bootstrap := &supervisorFixture{}
	bootstrap.job = SupervisorJob{Principal: principal, Endpoint: endpoint, Peer: peer, Binding: b, Ingress: store, Clock: fixtureClock{},
		Pipes: []SupervisorPipe{{StreamID: b.Streams[0].ID, PipeID: b.Streams[0].PipeID, Reader: io.NopCloser(bytes.NewReader(stdout))},
			{StreamID: b.Streams[1].ID, PipeID: b.Streams[1].PipeID, Reader: io.NopCloser(bytes.NewReader(stderr))}}}
	bootstrap.job.Close = func() error {
		bootstrap.closes++
		for _, pipe := range bootstrap.job.Pipes {
			if err := pipe.Reader.Close(); err != nil {
				return err
			}
		}
		return bootstrap.closeErr
	}
	if err := api.ValidateWorkerPrincipal(principal, endpoint, peer, api.WorkerCaptureState, fixtureClock{}.Now()); err != nil {
		t.Fatal(err)
	}
	return bootstrap
}

func captureRecord(t *testing.T, event api.Event) api.CaptureRecord {
	t.Helper()
	var record api.CaptureRecord
	if err := json.Unmarshal(event.Payload, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func sameCaptureBytes(left, right []byte) bool { return reflect.DeepEqual(left, right) }

var _ api.Clock = (*movingClock)(nil)
