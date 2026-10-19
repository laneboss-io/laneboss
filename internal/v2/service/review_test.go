package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func TestEndpointClassPrecedesActorLabel(t *testing.T) {
	server := fixtureServer(t)
	server.deps.Authenticator.(*authFixture).scope.Actor = api.Actor{Kind: "human", ID: fixtureID(t)}
	called := false
	if err := server.Register("store.verify", func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
		called = true
		return nil, serviceError(api.CodeIntegrity, "wrong endpoint invoked handler")
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err := server.dispatch(context.Background(), nil, requestFor(t, "store.verify", api.VerifyRequest{Scope: "all"}))
	codeIs(t, err, api.CodeForbidden)
	if called {
		t.Fatal("human label bypassed installed lane endpoint")
	}
}

type healthLauncher struct {
	api.Launcher
	probe api.IsolationCapabilities
	err   error
}

func (l *healthLauncher) Probe(context.Context) (api.IsolationCapabilities, error) {
	return l.probe, l.err
}

func TestHealthTracksHostObservations(t *testing.T) {
	s := fixtureServer(t)
	s.deps.Binding.Backend = "linux-bwrap-landlock"
	s.verified, s.bound, s.serving = true, true, true
	s.reconciling = true
	s.launchConfigured, s.launchJobsActive, s.launchJobsHealthy = true, true, true
	s.streams = map[api.Method]api.StreamHandler{}
	for _, method := range []api.Method{"event.tail", "lane.attach"} {
		s.streams[method] = func(context.Context, api.Scope, json.RawMessage) (api.EventStream, error) {
			return &heldEventStream{}, nil
		}
	}
	for method := range api.Methods {
		if err := s.Register(method, identityHandler); err == nil {
			t.Fatal("serving registry accepted late route")
		}
		s.handlers[method] = identityHandler // Isolated host-observation fixture.
	}
	probe := &healthLauncher{probe: api.IsolationCapabilities{Available: true, Backend: s.deps.Binding.Backend,
		Checks: []api.Capability{{Name: "native-boundary", Available: true, Reason: "fixture observation"}}}}
	s.runtime.Launcher = probe
	// Compute Health's digest from the actual test executable, then require
	// both production hash paths to describe those same bytes.
	artifactPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	artifactBytes, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(artifactBytes)
	artifactDigest := api.Digest(hex.EncodeToString(sum[:]))
	core, err := New(s.deps)
	if err != nil {
		t.Fatal("service artifact observation failed", err)
	}
	if core.artifact != artifactDigest {
		t.Fatal("service artifact digest differs from executable bytes")
	}
	transportDigest, err := wire.ArtifactDigest()
	if err != nil || transportDigest != artifactDigest {
		t.Fatal("installed host artifact digest differs from executable bytes", err)
	}
	encoded, err := json.Marshal(api.Health{Protocol: api.Protocol, Schema: api.SchemaVersion,
		ServiceVersion: release.Version, ArtifactSHA256: artifactDigest, Ready: true, Capabilities: []api.Capability{}})
	if err != nil {
		t.Fatal(err)
	}
	observe := func() api.Health {
		t.Helper()
		data, err := s.observedHealth(context.Background(), encoded)
		if err != nil {
			t.Fatal(err)
		}
		var result api.Health
		if err := wire.Decode(data, &result); err != nil {
			t.Fatal(err)
		}
		if result.ArtifactSHA256 != artifactDigest {
			t.Fatal("host health changed the executable digest")
		}
		return result
	}
	if !observe().Ready {
		t.Fatal("healthy host observation control failed")
	}
	probe.probe.Checks[0].Available = false
	if observe().Ready {
		t.Fatal("failed isolation check left health ready")
	}
	probe.probe.Checks[0].Available = true
	s.serving = false
	if observe().Ready {
		t.Fatal("closed listener left health ready")
	}
	s.serving = true
	s.dispatchPaused = true
	if observe().Ready {
		t.Fatal("durable dispatch freeze left health ready")
	}
	s.dispatchPaused = false
	delete(s.handlers, "blob.commit")
	if observe().Ready {
		t.Fatal("missing registered method left health ready")
	}
	s.handlers["blob.commit"] = identityHandler
	stream := s.streams["event.tail"]
	delete(s.streams, "event.tail")
	if observe().Ready {
		t.Fatal("missing stream producer left health ready")
	}
	s.streams["event.tail"] = stream
	s.recordFault(serviceError(api.CodeIntegrity, "fixture reconciler fault"))
	if observe().Ready {
		t.Fatal("reconciler fault left health ready")
	}
}

type finiteEventStream struct {
	frames   []api.StreamFrame
	err      error
	closeErr error
	closed   chan struct{}
	once     sync.Once
}

func (f *finiteEventStream) Next(context.Context) (api.StreamFrame, error) {
	if len(f.frames) == 0 {
		return api.StreamFrame{}, f.err
	}
	frame := f.frames[0]
	f.frames = f.frames[1:]
	return frame, nil
}
func (f *finiteEventStream) Close() error { f.once.Do(func() { close(f.closed) }); return f.closeErr }

func TestLivePrivateEventFiltering(t *testing.T) {
	s := fixtureServer(t)
	scope := s.deps.Authenticator.(*authFixture).scope
	request := requestFor(t, "event.tail", api.EventTailRequest{LifeID: scope.Actor.LifeID, Run: 1, Follow: true})
	now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	operation := fixtureID(t)
	privatePayload, err := json.Marshal(api.ProofUseReceipt{ProofID: fixtureID(t), CredentialID: fixtureID(t), NonceID: fixtureID(t), OperationID: operation, UsedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	private := api.Event{Schema: api.SchemaVersion, ID: fixtureID(t), Config: scope.Config, Kind: "human.proof.used", LifeID: scope.Actor.LifeID, Run: 1, Seq: 1,
		Actor: api.Actor{Kind: "service", ID: fixtureID(t)}, RequestedBy: scope.Actor, OperationID: operation, RequestID: fixtureID(t),
		StarterChain: []api.ID{}, RecordedAt: now, RequestedAt: now, ObservedAt: now, Origin: "service", Payload: privatePayload}
	public := private
	public.ID, public.Kind, public.Seq, public.Actor, public.Origin = fixtureID(t), "blob.committed", 2, scope.Actor, "observation"
	public.Payload, err = json.Marshal(api.BlobRef{ID: fixtureID(t), Class: "record", Bytes: 1, SHA256: queueFrame([]byte("x")).Chunk.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []api.Event{private, public} {
		if err := wire.ValidateEvent(event); err != nil {
			t.Fatal("live visibility canary is invalid", err)
		}
	}
	producer := &finiteEventStream{frames: []api.StreamFrame{{Cursor: "private-cursor", Event: &private}, {Cursor: "public-cursor", Event: &public}},
		err: serviceError(api.CodeUnavailable, "fixture producer ended"), closed: make(chan struct{})}
	if err := s.RegisterStream("event.tail", func(context.Context, api.Scope, json.RawMessage) (api.EventStream, error) { return producer, nil }); err != nil {
		t.Fatal(err)
	}
	initial, err := json.Marshal(api.EventPage{Events: []api.Event{}, Cursor: "initial-cursor", Complete: true})
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); defer a.Close(); s.serveStream(ctx, a, scope, request, initial) }()
	if err := b.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data, err := wire.ReadFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := wire.DecodeStream(data, request.RequestID, 1)
	if err != nil || observed.Event == nil || observed.Event.Kind != public.Kind || observed.Event.ID != public.ID {
		t.Fatal("live private event bypassed visibility policy")
	}
	data, err = wire.ReadFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	observed, err = wire.DecodeStream(data, request.RequestID, 2)
	if err != nil || observed.Event != nil || observed.Error == nil || observed.Error.Code != api.CodeUnavailable || observed.Cursor != "public-cursor" {
		t.Fatal("live event control lost public cursor", err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("private event watcher did not drain")
	}
}

func TestQueuedFramesDrainBeforeError(t *testing.T) {
	s := fixtureServer(t)
	scope := s.deps.Authenticator.(*authFixture).scope
	request := requestFor(t, "lane.attach", api.AttachRequest{Target: api.LifeRef{LifeID: scope.Actor.LifeID, Run: 1}, Mode: "output"})
	first, second := queueFrame([]byte("first")), queueFrame([]byte("second"))
	first.Cursor, second.Cursor = "cursor-one", "cursor-two"
	producer := &finiteEventStream{frames: []api.StreamFrame{first, second}, err: serviceError(api.CodeUnavailable, "fixture terminal"),
		closeErr: serviceError(api.CodeIntegrity, "fixture close error"), closed: make(chan struct{})}
	if err := s.RegisterStream("lane.attach", func(context.Context, api.Scope, json.RawMessage) (api.EventStream, error) { return producer, nil }); err != nil {
		t.Fatal(err)
	}
	snapshot := queueFrame([]byte("initial"))
	snapshot.RequestID, snapshot.Index = request.RequestID, 1
	initial, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); defer a.Close(); s.serveStream(ctx, a, scope, request, initial) }()
	for index, expected := range []string{"first", "second", "error"} {
		if err := b.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		data, err := wire.ReadFrame(b)
		if err != nil {
			t.Fatal("queued frame was discarded before producer error", err)
		}
		frame, err := wire.DecodeStream(data, request.RequestID, uint64(index+1))
		if err != nil {
			t.Fatal(err)
		}
		if expected == "error" {
			if frame.Error == nil || frame.Cursor != second.Cursor {
				t.Fatal("producer error lost last delivered cursor")
			}
		} else if frame.Chunk == nil || string(frame.Chunk.Data) != expected {
			t.Fatal("queued frame was discarded before producer error")
		}
	}
	if _, err := wire.ReadFrame(b); err == nil {
		t.Fatal("stream wrote a second terminal frame")
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("queued producer did not drain")
	}
}

type heldEventStream struct{}

func (*heldEventStream) Next(ctx context.Context) (api.StreamFrame, error) {
	<-ctx.Done()
	return api.StreamFrame{}, ctx.Err()
}
func (*heldEventStream) Close() error { return nil }

func TestPrincipalWatcherIsolation(t *testing.T) {
	s := fixtureServer(t)
	scope := s.deps.Authenticator.(*authFixture).scope
	request := requestFor(t, "lane.attach", api.AttachRequest{Target: api.LifeRef{LifeID: scope.Actor.LifeID, Run: 1}, Mode: "output"})
	frame := queueFrame([]byte("snapshot"))
	frame.RequestID, frame.Index = request.RequestID, 1
	initial, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 8)
	if err := s.RegisterStream("lane.attach", func(context.Context, api.Scope, json.RawMessage) (api.EventStream, error) {
		started <- struct{}{}
		return &heldEventStream{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var peers []net.Conn
	var completions []chan struct{}
	t.Cleanup(func() {
		cancel()
		for _, peer := range peers {
			peer.Close()
		}
		for _, done := range completions {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("quota fixture did not collect watcher")
			}
		}
	})
	open := func(authority api.Scope) net.Conn {
		a, b := net.Pipe()
		peers = append(peers, b)
		done := make(chan struct{})
		completions = append(completions, done)
		go func() { defer close(done); defer a.Close(); s.serveStream(ctx, a, authority, request, initial) }()
		return b
	}
	for index := 0; index < 2; index++ {
		open(scope)
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("principal watcher capacity control failed")
		}
	}
	third := open(scope)
	type reply struct {
		data []byte
		err  error
	}
	replies := make(chan reply, 1)
	go func() { data, err := wire.ReadFrame(third); replies <- reply{data, err} }()
	select {
	case <-started:
		t.Fatal("principal watcher limit admitted excess producer")
	case result := <-replies:
		if result.err != nil {
			t.Fatal(result.err)
		}
		frame, err := wire.DecodeStream(result.data, request.RequestID, 1)
		if err != nil || frame.Error == nil || frame.Error.Code != api.CodeUnavailable {
			t.Fatal("principal watcher limit lost explicit refusal", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("principal watcher limit did not respond")
	}
	other := scope
	other.Actor.ID, other.Actor.LifeID = fixtureID(t), fixtureID(t)
	open(other)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("full principal quota blocked another principal")
	}
}

type uncooperativeStream struct {
	ready   chan struct{}
	release chan struct{}
	exited  chan struct{}
}

func (s *uncooperativeStream) Next(context.Context) (api.StreamFrame, error) {
	close(s.ready)
	<-s.release
	close(s.exited)
	return api.StreamFrame{}, context.Canceled
}
func (*uncooperativeStream) Close() error { return nil }

func TestUncooperativeProducerIsBounded(t *testing.T) {
	s := fixtureServer(t)
	scope := s.deps.Authenticator.(*authFixture).scope
	request := requestFor(t, "lane.attach", api.AttachRequest{Target: api.LifeRef{LifeID: scope.Actor.LifeID, Run: 1}, Mode: "output"})
	frame := queueFrame([]byte("snapshot"))
	frame.RequestID, frame.Index = request.RequestID, 1
	initial, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	producer := &uncooperativeStream{ready: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	if err := s.RegisterStream("lane.attach", func(context.Context, api.Scope, json.RawMessage) (api.EventStream, error) { return producer, nil }); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		close(producer.release)
		b.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("uncooperative fixture watcher was not collected")
		}
		select {
		case <-producer.exited:
		case <-time.After(3 * time.Second):
			t.Error("released fixture producer was not collected")
		}
	})
	go func() { defer close(done); defer a.Close(); s.serveStream(ctx, a, scope, request, initial) }()
	select {
	case <-producer.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("producer collection control did not start")
	}
	cancel()
	if err := b.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadFrame(b); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("uncooperative producer pinned watcher")
	}
	s.mu.RLock()
	fault := s.fault
	s.mu.RUnlock()
	if fault == nil {
		t.Fatal("uncollected producer did not record integrity fault")
	}
	codeIs(t, fault, api.CodeIntegrity)
}
