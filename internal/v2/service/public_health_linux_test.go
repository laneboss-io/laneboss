//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/store"
)

// This uses the production listener, credential framing and private handler.
// It proves negative replies only; no mocked listener or successful enrollment
// stands in for the separately required installed root-helper E2E.
func TestEnrollmentNativeRefusals(t *testing.T) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Fatal("native refusal controls require the unprivileged Linux test user")
	}
	digest, err := wire.ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name, field string
		code        api.ErrorCode
		edit        func(*api.AdminEnrollmentFrame)
		malformed   bool
	}{
		{"native_peer", "peer_uid", api.CodeInvalid, nil, false},
		{"generation", "generation", api.CodeForbidden, func(f *api.AdminEnrollmentFrame) { f.Generation++ }, false},
		{"config", "config", api.CodeForbidden, func(f *api.AdminEnrollmentFrame) { f.Config = "foreign" }, false},
		{"nonce", "nonce", api.CodeForbidden, func(f *api.AdminEnrollmentFrame) { f.Nonce = "short" }, false},
		{"malformed", "frame", api.CodeInvalid, nil, true},
	} {
		t.Run(check.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			path := filepath.Join(t.TempDir(), "enrollment.sock")
			binding := api.InstalledBinding{Config: "service-fixture", Socket: path,
				ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), InstallationGeneration: 2}
			listener, err := listenAdministrator(ctx, binding)
			if err != nil {
				t.Fatal("actual administrator listener did not open", err)
			}
			t.Cleanup(func() {
				if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error("native refusal listener close failed", err)
				}
			})
			endpoint := api.AdminEnrollmentEndpoint{Config: binding.Config, Socket: path, ServiceUID: binding.ServiceUID,
				InstallationGeneration: binding.InstallationGeneration, Origin: "https://configured.example", RPID: "configured.example",
				Helper: api.Executable{ID: "helper", Version: release.Version, SHA256: digest}}
			server := fixtureServer(t)
			server.options.AdminEnrollment = &endpoint
			done := make(chan error, 1)
			go func() {
				accepted, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				server.serveEnrollment(ctx, accepted, binding)
				done <- accepted.Close()
			}()
			connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error("native refusal client close failed", err)
				}
			})
			if err := wire.EnableCredentials(connection); err != nil {
				t.Fatal(err)
			}
			if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			request := api.AdminEnrollmentFrame{Protocol: api.AdminEnrollmentProtocol, Revision: api.ContractRevision,
				Config: binding.Config, Generation: binding.InstallationGeneration, ArtifactSHA256: digest,
				Nonce: fixtureID(t), Method: "enroll_begin", Params: json.RawMessage("{}")}
			if check.edit != nil {
				check.edit(&request)
			}
			data, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if check.malformed {
				data = []byte("{")
			}
			if err := wire.WriteFrame(connection, data); err != nil {
				t.Fatal(err)
			}
			peer, err := wire.PeerCredentials(connection)
			if err != nil {
				t.Fatal(err)
			}
			frame, err := wire.ReadPinnedFrame(connection, peer)
			if err != nil {
				t.Fatal("private listener closed without a typed refusal", err)
			}
			var reply api.AdminEnrollmentReply
			if err := api.DecodeObject(frame.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if err := api.ValidateAdminEnrollmentReply(reply, request); err != nil || reply.Error == nil ||
				reply.Error.Code != check.code || reply.Error.Owner != "lb-v2-admin" || reply.FailureField != check.field || len(reply.Result) != 0 {
				t.Fatal("native refusal lost correlation, field or actual error", err)
			}
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("native refusal worker did not finish")
			}
			if server.fault != nil {
				t.Fatal("a refused frame became a host failure")
			}
		})
	}
}

func TestEnrollmentJournalRedaction(t *testing.T) {
	canary := fixtureID(t)
	refusal := &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-admin", Message: string(canary), OperationID: canary, Instead: string(canary)}
	data, err := enrollmentJournal("nonce", refusal)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 4 || string(fields["field"]) != "\"nonce\"" ||
		string(fields["code"]) != "\"forbidden\"" || bytes.Contains(data, []byte(canary)) {
		t.Fatal("enrollment journal lost the field or disclosed a request/error value")
	}
	permission := &os.PathError{Op: "open", Path: string(canary), Err: os.ErrPermission}
	typed := enrollmentError("helper_executable", api.AdminEnrollmentFailure("helper_executable", permission))
	if typed.Code != api.CodePrerequisite || typed.Owner != "lb-v2-admin" || bytes.Contains([]byte(typed.Message), []byte(canary)) {
		t.Fatal("native prerequisite cause was hidden or disclosed a path")
	}
}

// Refusal closes the actual native connection, matching identity's contract.
// No authentication or authorization attempt can succeed in these tests.
type refusingHealthAuth struct {
	api.Authenticator
	authentications atomic.Int64
	authorizations  atomic.Int64
}

func (a *refusingHealthAuth) Authenticate(_ context.Context, connection api.ConnectionContext) (api.Scope, error) {
	a.authentications.Add(1)
	return api.Scope{}, errors.Join(serviceError(api.CodeUnauthenticated, "fixture caller is not enrolled"), connection.Close())
}

func (a *refusingHealthAuth) Authorize(context.Context, api.Scope, api.Request) error {
	a.authorizations.Add(1)
	return serviceError(api.CodeForbidden, "fixture caller has no authority")
}

type healthReadStore struct {
	api.StateStore
	actual    *store.Service
	snapshots atomic.Int64
	forbidden atomic.Int64
	entered   chan struct{}
	gate      <-chan struct{}
}

func (s *healthReadStore) HealthSnapshot(ctx context.Context) (api.ReadSnapshot, error) {
	snapshot, err := s.actual.HealthSnapshot(ctx)
	if err != nil {
		return snapshot, err
	}
	s.snapshots.Add(1)
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		case <-ctx.Done():
			return snapshot, ctx.Err()
		}
	}
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return snapshot, ctx.Err()
		}
	}
	return snapshot, nil
}

func (s *healthReadStore) Verify(context.Context, api.VerifyRequest) (api.Verification, error) {
	s.forbidden.Add(1)
	return api.Verification{}, serviceError(api.CodeForbidden, "public health attempted full state verification")
}

func (s *healthReadStore) BeginRead(context.Context, api.Scope) (api.ReadView, error) {
	s.forbidden.Add(1)
	return nil, serviceError(api.CodeForbidden, "public health attempted a scoped read")
}

func (s *healthReadStore) ObjectMetadata(context.Context, api.Scope, api.ID) (api.ObjectMetadata, error) {
	s.forbidden.Add(1)
	return api.ObjectMetadata{}, serviceError(api.CodeForbidden, "public health attempted an object read")
}

func (s *healthReadStore) Blob(context.Context, api.Scope, api.BlobReadRequest) (api.BlobChunk, error) {
	s.forbidden.Add(1)
	return api.BlobChunk{}, serviceError(api.CodeForbidden, "public health attempted blob access")
}

type publicHealthHarness struct {
	server      *Server
	state       *healthReadStore
	auth        *refusingHealthAuth
	listener    *net.UnixListener
	ctx         context.Context
	digest      api.Digest
	head        api.Sequence
	clients     []*net.UnixConn
	done        []<-chan struct{}
	healthCalls atomic.Int64
	dispatched  atomic.Int64
}

// Real Linux socket credentials and SQLite are composed under explicit host
// fixtures. This does not replace the installed service/UID E2E.
func newPublicHealthHarness(t *testing.T, credentials bool) *publicHealthHarness {
	t.Helper()
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Fatal("public health fixtures require an unprivileged Linux test user")
	}
	directory := privateHostDirectory(t)
	actual, err := store.New(store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := actual.Close(); err != nil {
			t.Error(err)
		}
	})
	socketRecord(t, &actual, directory)
	snapshot, err := actual.HealthSnapshot(context.Background())
	if err != nil || snapshot.LastSeq == 0 {
		t.Fatal("health fixture has no actual journal head", err)
	}
	path := filepath.Join(t.TempDir(), "health.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	if credentials {
		if err := wire.EnableCredentials(listener); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := wire.ArtifactDigest()
	if err != nil {
		t.Fatal(err)
	}
	state := &healthReadStore{StateStore: actual, actual: actual}
	auth := &refusingHealthAuth{}
	server := fixtureServer(t)
	server.deps.Store, server.deps.Authenticator = state, auth
	server.deps.Binding = api.InstalledBinding{Schema: "laneboss.binding.v2", Config: "service-fixture", Class: api.EndpointHuman,
		Socket: path, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()),
		EndpointGeneration: 1, InstallationGeneration: 1, ArtifactSHA256: digest, ServiceVersion: release.Version,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision, Backend: "linux-bwrap-landlock"}
	if err := api.ValidateBinding(server.deps.Binding, server.options.Config, release.Version); err != nil {
		t.Fatal("native health binding control failed", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	h := &publicHealthHarness{server: server, state: state, auth: auth, listener: listener, ctx: ctx, digest: digest, head: snapshot.LastSeq}
	t.Cleanup(func() {
		cancel()
		for _, client := range h.clients {
			if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		}
		for _, done := range h.done {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("public health fixture retained a connection worker")
			}
		}
	})
	core, err := New(server.deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Register(server); err != nil {
		t.Fatal(err)
	}
	health := server.handlers["health"]
	server.handlers["health"] = func(ctx context.Context, scope api.Scope, params json.RawMessage) (json.RawMessage, error) {
		h.healthCalls.Add(1)
		if !reflect.ValueOf(scope).IsZero() {
			return nil, serviceError(api.CodeIntegrity, "public health was given a scope")
		}
		return health(ctx, scope, params)
	}
	if err := server.Register("identity.self", func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
		h.dispatched.Add(1)
		return nil, serviceError(api.CodeIntegrity, "unenrolled method reached dispatch")
	}); err != nil {
		t.Fatal(err)
	}
	server.verified, server.bound, server.serving = true, true, true
	return h
}

func (h *publicHealthHarness) connect(t *testing.T) (*net.UnixConn, <-chan struct{}) {
	t.Helper()
	client, err := net.DialUnix("unix", nil, h.listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	h.clients = append(h.clients, client)
	if err := h.listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	accepted, err := h.listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := wire.PeerCredentials(accepted)
	if err != nil || peer.UID != uint32(os.Geteuid()) || peer.GID != uint32(os.Getegid()) || peer.PID != os.Getpid() {
		accepted.Close()
		t.Fatal("native health connector evidence differs", err)
	}
	if err := client.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		accepted.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	h.done = append(h.done, done)
	go func() { defer close(done); h.server.serveConnection(h.ctx, accepted) }()
	return client, done
}

func (h *publicHealthHarness) request(t *testing.T) api.Request {
	t.Helper()
	return requestFor(t, "health", api.HealthRequest{ClientVersion: release.Version, ArtifactSHA256: h.digest})
}

func publicFrame(t *testing.T, request api.Request) []byte {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (h *publicHealthHarness) readHealth(t *testing.T, client *net.UnixConn, request api.Request) {
	t.Helper()
	data, err := wire.ReadFrame(client)
	if err != nil {
		t.Fatal("unenrolled native peer did not receive health", err)
	}
	response, err := wire.DecodeResponse(data, request)
	if err != nil || response.Error != nil {
		t.Fatal("public health response failed", err, response.Error)
	}
	var health api.Health
	if err := wire.Decode(response.Result, &health); err != nil {
		t.Fatal(err)
	}
	if health.ArtifactSHA256 != h.digest || health.ServiceVersion != release.Version || response.LastSeq != h.head {
		t.Fatal("public health lost its actual artifact or journal head")
	}
	if health.Ready {
		t.Fatal("incomplete component host falsely reported ready")
	}
	seen := map[string]bool{}
	for _, capability := range health.Capabilities {
		if capability.Name == "native-peer" || capability.Name == "binding-shape" || capability.Name == "state-snapshot" {
			seen[capability.Name] = capability.Available
		}
	}
	if !seen["native-peer"] || !seen["binding-shape"] || !seen["state-snapshot"] {
		t.Fatal("public health lost native, binding or snapshot observations")
	}
}

func healthSocketClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, net.ErrClosed)
}

func waitHealthClosed(t *testing.T, client *net.UnixConn, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("public health did not close its one-request connection")
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var next [1]byte
	n, err := client.Read(next[:])
	if n != 0 || !healthSocketClosed(err) {
		t.Fatal("public health connection carried another response or stayed open", err)
	}
}

func (h *publicHealthHarness) assertNoAuthority(t *testing.T) {
	t.Helper()
	if h.auth.authentications.Load() != 0 || h.auth.authorizations.Load() != 0 || h.dispatched.Load() != 0 || h.state.forbidden.Load() != 0 {
		t.Fatal("public health used authentication, dispatch or scoped state")
	}
}

func TestUnenrolledNativeHealth(t *testing.T) {
	h := newPublicHealthHarness(t, true)
	client, done := h.connect(t)
	request := h.request(t)
	if err := wire.WriteFrame(client, publicFrame(t, request)); err != nil {
		t.Fatal(err)
	}
	h.readHealth(t, client, request)
	waitHealthClosed(t, client, done)
	h.assertNoAuthority(t)
	if h.state.snapshots.Load() != 1 || h.healthCalls.Load() != 1 {
		t.Fatal("public health did not use exactly one health snapshot and handler")
	}
}

func assertHealthVariant(t *testing.T, reason string, available bool) {
	t.Helper()
	h := newPublicHealthHarness(t, true)
	client, done := h.connect(t)
	request := h.request(t)
	if err := wire.WriteFrame(client, publicFrame(t, request)); err != nil {
		t.Fatal(err)
	}
	data, err := wire.ReadFrame(client)
	if err != nil {
		t.Fatal("variant health read failed", err)
	}
	response, err := wire.DecodeResponse(data, request)
	if err != nil || response.Error != nil {
		t.Fatal("variant health response failed", err, response.Error)
	}
	var health api.Health
	if err := wire.Decode(response.Result, &health); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, capability := range health.Capabilities {
		if capability.Name == "build-variant" {
			found = capability.Reason == reason && capability.Available == available
		}
	}
	if !found {
		t.Fatal("health omitted the compiled build variant")
	}
	if !available && health.Ready {
		t.Fatal("test build variant reported production readiness")
	}
	waitHealthClosed(t, client, done)
	h.assertNoAuthority(t)
}

// This fixture supplies an authenticated component read view from the actual
// store head. It isolates native frame routing, not production enrollment.
type openedHealthStore struct {
	*healthReadStore
	reads atomic.Int64
}

func (s *openedHealthStore) BeginRead(ctx context.Context, scope api.Scope) (api.ReadView, error) {
	s.reads.Add(1)
	if scope.Connection == nil || scope.Actor.Kind != "human" {
		return nil, serviceError(api.CodeForbidden, "opened health fixture requires its authenticated scope")
	}
	snapshot, err := s.actual.HealthSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	if scope.Config != snapshot.Config {
		return nil, serviceError(api.CodeForbidden, "opened health fixture configuration differs")
	}
	return receiptView{snapshot: snapshot}, nil
}

func TestOpenedConnectionRejectsHealth(t *testing.T) {
	h := newPublicHealthHarness(t, true)
	public, publicDone := h.connect(t)
	first := h.request(t)
	if err := wire.WriteFrame(public, publicFrame(t, first)); err != nil {
		t.Fatal(err)
	}
	h.readHealth(t, public, first)
	waitHealthClosed(t, public, publicDone)
	h.assertNoAuthority(t)

	auth := &authFixture{scope: api.Scope{Config: h.server.options.Config,
		Actor: api.Actor{Kind: "human", ID: fixtureID(t)}, EndpointGeneration: h.server.deps.Binding.EndpointGeneration}}
	state := &openedHealthStore{healthReadStore: h.state}
	h.server.deps.Authenticator, h.server.deps.Store = auth, state
	h.server.handlers["identity.self"] = identityHandler
	client, _ := h.connect(t)
	exchange := func(request api.Request) api.Response {
		t.Helper()
		if err := wire.WriteFrame(client, publicFrame(t, request)); err != nil {
			t.Fatal("opened connection write failed", err)
		}
		data, err := wire.ReadFrame(client)
		if err != nil {
			t.Fatal("opened connection read failed", err)
		}
		response, err := wire.DecodeResponse(data, request)
		if err != nil {
			t.Fatal("opened connection response is invalid", err)
		}
		return response
	}
	identity := requestFor(t, "identity.self", api.Empty{})
	response := exchange(identity)
	var scope api.Scope
	if response.Error != nil || wire.Decode(response.Result, &scope) != nil || scope.Actor != auth.scope.Actor || response.LastSeq != h.head || state.reads.Load() != 1 {
		t.Fatal("authenticated first-frame control failed", response.Error)
	}
	auth.mu.Lock()
	before := auth.calls
	auth.mu.Unlock()
	response = exchange(h.request(t))
	if h.healthCalls.Load() != 1 || h.state.forbidden.Load() != 0 || state.reads.Load() != 1 || h.state.snapshots.Load() != 1 {
		t.Fatal("opened connection dispatched health")
	}
	if response.Error == nil || response.Error.Code != api.CodeForbidden {
		t.Fatal("later health did not return the first-frame refusal", response.Error)
	}
	auth.mu.Lock()
	after := auth.calls
	auth.mu.Unlock()
	if after != before {
		t.Fatal("later health entered ordinary authentication")
	}
	response = exchange(requestFor(t, "identity.self", api.Empty{}))
	if response.Error != nil || state.reads.Load() != 2 {
		t.Fatal("health refusal broke the authenticated connection", response.Error)
	}
}

func TestHealthNeedsPublicContext(t *testing.T) {
	h := newPublicHealthHarness(t, true)
	core, err := New(h.server.deps)
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.Health(context.Background(), api.Scope{}, api.HealthRequest{ClientVersion: release.Version, ArtifactSHA256: h.digest})
	if err == nil {
		t.Fatal("health without public context was accepted")
	}
	codeIs(t, err, api.CodeForbidden)
	if h.state.forbidden.Load() != 0 || h.state.snapshots.Load() != 0 {
		t.Fatal("health without public context accessed state")
	}
	client, done := h.connect(t)
	request := h.request(t)
	if err := wire.WriteFrame(client, publicFrame(t, request)); err != nil {
		t.Fatal(err)
	}
	h.readHealth(t, client, request)
	waitHealthClosed(t, client, done)
	h.assertNoAuthority(t)
}

func TestUnauthenticatedFirstMethod(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			h := newPublicHealthHarness(t, true)
			client, done := h.connect(t)
			var params any = api.Empty{}
			if invalid {
				params = map[string]any{"extra": true}
			}
			request := requestFor(t, "identity.self", params)
			if err := wire.WriteFrame(client, publicFrame(t, request)); err != nil && !healthSocketClosed(err) {
				t.Fatal(err)
			}
			data, readErr := wire.ReadFrame(client)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("unauthenticated first method did not fail closed")
			}
			if h.dispatched.Load() != 0 || h.state.snapshots.Load() != 0 || h.state.forbidden.Load() != 0 || h.auth.authorizations.Load() != 0 {
				t.Fatal("unauthenticated first method reached dispatch or state")
			}
			if invalid {
				if h.auth.authentications.Load() != 0 {
					t.Fatal("first-frame validation ran after authentication")
				}
				var response api.Response
				if readErr != nil || wire.Decode(data, &response) != nil || response.Error == nil || response.Error.Code != api.CodeInvalid {
					t.Fatal("invalid first method lost its protocol refusal", readErr)
				}
			} else {
				response, err := wire.DecodeResponse(data, request)
				if h.auth.authentications.Load() != 1 || readErr != nil || err != nil || response.Error == nil ||
					response.Error.Code != api.CodeUnauthenticated || response.Error.Message != "service connection refused at authentication" {
					t.Fatal("non-health first method lost its correlated authentication refusal", readErr, err)
				}
				waitHealthClosed(t, client, done)
			}
		})
	}
}

func TestPublicHealthClosesBeforeSecond(t *testing.T) {
	h := newPublicHealthHarness(t, true)
	client, done := h.connect(t)
	request := h.request(t)
	if err := wire.WriteFrame(client, publicFrame(t, request)); err != nil {
		t.Fatal(err)
	}
	h.readHealth(t, client, request)
	second := requestFor(t, "identity.self", api.Empty{})
	if err := wire.WriteFrame(client, publicFrame(t, second)); err != nil && !healthSocketClosed(err) {
		t.Fatal("second-frame canary failed without a closed connection", err)
	}
	waitHealthClosed(t, client, done)
	h.assertNoAuthority(t)
	if h.state.snapshots.Load() != 1 || h.healthCalls.Load() != 1 {
		t.Fatal("public health consumed a second request")
	}
}

func TestPublicHealthRejectsAuthority(t *testing.T) {
	for _, kind := range []string{"proof", "params", "objects", "envelope"} {
		t.Run(kind, func(t *testing.T) {
			h := newPublicHealthHarness(t, true)
			client, done := h.connect(t)
			request := h.request(t)
			if kind == "proof" {
				request.Proof = &api.ProofRef{ID: fixtureID(t), RequestSHA256: request.RequestSHA256,
					ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}
				if err := wire.ValidateRequest(request); err != nil {
					t.Fatal("proof canary has invalid transport shape", err)
				}
			}
			if kind == "params" {
				request = requestFor(t, "health", map[string]any{"client_version": release.Version, "artifact_sha256": h.digest, "objects": []any{}})
			}
			data := publicFrame(t, request)
			if kind == "objects" || kind == "envelope" {
				var object map[string]json.RawMessage
				if err := json.Unmarshal(data, &object); err != nil {
					t.Fatal(err)
				}
				if kind == "objects" {
					object["objects"] = json.RawMessage(`[]`)
				} else {
					object["extra"] = json.RawMessage(`true`)
				}
				var err error
				data, err = json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := wire.WriteFrame(client, data); err != nil {
				t.Fatal(err)
			}
			data, err := wire.ReadFrame(client)
			if err != nil {
				t.Fatal("public health authority refusal was not returned", err)
			}
			var response api.Response
			if err := wire.Decode(data, &response); err != nil || response.Error == nil || response.Error.Code != api.CodeInvalid || len(response.Result) != 0 {
				t.Fatal("public health accepted proof, objects or extra fields", err)
			}
			waitHealthClosed(t, client, done)
			h.assertNoAuthority(t)
			if h.state.snapshots.Load() != 0 || h.healthCalls.Load() != 0 {
				t.Fatal("invalid public health reached state or its handler")
			}
		})
	}
}

func TestPublicHealthUIDAdmission(t *testing.T) {
	h := newPublicHealthHarness(t, true)
	gate := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	h.state.gate, h.state.entered = gate, make(chan struct{}, 16)
	var clients []*net.UnixConn
	var ends []<-chan struct{}
	var requests []api.Request
	for index := 0; index < 8; index++ {
		client, done := h.connect(t)
		request := h.request(t)
		if err := wire.WriteFrame(client, publicFrame(t, request)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-h.state.entered:
		case <-done:
			t.Fatal("connection closed before public health admission reached its snapshot")
		case <-h.ctx.Done():
			t.Fatal("public health admission control never reached eight snapshots")
		}
		clients, ends, requests = append(clients, client), append(ends, done), append(requests, request)
	}
	h.server.mu.RLock()
	count := h.server.admissions["uid:"+fmt.Sprint(os.Geteuid())]
	h.server.mu.RUnlock()
	if count != 8 {
		t.Fatal("public health admission is not keyed by kernel UID")
	}
	ninth, ninthDone := h.connect(t)
	if err := wire.WriteFrame(ninth, publicFrame(t, h.request(t))); err != nil && !healthSocketClosed(err) {
		t.Fatal(err)
	}
	select {
	case <-h.state.entered:
		t.Fatal("public health exceeded the per-UID admission limit")
	case <-ninthDone:
	case <-h.ctx.Done():
		t.Fatal("public health admission refusal did not close")
	}
	waitHealthClosed(t, ninth, ninthDone)
	if h.state.snapshots.Load() != 8 {
		t.Fatal("over-limit public health accessed the snapshot")
	}
	release.Do(func() { close(gate) })
	for index, client := range clients {
		h.readHealth(t, client, requests[index])
		waitHealthClosed(t, client, ends[index])
	}
	control, controlDone := h.connect(t)
	controlRequest := h.request(t)
	if err := wire.WriteFrame(control, publicFrame(t, controlRequest)); err != nil {
		t.Fatal(err)
	}
	h.readHealth(t, control, controlRequest)
	waitHealthClosed(t, control, controlDone)
	h.assertNoAuthority(t)
	h.server.mu.RLock()
	remaining := len(h.server.admissions)
	h.server.mu.RUnlock()
	if remaining != 0 || h.state.snapshots.Load() != 9 || h.healthCalls.Load() != 9 {
		t.Fatal("public health did not release admission or retain exact call counts")
	}
}

func TestPublicHealthWriterGate(t *testing.T) {
	for _, rights := range []bool{false, true} {
		t.Run(fmt.Sprint(rights), func(t *testing.T) {
			h := newPublicHealthHarness(t, rights)
			client, done := h.connect(t)
			data := publicFrame(t, h.request(t))
			if rights {
				file, err := os.CreateTemp(t.TempDir(), "health-fd")
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := file.Close(); err != nil {
						t.Error(err)
					}
				}()
				packet := make([]byte, 4+len(data))
				binary.BigEndian.PutUint32(packet, uint32(len(data)))
				copy(packet[4:], data)
				n, _, err := client.WriteMsgUnix(packet, unix.UnixRights(int(file.Fd())), nil)
				if err != nil || n != len(packet) {
					t.Fatal("descriptor canary did not reach the socket", err)
				}
				// Missing credentials can be refused at the header, before the
				// remaining payload write completes. Only closure is an allowed error.
			} else if err := wire.WriteFrame(client, data); err != nil && !healthSocketClosed(err) {
				t.Fatal(err)
			}
			data, readErr := wire.ReadFrame(client)
			if readErr == nil {
				var response api.Response
				if err := wire.Decode(data, &response); err != nil || response.Error == nil || response.Error.Code != api.CodeInvalid || len(response.Result) != 0 {
					t.Fatal("public health accepted missing credentials or descriptor transfer", err)
				}
			} else if !healthSocketClosed(readErr) {
				t.Fatal("native writer refusal did not complete", readErr)
			}
			waitHealthClosed(t, client, done)
			h.assertNoAuthority(t)
			if h.state.snapshots.Load() != 0 || h.healthCalls.Load() != 0 {
				t.Fatal("invalid native writer reached public health")
			}
		})
	}
}
