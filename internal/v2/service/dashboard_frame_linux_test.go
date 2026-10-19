//go:build linux

package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/approval"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/dashboard"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/messaging"
	"laneboss.io/laneboss/internal/v2/store"
)

// Only the installed peer-verifier boundary and prior enrollment are fixture
// inputs. Every frame comes from the real credential-aware Unix transport;
// identity verifies signatures and the real store commits challenges/proofs.
type dashboardFramePeers struct{}

type dashboardEventRead struct {
	scope api.Scope
	tail  api.EventTailRequest
}

type dashboardEventStore struct {
	*store.Service
	reads []dashboardEventRead
}

func (s *dashboardEventStore) Events(ctx context.Context, scope api.Scope, tail api.EventTailRequest) (api.EventPage, error) {
	s.reads = append(s.reads, dashboardEventRead{scope: scope, tail: tail})
	return s.Service.Events(ctx, scope, tail)
}

func (dashboardFramePeers) Verify(_ context.Context, connection net.Conn, _ api.InstalledBinding) (api.VerifiedPeer, error) {
	peer, err := wire.PeerCredentials(connection.(*net.UnixConn))
	if err != nil {
		return nil, err
	}
	return &peerFixture{facts: api.PeerFacts{HostUID: peer.UID, HostGID: peer.GID,
		HostPID: peer.PID, ProcessGeneration: "dashboard-frame-component"}}, nil
}

func TestDashboardEntryBootstrapStoreFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	directory := privateHostDirectory(t)
	state, err := store.New(store.Dependencies{Config: "service-fixture", Directory: directory, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	host := fixtureServer(t)
	actor := api.Actor{Kind: "human", ID: fixtureID(t)}
	binding := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: "service-fixture", Class: api.EndpointHuman,
		InstallationGeneration: 1, EndpointGeneration: 1, ServiceVersion: release.Version,
		ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid()), Socket: filepath.Join(directory, "human.sock"),
		ArtifactSHA256: digestBytes([]byte("dashboard component executable")), Backend: "linux-bwrap-landlock"}
	setup := api.Scope{Config: binding.Config, Actor: api.Actor{Kind: "service", ID: fixtureID(t)}, Source: "service"}
	policy := dashPlanOrg(t, state, setup)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	credential := api.HumanCredential{ID: fixtureID(t), RawCredentialID: public, Algorithm: "Ed25519", PublicKeyDER: der, Generation: 1}
	enrollment := api.HumanEnrollment{Config: binding.Config, PrincipalID: actor.ID, Origin: "https://dashboard.invalid", RPID: "dashboard.invalid",
		Generation: 1, Credentials: []api.HumanCredential{credential}}
	grantsFlowProjection(t, directory, "enrollment", actor.ID, enrollment)
	identities, err := identity.New(identity.Dependencies{Peers: dashboardFramePeers{}, Registry: &grantsFlowPorts{},
		Store: state, Sessions: state, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	host.deps.Store, host.deps.Binding, host.deps.Authenticator = state, binding, identities
	if err := identities.Register(host); err != nil {
		t.Fatal(err)
	}
	readStore := &dashboardEventStore{Service: state}
	host.deps.Store = readStore
	// These owners are unreached by the read regression; every reached
	// dashboard, dispatcher, identity and store operation is production code.
	views, err := dashboard.New(dashboard.Dependencies{Transport: host, Store: readStore, Human: identities,
		Identity: identities, Authenticator: identities, Lifecycle: &lifecycle.Service{},
		Messaging: &messaging.Service{}, Approval: &approval.Service{}, Clock: fixtureClock{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := views.Register(host); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: binding.Socket + ".browser", Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := wire.EnableCredentials(listener); err != nil {
		t.Fatal(err)
	}
	connect := func() (*net.UnixConn, func(any, any), DashboardConnection) {
		t.Helper()
		dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error { return wire.EnableRawCredentials(raw) }}
		client, err := dialer.DialContext(ctx, "unix", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { defer close(done); host.serveDashboardEntry(ctx, accepted) }()
		t.Cleanup(func() {
			_ = client.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("dashboard native connection did not quiesce")
			}
		})
		socket := client.(*net.UnixConn)
		peer, err := wire.PeerCredentials(socket)
		if err != nil {
			t.Fatal(err)
		}
		exchange := func(request, result any) {
			t.Helper()
			if err := socket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := wire.WriteFrame(socket, fixtureJSON(t, request)); err != nil {
				t.Fatal(err)
			}
			raw, err := wire.ReadFrame(&entryPeerReader{socket: socket, peer: peer})
			if err != nil {
				t.Fatal(err)
			}
			var response struct {
				Result json.RawMessage `json:"result"`
				Error  *api.Error      `json:"error"`
			}
			if err := json.Unmarshal(raw, &response); err != nil {
				t.Fatal(err)
			}
			if response.Error != nil {
				t.Fatalf("native dashboard submission refused: %s: %s", response.Error.Code, response.Error.Message)
			}
			if err := json.Unmarshal(response.Result, result); err != nil {
				t.Fatal(err)
			}
		}
		var opened DashboardConnection
		exchange(DashboardEntryRequest{Protocol: DashboardEntryProtocol, Action: "open"}, &opened)
		if opened.Config != binding.Config || opened.Actor != actor || opened.ConnectionID == "" {
			t.Fatal("native dashboard opened another principal")
		}
		return socket, exchange, opened
	}
	_, issuerCall, issuer := connect()
	_, redemptionCall, redemption := connect()
	var counter uint32
	signIntent := func(call func(any, any), connectionID api.ID, request api.Request, target api.HumanChallengeRequest) api.Request {
		t.Helper()
		var challenge api.HumanChallenge
		call(requestFor(t, "human.challenge", target), &challenge)
		if challenge.Method != target.Method || challenge.TargetID != target.TargetID || challenge.RequestSHA256 != target.RequestSHA256 {
			t.Fatal("native challenge changed the session intent")
		}
		clientData := fixtureJSON(t, map[string]any{"type": "webauthn.get", "origin": enrollment.Origin,
			"challenge": base64.RawURLEncoding.EncodeToString(challenge.Challenge), "crossOrigin": false})
		authData := make([]byte, 37)
		rp := sha256.Sum256([]byte(enrollment.RPID))
		copy(authData, rp[:])
		authData[32] = 0x05
		counter++
		binary.BigEndian.PutUint32(authData[33:], counter)
		clientHash := sha256.Sum256(clientData)
		assertion := api.HumanConfirmRequest{ChallengeID: challenge.ID, CredentialID: credential.ID, ClientDataJSON: clientData,
			AuthenticatorData: authData, Signature: ed25519.Sign(private, append(append([]byte(nil), authData...), clientHash[:]...))}
		var proof api.ProofRef
		call(requestFor(t, "human.confirm", assertion), &proof)
		request.Proof = &proof
		host.mu.RLock()
		connection := host.connections[connectionID]
		host.mu.RUnlock()
		scope, err := identities.CurrentConnectionScope(ctx, connection)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := state.Proof(ctx, scope, proof.ID)
		if err != nil || stored.ConnectionID != connectionID || stored.Target != target || stored.Ref != proof || stored.CredentialID != credential.ID {
			t.Fatal("signed native confirmation did not retain its exact proof", err)
		}
		return request
	}
	sessionIntent := func(call func(any, any), connectionID api.ID) api.Request {
		t.Helper()
		request := requestFor(t, "human.session", api.HumanSessionRequest{})
		return signIntent(call, connectionID, request, api.HumanChallengeRequest{
			Method: request.Method, TargetID: actor.ID, RequestSHA256: request.RequestSHA256})
	}
	var session api.HumanSession
	issuerCall(sessionIntent(issuerCall, issuer.ConnectionID), &session)
	request := sessionIntent(redemptionCall, redemption.ConnectionID)
	host.mu.RLock()
	redemptionConnection := host.connections[redemption.ConnectionID]
	host.mu.RUnlock()
	scope, err := identities.CurrentConnectionScope(ctx, redemptionConnection)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request, scope.Source = request, "cli"
	if !api.Methods[request.Method].Mutation {
		t.Fatal("dashboard session lost its mutation classification")
	}
	_, err = state.AuthorizationTarget(ctx, scope, request)
	var refusal *api.Error
	if !errors.As(err, &refusal) || refusal.Code != api.CodeUnauthenticated || refusal.Message != "public mutation lacks its credential-verified frame" {
		t.Fatal("unframed public mutation was not refused at the store gate", err)
	}
	// Accept a third native client without serving it. The frame below is the
	// real credential-aware transport's receivedFrame, not a test FrameContext.
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error { return wire.EnableRawCredentials(raw) }}
	thirdClient, err := dialer.DialContext(ctx, "unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer thirdClient.Close()
	thirdSocket, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer thirdSocket.Close()
	if err := thirdSocket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writer, err := wire.PeerCredentials(thirdSocket)
	if err != nil {
		t.Fatal(err)
	}
	thirdRaw := fixtureJSON(t, request)
	if err := wire.WriteFrame(thirdClient, thirdRaw); err != nil {
		t.Fatal(err)
	}
	thirdFrame, err := wire.ReadPinnedFrame(thirdSocket, writer)
	if err != nil || !bytes.Equal(thirdFrame.Bytes(), thirdRaw) {
		t.Fatal("third native frame did not retain its actual request bytes", err)
	}
	t.Logf("store control uses %T with %d received bytes", thirdFrame, len(thirdRaw))
	thirdConnection, err := newConnection(thirdSocket, binding, fixtureClock{})
	if err != nil {
		t.Fatal(err)
	}
	defer thirdConnection.Close()
	pinned := &peerFixture{facts: api.PeerFacts{HostUID: writer.UID, HostGID: writer.GID,
		HostPID: writer.PID, ProcessGeneration: "dashboard-third-frame-component"}}
	if err := thirdConnection.BindPeer(pinned); err != nil {
		t.Fatal(err)
	}
	// The receiving socket and its actual kernel writer must pass the same
	// store gate before either binding is deliberately made inconsistent.
	matched := scope
	matched.Connection, matched.Frame = thirdConnection, thirdFrame
	target, err := state.AuthorizationTarget(ctx, matched, request)
	if err != nil || target.Method != request.Method || target.TargetID != actor.ID || target.RequestSHA256 != request.RequestSHA256 {
		t.Fatal("real received frame failed its matching store-gate control", err)
	}
	t.Run("real-frame-connection", func(t *testing.T) {
		foreign := scope
		foreign.Frame = thirdFrame // Its socket is not the dashboard redemption socket.
		_, err := state.AuthorizationTarget(ctx, foreign, request)
		var refused *api.Error
		if !errors.As(err, &refused) || refused.Code != api.CodeInvalid || refused.Message != "frame lacks its authenticated connection" {
			t.Fatalf("store gate accepted a real frame from another connection or lost its refusal: %v", err)
		}
		t.Log(refused.Message)
	})
	t.Run("real-frame-writer", func(t *testing.T) {
		// Peer identity is the declared component boundary. Change only its
		// pinned PID; the actual received socket, bytes and kernel writer stay fixed.
		before := pinned.facts
		pinned.facts.HostPID++
		defer func() { pinned.facts = before }()
		_, err := state.AuthorizationTarget(ctx, matched, request)
		var refused *api.Error
		if !errors.As(err, &refused) || refused.Code != api.CodeUnauthenticated || refused.Message != "frame writer differs from pinned connector" {
			t.Fatalf("store gate accepted a real frame from another pinned writer or lost its refusal: %v", err)
		}
		t.Log(refused.Message)
	})
	nonce := []byte("dashboard-browser-component-nonce")
	var bootstrap dashboard.BootstrapBinding
	issuerCall(DashboardEntryRequest{Protocol: DashboardEntryProtocol, Action: "bootstrap", RedeemID: redemption.ConnectionID,
		Nonce: nonce, Session: &request}, &bootstrap)
	if bootstrap.ConnectionID != redemption.ConnectionID || bootstrap.Actor != actor || bootstrap.Proof != *request.Proof || bootstrap.Token == "" {
		t.Fatal("dashboard bootstrap lost its verified redemption intent")
	}
	if _, err := redemptionConnection.ReadAuthority(ctx); err == nil {
		t.Fatal("native bootstrap minted a read session before browser redemption")
	}
	connection, retained, err := host.loadDashboardBootstrap(ctx, bootstrap.Token, nonce, false)
	if err != nil || connection != redemptionConnection || retained != bootstrap {
		t.Fatal("native bootstrap did not retain its actual binding", err)
	}
	if !bytes.Equal(request.Params, []byte("{}")) {
		t.Fatal("session request parameters changed during the handoff")
	}

	// Prior lane projections are explicit component inputs. Their observation
	// events are committed by the real writer and read through the real gate.
	lives := []api.ID{fixtureID(t), fixtureID(t)}
	for i, life := range lives {
		ref := api.BlobRef{ID: fixtureID(t), Class: "task", Bytes: 1, SHA256: digestBytes([]byte("task"))}
		lane := api.Lane{Task: ref, LaunchID: fixtureID(t), CancellationEpoch: 1, ProfileGrantID: fixtureID(t),
			Model: []string{"claude-sonnet-5-5", "gpt-6.1-sol"}[i], Effort: "high",
			BudgetRemaining: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 1 << 20, Processes: 4, DiskBytes: 1 << 20, Currency: "USD"},
			LifeID:          life, Name: "dashboard-read-" + string(life), RootLifeID: life, StarterChain: []api.ID{}, StarterEventSeq: 1,
			Run: 1, Generation: 1, State: "running", Level: 3, Role: "executor", GrantSetID: fixtureID(t), PolicyGeneration: 1,
			Session: api.Session{HistoryID: fixtureID(t), ID: fixtureID(t), HomeID: fixtureID(t), LogicalCWD: "/work/main",
				Driver: []api.Driver{api.DriverClaudock, api.DriverCodex}[i]},
			Workspace: api.Workspace{ID: fixtureID(t), ProjectID: fixtureID(t), Base: string(ref.SHA256),
				Branch: "dashboard-read", LogicalCWD: "/work/main", Snapshot: ref}}
		var decoded api.Lane
		if err := wire.Decode(fixtureJSON(t, lane), &decoded); err != nil {
			t.Fatal("prior lane fixture is not schema-valid", err)
		}
		grantsFlowProjection(t, directory, "lane", life, lane)
		content := []byte(fixtureID(t))
		record := api.Record{ID: fixtureID(t), Collection: "observations", LifeID: life, Run: lane.Run,
			Content: api.BlobRef{ID: fixtureID(t), Class: "record", Bytes: int64(len(content)), SHA256: digestBytes(content)},
			Actor:   setup.Actor, Origin: "observation", Generation: 1,
			RecordedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
		event := api.Event{Schema: api.SchemaVersion, ID: fixtureID(t), Config: setup.Config,
			Kind: "record.appended", Actor: setup.Actor, RequestedBy: setup.Actor, LifeID: life, Run: lane.Run,
			Origin: "observation", StarterChain: []api.ID{}, Payload: fixtureJSON(t, record)}
		cause := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalOrgBootstrap, Config: setup.Config, Actor: setup.Actor, RequestedBy: setup.Actor}
		if _, err := state.Transact(ctx, api.Transaction{Scope: setup, Internal: &cause, Events: []api.Event{event}}); err != nil {
			t.Fatal("dashboard observation fixture did not commit", err)
		}
	}
	treeRequest := requestFor(t, "dashboard.tree", api.DashboardQuery{Limit: 200})
	readScope, err := host.Scope(ctx, httptest.NewRequest("GET", "https://dashboard.invalid/api/v2/tree?limit=200", nil),
		treeRequest, fixtureJSON(t, treeRequest), &dashboard.SessionClaim{SessionID: session.ID,
			Actor: actor, ConnectionID: issuer.ConnectionID, EndpointGeneration: binding.EndpointGeneration})
	if err != nil {
		t.Fatal(err)
	}
	for _, tail := range []api.EventTailRequest{{}, {LifeID: lives[0]}, {LifeID: fixtureID(t)}} {
		if _, err := state.Events(ctx, readScope, tail); err == nil {
			t.Fatal("human event read with missing life/run selectors was admitted")
		} else {
			codeIs(t, err, api.CodeInvalid)
		}
	}
	unbound := readScope
	unbound.Connection, unbound.Frame, unbound.ReadAuthority = thirdConnection, nil, nil
	if page, err := state.Events(ctx, unbound, api.EventTailRequest{LifeID: lives[0], Run: 1}); err == nil || len(page.Events) != 0 {
		t.Fatal("human connection without read authority acquired selected events", err)
	} else {
		codeIs(t, err, api.CodeUnauthenticated)
	}
	foreign := readScope
	foreign.Config = "another-fixture"
	if _, err := state.Events(ctx, foreign, api.EventTailRequest{LifeID: lives[0]}); err == nil {
		t.Fatal("human acquired life-only reads in another configuration")
	} else {
		codeIs(t, err, api.CodeUnauthenticated)
	}
	if page, err := state.Events(ctx, readScope, api.EventTailRequest{LifeID: lives[0], Run: 1}); err != nil || len(page.Events) != 1 {
		t.Fatal("exact human life/run positive control failed", err)
	}
	watchdog := api.Scope{Config: setup.Config, Actor: api.Actor{Kind: "watchdog", ID: fixtureID(t)}, Source: "watchdog"}
	for _, control := range []api.Scope{setup, watchdog} {
		page, err := state.Events(ctx, control, api.EventTailRequest{LifeID: lives[0]})
		if err != nil || len(page.Events) != 1 || page.Events[0].LifeID != lives[0] {
			t.Fatal("internal/watchdog life-only reader changed", err)
		}
	}
	if page, err := state.Events(ctx, setup, api.EventTailRequest{}); err != nil || len(page.Events) == 0 {
		t.Fatal("internal configuration reader changed", err)
	}
	response, err := host.Dispatch(ctx, readScope, treeRequest)
	if err != nil {
		if len(readStore.reads) != 0 {
			seen := readStore.reads[0]
			t.Logf("dashboard read: method=%s actor=%s proof=%t life_selected=%t run=%d source=%s",
				seen.scope.Request.Method, seen.scope.Actor.Kind, seen.scope.Request.Proof != nil,
				seen.tail.LifeID != "", seen.tail.Run, seen.scope.Source)
		}
		t.Fatalf("dashboard tree event read refused: %v", err)
	}
	var tree api.TreeView
	if err := json.Unmarshal(response.Result, &tree); err != nil {
		t.Fatal(err)
	}
	if len(tree.Nodes) != len(lives) || len(readStore.reads) != len(lives) {
		t.Fatalf("dashboard tree did not select both real lives: nodes=%d reads=%d", len(tree.Nodes), len(readStore.reads))
	}
	selected := make(map[api.ID]bool)
	for _, seen := range readStore.reads {
		if seen.scope.Request.Method != "dashboard.tree" || seen.scope.Actor != actor || seen.scope.Source != "dashboard" ||
			seen.scope.Request.Proof != nil || seen.tail.Run != 1 || seen.tail.LifeID != lives[0] && seen.tail.LifeID != lives[1] {
			t.Fatal("dashboard event lookup lost its exact authorized life/run or human read scope")
		}
		selected[seen.tail.LifeID] = true
	}
	if len(selected) != len(lives) {
		t.Fatal("dashboard repeated one life instead of reading each selected life")
	}
	for _, method := range []api.Method{"dashboard.raw", "dashboard.decisions", "dashboard.refusals", "dashboard.plugins", "dashboard.resources", "dashboard.lifecycle", "dashboard.approvals"} {
		t.Run("view-"+string(method), func(t *testing.T) {
			request := requestFor(t, method, api.DashboardQuery{Limit: 200})
			scope, err := host.Scope(ctx, httptest.NewRequest("POST", "https://dashboard.invalid/api/v2/rpc", nil),
				request, fixtureJSON(t, request), &dashboard.SessionClaim{SessionID: session.ID,
					Actor: actor, ConnectionID: issuer.ConnectionID, EndpointGeneration: binding.EndpointGeneration})
			if err != nil {
				t.Fatal(err)
			}
			readStore.reads = nil
			response, err := host.Dispatch(ctx, scope, request)
			if err != nil {
				t.Fatalf("%s selected event inventory refused: %v", method, err)
			}
			if len(response.Result) == 0 || len(readStore.reads) != len(lives) {
				t.Fatalf("%s omitted its result or a selected life: reads=%d", method, len(readStore.reads))
			}
			selected := make(map[api.ID]bool)
			for _, seen := range readStore.reads {
				if seen.scope.Request.Method != method || seen.scope.Actor != actor || seen.scope.Source != "dashboard" ||
					seen.scope.Request.Proof != nil || seen.tail.Run != 1 || seen.tail.LifeID != lives[0] && seen.tail.LifeID != lives[1] {
					t.Fatalf("%s lost its selected life/run or authenticated human scope", method)
				}
				selected[seen.tail.LifeID] = true
			}
			if len(selected) != len(lives) {
				t.Fatalf("%s repeated one life instead of reading both", method)
			}
		})
	}
	t.Run("ticket-http", func(t *testing.T) {
		if err := views.ConfigureHTTP(binding.Config, enrollment.Origin, enrollment.RPID); err != nil {
			t.Fatal(err)
		}
		post := func(request api.Request, cookie *http.Cookie, bootstrap bool) *httptest.ResponseRecorder {
			t.Helper()
			r := httptest.NewRequest(http.MethodPost, enrollment.Origin+"/api/v2/rpc", bytes.NewReader(fixtureJSON(t, request)))
			r.Header.Set("Origin", enrollment.Origin)
			r.Header.Set("Content-Type", "application/json")
			if cookie != nil {
				r.AddCookie(cookie)
			}
			if bootstrap {
				r.Header.Set(dashboard.BootstrapHeader, string(retained.Token))
				r.Header.Set(dashboard.BootstrapNonceHeader, base64.RawURLEncoding.EncodeToString(nonce))
			}
			w := httptest.NewRecorder()
			views.ServeHTTP(w, r)
			return w
		}
		w := post(request, nil, true)
		if w.Code != http.StatusOK || len(w.Result().Cookies()) != 1 {
			t.Fatalf("HTTP session redemption failed: %d %s", w.Code, w.Body.String())
		}
		cookie := w.Result().Cookies()[0]
		call := func(input, output any) {
			t.Helper()
			w := post(input.(api.Request), cookie, false)
			var reply api.Response
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK || reply.Error != nil {
				t.Fatalf("HTTP operation refused: status=%d error=%v", w.Code, reply.Error)
			}
			if err := json.Unmarshal(reply.Result, output); err != nil {
				t.Fatal(err)
			}
		}
		// Prior root authority is a component input; ticket issuance, proof
		// verification, receipt and persisted ticket all use production code.
		expires := api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
		sourceBytes := fixtureJSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2",
			Entries: []api.ObjectEntry{{Path: ".", Kind: "directory", Mode: 0700}}})
		source := api.BlobRef{ID: fixtureID(t), Class: "manifest", Bytes: int64(len(sourceBytes)), SHA256: digestBytes(sourceBytes)}
		cause := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalOrgBootstrap, Config: setup.Config, Actor: setup.Actor, RequestedBy: setup.Actor}
		if _, err := state.Transact(ctx, api.Transaction{Scope: setup, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{{
			ObjectKey: source.ID, Class: source.Class, Bytes: sourceBytes, SHA256: source.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: setup.Config, Owner: setup.Actor, Audience: "owner", Generation: 1}}}}}); err != nil {
			t.Fatal(err)
		}
		root := api.GrantSet{ID: fixtureID(t), LifeID: fixtureID(t), Generation: 1, PolicyGeneration: policy.Generation,
			Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{},
			Profiles: []api.ProfileGrant{{ID: fixtureID(t), ProfileID: fixtureID(t), Driver: api.DriverCodex,
				Provider: "component-provider", Delegate: true, ExpiresAt: expires}},
			Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}, ExpiresAt: expires,
			Data: []api.DataGrant{{ID: fixtureID(t), SourceObjectID: source.ID, SourceSHA256: source.SHA256,
				RelativePath: ".", Access: "rw", Delivery: "copy", Destination: "/work/main", HistoryScope: "tree", Delegate: true, ExpiresAt: expires}}}
		root.SHA256, err = manifest.HashValue(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := manifest.Set(root, time.Now()); err != nil {
			t.Fatal("prior root grant fixture is not a valid effective set", err)
		}
		var decoded api.GrantSet
		if err := wire.Decode(fixtureJSON(t, root), &decoded); err != nil {
			t.Fatal("prior root grant fixture is not schema-valid", err)
		}
		grantsFlowProjection(t, directory, "grants", root.ID, root)
		// DashData.root_ticket uses exactly these four parameters for DASH-L6.
		params := api.TicketIssueRequest{Level: 6, Role: "supervisor", GrantSetID: root.ID,
			ExpiresAt: api.Timestamp(time.Now().UTC().Add(90 * time.Second).Format(time.RFC3339Nano))}
		operation := requestFor(t, "ticket.issue", params)
		operation = signIntent(call, redemption.ConnectionID, operation, api.HumanChallengeRequest{
			Method: operation.Method, TargetID: root.ID, BaseGeneration: root.Generation, RequestSHA256: operation.RequestSHA256})
		for _, row := range []struct {
			name    string
			req     api.Request
			message string
		}{
			{"proof-required", func() api.Request { r := operation; r.Proof = nil; return r }(),
				"operation-bound human proof is required for mutations"},
			{"proof-bound", func() api.Request {
				r := requestFor(t, "ticket.issue", api.TicketIssueRequest{Level: 3, Role: params.Role,
					GrantSetID: params.GrantSetID, ExpiresAt: params.ExpiresAt})
				r.Proof = operation.Proof
				return r
			}(), "proof request_sha256 does not match request envelope digest"},
			// This RPC exists internally but has no documented dashboard method.
			{"undocumented", requestFor(t, "grants.enroll", api.CapabilityEnrollmentRequest{}),
				"method is not exposed on the dashboard"},
		} {
			t.Run(row.name, func(t *testing.T) {
				w := post(row.req, cookie, false)
				var reply api.Response
				if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
					t.Fatal(err)
				}
				if w.Code != http.StatusForbidden || reply.Error == nil || reply.Error.Code != api.CodeForbidden ||
					reply.Error.Owner != "lb-v2-dashboard" || reply.Error.Message != row.message {
					t.Fatalf("HTTP mutation control failed: status=%d error=%v", w.Code, reply.Error)
				}
				effects, err := state.PendingEffects(ctx, api.CursorRequest{Limit: 200})
				if err != nil || len(effects) != 0 {
					t.Fatal("refused HTTP proof reserved a launch operation", err)
				}
			})
		}
		var ticket api.Ticket
		call(operation, &ticket)
		current, err := identities.CurrentConnectionScope(ctx, redemptionConnection)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := state.Ticket(ctx, current, ticket.ID)
		if err != nil || stored != ticket || ticket.ID == "" || ticket.PrincipalID != actor.ID || ticket.Config != binding.Config ||
			ticket.Level != params.Level || ticket.Role != params.Role || ticket.GrantSetID != params.GrantSetID || ticket.ExpiresAt != params.ExpiresAt || ticket.Redeemed {
			t.Fatal("HTTP ticket differs from its exact operation or persisted authority", err)
		}
		dashPlanComplete(t, host, state, identities, setup, directory, root, ticket, call)
	})
}
