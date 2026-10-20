package service

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func entryFrame(t *testing.T, conn *connectionContext, input DashboardEntryRequest) dashboardNativeFrame {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return dashboardNativeFrame{raw: raw, conn: conn}
}

func TestDashboardEntrySocket(t *testing.T) {
	if testing.Short() {
		t.Fatal("dashboard socket control requires its real transport")
	}
	server, _, actor := dashboardTransportFixture(t)
	server.verified, server.bound = true, true
	server.deps.Binding.Socket = filepath.Join(t.TempDir(), "control.sock")
	server.deps.Binding.ServiceUID, server.deps.Binding.ServiceGID = uint32(os.Getuid()), uint32(os.Getgid())
	server.options.AdminEnrollment = &api.AdminEnrollmentEndpoint{}
	server.dashboardHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.URL.Path)) })
	entry, err := server.OpenDashboardEntry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := entry.Close(); err != nil {
			t.Error(err)
		}
	})
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error { return wire.EnableRawCredentials(raw) }}
	connection, err := dialer.DialContext(context.Background(), "unix", server.deps.Binding.Socket+".browser")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(DashboardEntryRequest{Protocol: DashboardEntryProtocol, Action: "open"})
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteFrame(connection, raw); err != nil {
		t.Fatal(err)
	}
	socket := connection.(*net.UnixConn)
	peer, err := wire.PeerCredentials(socket)
	if err != nil {
		t.Fatal(err)
	}
	read, err := wire.ReadFrame(&entryPeerReader{socket: socket, peer: peer})
	if err != nil {
		t.Fatal(err)
	}
	var response DashboardEntryReply
	if err := api.DecodeObject(read, &response); err != nil {
		t.Fatal(err)
	}
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	var observed DashboardConnection
	if err := api.DecodeObject(response.Result, &observed); err != nil {
		t.Fatal(err)
	}
	if observed.ConnectionID == "" || observed.Actor != actor {
		t.Fatal("native socket did not return its authenticated connection")
	}
	if err := entry.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".browser", ".web"} {
		if _, err := os.Lstat(server.deps.Binding.Socket + suffix); !os.IsNotExist(err) {
			t.Fatal("dashboard entry retained an owned socket")
		}
	}
}

type entryPeerReader struct {
	socket *net.UnixConn
	peer   wire.SocketPeer
}

func (r *entryPeerReader) Read(raw []byte) (int, error) {
	return wire.ReadPeerBytes(r.socket, r.peer, raw)
}

func TestDashboardEntryOpen(t *testing.T) {
	server, conn, actor := dashboardTransportFixture(t)
	request := DashboardEntryRequest{Protocol: DashboardEntryProtocol, Action: "open"}
	value, err := server.dashboardEntryCall(context.Background(), conn, entryFrame(t, conn, request), request)
	if err != nil {
		t.Fatal(err)
	}
	opened := value.(DashboardConnection)
	if opened.ConnectionID != conn.ID() || opened.Actor != actor || opened.Config != server.options.Config {
		t.Fatal("native entry lost its actual connection identity")
	}
	if _, err := conn.ReadAuthority(context.Background()); err == nil {
		t.Fatal("open minted a read session")
	}
	request.RedeemID = "claimed-session"
	if _, err := server.dashboardEntryCall(context.Background(), conn, entryFrame(t, conn, request), request); err == nil {
		t.Fatal("open accepted supplied authority")
	}
	request.RedeemID = ""
	server.deps.Authenticator.(*authFixture).scope.EndpointGeneration++
	if _, err := server.dashboardEntryCall(context.Background(), conn, entryFrame(t, conn, request), request); err == nil {
		t.Fatal("entry accepted a changed endpoint generation")
	}
}

func TestDashboardStagingFences(t *testing.T) {
	server, conn, actor := dashboardTransportFixture(t)
	ctx := context.Background()
	request := DashboardEntryRequest{Protocol: DashboardEntryProtocol, Action: "open"}
	frame := entryFrame(t, conn, request)
	if _, err := server.dashboardEntryCall(ctx, conn, frame, request); err != nil {
		t.Fatal("native open control failed", err)
	}
	bound, err := conn.HumanStaging(ctx)
	if err != nil || bound.PrincipalID != actor.ID || bound.CredentialID != "" || string(bound.Frame.Bytes()) != string(frame.Bytes()) {
		t.Fatal("native open did not retain its authenticated principal and exact frame", err)
	}
	if _, err := conn.ReadAuthority(ctx); err == nil {
		t.Fatal("native staging granted read authority")
	}
	server.deps.Authenticator.(*authFixture).scope.Actor.ID = fixtureID(t)
	request.Action = "ping"
	if _, err := server.dashboardEntryCall(ctx, conn, entryFrame(t, conn, request), request); err == nil {
		t.Fatal("cached native principal changed after opening")
	}
	bound, err = conn.HumanStaging(ctx)
	if err != nil || bound.PrincipalID != actor.ID {
		t.Fatal("refused native entry replaced its authenticated principal", err)
	}
}

func TestDashboardRefusedStaging(t *testing.T) {
	server, conn, _ := dashboardTransportFixture(t)
	request := DashboardEntryRequest{Protocol: DashboardEntryProtocol, Action: "open", RedeemID: fixtureID(t)}
	if _, err := server.dashboardEntryCall(context.Background(), conn, entryFrame(t, conn, request), request); err == nil {
		t.Fatal("native open accepted a supplied redemption")
	}
	if _, err := conn.HumanStaging(context.Background()); err == nil {
		t.Fatal("refused native open installed a staging principal")
	}
}

type entryClosingAuth struct{ *authFixture }

func (a *entryClosingAuth) Authenticate(ctx context.Context, conn api.ConnectionContext) (api.Scope, error) {
	if err := conn.Close(); err != nil {
		return api.Scope{}, err
	}
	return api.Scope{}, &api.Error{Code: api.CodeForbidden, Owner: "entry-test-owner", Message: "fixture native authentication refused"}
}

func TestDashboardEntryRefusal(t *testing.T) {
	server, _, _ := dashboardTransportFixture(t)
	server.deps.Authenticator = &entryClosingAuth{authFixture: server.deps.Authenticator.(*authFixture)}
	path := filepath.Join(t.TempDir(), "entry.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := wire.EnableCredentials(listener); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			server.serveDashboardEntry(context.Background(), conn)
		}
		done <- err
	}()
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error { return wire.EnableRawCredentials(raw) }}
	conn, err := dialer.DialContext(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(DashboardEntryRequest{Protocol: DashboardEntryProtocol, Action: "open"})
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteFrame(conn, raw); err != nil {
		t.Fatal(err)
	}
	socket := conn.(*net.UnixConn)
	peer, err := wire.PeerCredentials(socket)
	if err != nil {
		t.Fatal(err)
	}
	response, err := wire.ReadFrame(&entryPeerReader{socket: socket, peer: peer})
	if err != nil {
		t.Fatalf("native refusal was lost before its reply: %v", err)
	}
	var reply DashboardEntryReply
	if err := api.DecodeObject(response, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Error == nil || reply.Error.Code != api.CodeForbidden || reply.Error.Owner != "entry-test-owner" {
		t.Fatal("native refusal lost its exact owner and code")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refused native entry did not close")
	}
}

func TestDashboardEntryBootstrap(t *testing.T) {
	server, issuer, actor := dashboardTransportFixture(t)
	redemption := dashboardFreshConnection(t, server)
	_, session, _, nonce := issueDashboardBootstrap(t, server, issuer, redemption, actor)
	request := DashboardEntryRequest{Protocol: DashboardEntryProtocol, Action: "bootstrap", RedeemID: redemption.ID(), Nonce: nonce, Session: &session}
	value, err := server.dashboardEntryCall(context.Background(), issuer, entryFrame(t, issuer, request), request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Token        api.ID `json:"token"`
		ConnectionID api.ID `json:"connection_id"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.ConnectionID != redemption.ID() || result.Token == "" {
		t.Fatal("entry did not issue the actual redemption binding")
	}
	if _, _, err := server.loadDashboardBootstrap(context.Background(), result.Token, nonce, false); err != nil {
		t.Fatal(err)
	}
	request.RedeemID = issuer.ID()
	if _, err := server.dashboardEntryCall(context.Background(), issuer, entryFrame(t, issuer, request), request); err == nil {
		t.Fatal("entry rebound an authenticated connection")
	}
}

func TestDashboardEntryExactFrame(t *testing.T) {
	server, conn, _ := dashboardTransportFixture(t)
	request := DashboardEntryRequest{Protocol: DashboardEntryProtocol, Action: "open"}
	frame := entryFrame(t, conn, request)
	request.Action = "ping"
	if _, err := server.dashboardEntryCall(context.Background(), conn, frame, request); err == nil {
		t.Fatal("entry accepted bytes other than its native frame")
	}
	if _, err := server.dashboardEntryCall(context.Background(), conn, nil, request); err == nil {
		t.Fatal("entry accepted no native frame")
	}
}
