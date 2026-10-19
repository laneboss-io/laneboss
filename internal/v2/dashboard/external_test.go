package dashboard_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dashboard"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/store"
)

// This transport deliberately lives outside dashboard. It has no *Service,
// cookie map, test export, or access to dashboard's private implementation.
// It models committed connection/session facts, not native peer verification.
type publicTransport struct {
	mu         sync.Mutex
	connection *publicConnection
	stored     api.StoredReadSession
	clients    map[string]bool
	badActor   bool
}

type publicConnection struct {
	mu        sync.Mutex
	id        api.ID
	authority api.ReadAuthority
	closed    bool
}

func (c *publicConnection) BindPeer(api.VerifiedPeer) error {
	return api.NotImplemented("lb-v2-identity", "external fixture native peer")
}
func (c *publicConnection) Peer() api.VerifiedPeer { return nil }
func (c *publicConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *publicConnection) ID() api.ID     { return c.id }
func (c *publicConnection) Conn() net.Conn { return nil }
func (c *publicConnection) Binding() api.InstalledBinding {
	return api.InstalledBinding{Config: "public-fixture", Class: api.EndpointHuman, EndpointGeneration: 1}
}
func (c *publicConnection) ReadAuthority(context.Context) (api.ReadAuthority, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.authority.SessionID == "" {
		return api.ReadAuthority{}, &api.Error{Code: api.CodeUnauthenticated}
	}
	return c.authority, nil
}
func (c *publicConnection) BindReadAuthority(a api.ReadAuthority) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.authority.SessionID != "" || a.ConnectionID != c.id {
		return &api.Error{Code: api.CodeForbidden}
	}
	c.authority = a
	return nil
}
func (c *publicConnection) RefreshReadAuthority(_ context.Context, update api.ReadAuthorityUpdate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return &api.Error{Code: api.CodeUnauthenticated}
	}
	if err := api.ValidateReadAuthorityUpdate(c.authority, update); err != nil {
		return err
	}
	c.authority = update.After
	return nil
}

type publicFrame []byte

func (f publicFrame) Bytes() []byte { return append([]byte(nil), f...) }
func (f publicFrame) Verify(ctx context.Context, c api.ConnectionContext) error {
	if len(f) == 0 || c == nil {
		return &api.Error{Code: api.CodeUnauthenticated}
	}
	_, err := c.ReadAuthority(ctx)
	return err
}

func (p *publicTransport) Scope(_ context.Context, r *http.Request, req api.Request, raw []byte, claim *dashboard.SessionClaim) (api.Scope, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	actor := api.Actor{Kind: "human", ID: "public-owner"}
	if claim != nil {
		if claim.SessionID != p.stored.Session.ID || claim.ConnectionID != p.connection.ID() ||
			claim.Actor != actor || claim.EndpointGeneration != p.stored.EndpointGeneration {
			return api.Scope{}, &api.Error{Code: api.CodeForbidden}
		}
		p.clients[r.RemoteAddr] = true
	} else if req.Method != "human.session" {
		return api.Scope{}, &api.Error{Code: api.CodeUnauthenticated}
	}
	if p.badActor {
		actor.ID = "another-owner"
	}
	return api.Scope{Config: req.Config, Source: "dashboard", Actor: actor, Connection: p.connection,
		EndpointGeneration: 1, PolicyGeneration: 1, Request: req, Frame: publicFrame(append([]byte(nil), raw...))}, nil
}

func (p *publicTransport) Dispatch(ctx context.Context, scope api.Scope, req api.Request) (api.Response, error) {
	var framed api.Request
	if err := api.DecodeObject(scope.Frame.Bytes(), &framed); err != nil {
		return api.Response{}, err
	}
	if !reflect.DeepEqual(framed, req) {
		return api.Response{}, &api.Error{Code: api.CodeUnauthenticated}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var value any
	switch req.Method {
	case "human.session":
		if req.Proof == nil || req.Proof.RequestSHA256 != req.RequestSHA256 || p.stored.Session.ID != "" {
			return api.Response{}, &api.Error{Code: api.CodeForbidden}
		}
		digest := sha256.Sum256(scope.Frame.Bytes())
		now := time.Now().UTC()
		session := api.HumanSession{ID: api.ID("session-" + hex.EncodeToString(digest[:16])), Config: req.Config,
			IdleExpiresAt: api.Timestamp(now.Add(5 * time.Minute).Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(now.Add(30 * time.Minute).Format(time.RFC3339Nano))}
		p.stored = api.StoredReadSession{Session: session, PrincipalID: scope.Actor.ID, CredentialID: req.Proof.ID,
			ConnectionID: p.connection.ID(), EndpointGeneration: 1, Generation: 1}
		if err := p.connection.BindReadAuthority(api.ReadAuthorityFromSession(p.stored)); err != nil {
			return api.Response{}, err
		}
		value = session
	case "dashboard.tree":
		if err := p.validateLocked(ctx, scope, req); err != nil {
			return api.Response{}, err
		}
		var query api.DashboardQuery
		if err := api.DecodeObject(req.Params, &query); err != nil {
			return api.Response{}, err
		}
		value = map[string]any{"nodes": []any{map[string]any{"id": p.stored.PrincipalID, "limit": query.Limit}}}
	default:
		return api.Response{}, api.NotImplemented("lb-v2-service", "external fixture method")
	}
	raw, err := json.Marshal(value)
	return api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: req.RequestID, Result: raw}, err
}

func (p *publicTransport) validateLocked(ctx context.Context, scope api.Scope, req api.Request) error {
	a, err := p.connection.ReadAuthority(ctx)
	if err != nil {
		return err
	}
	if a != api.ReadAuthorityFromSession(p.stored) || scope.Actor.ID != p.stored.PrincipalID || scope.Connection.ID() != p.stored.ConnectionID ||
		scope.Config != p.stored.Session.Config || scope.EndpointGeneration != p.stored.EndpointGeneration || !reflect.DeepEqual(req, scope.Request) {
		return &api.Error{Code: api.CodeUnauthenticated}
	}
	return scope.Frame.Verify(ctx, scope.Connection)
}

// Unreached store/lifecycle operations delegate to their explicit owning
// not_implemented stubs. No nil interface supplies a fabricated fixture port.
type publicStore struct {
	*store.Service
	transport *publicTransport
}

func (s publicStore) ReadSession(ctx context.Context, scope api.Scope, id api.ID) (api.StoredReadSession, error) {
	p := s.transport
	p.mu.Lock()
	defer p.mu.Unlock()
	if id != p.stored.Session.ID || scope.Actor.ID != p.stored.PrincipalID {
		return api.StoredReadSession{}, &api.Error{Code: api.CodeUnauthenticated}
	}
	return p.stored, nil
}

type publicIdentity struct {
	transport *publicTransport
}

func (publicIdentity) Authenticate(context.Context, api.ConnectionContext) (api.Scope, error) {
	return api.Scope{}, api.NotImplemented("lb-v2-identity", "external fixture Authenticate")
}
func (publicIdentity) BindLaunch(context.Context, api.LaunchBindingRequest) (api.LaunchPermit, error) {
	return api.LaunchPermit{}, api.NotImplemented("lb-v2-identity", "external fixture BindLaunch")
}
func (publicIdentity) RevokeLaunch(context.Context, api.ID) error {
	return api.NotImplemented("lb-v2-identity", "external fixture RevokeLaunch")
}
func (publicIdentity) HumanChallenge(context.Context, api.Scope, api.HumanChallengeRequest) (api.HumanChallenge, error) {
	return api.HumanChallenge{}, api.NotImplemented("lb-v2-identity", "external fixture HumanChallenge")
}
func (publicIdentity) HumanConfirm(context.Context, api.Scope, api.HumanConfirmRequest) (api.ProofRef, error) {
	return api.ProofRef{}, api.NotImplemented("lb-v2-identity", "external fixture HumanConfirm")
}
func (publicIdentity) HumanSession(context.Context, api.Scope, api.HumanSessionRequest) (api.HumanSession, error) {
	return api.HumanSession{}, api.NotImplemented("lb-v2-identity", "external fixture HumanSession")
}
func (publicIdentity) TicketIssue(context.Context, api.Scope, api.TicketIssueRequest) (api.Ticket, error) {
	return api.Ticket{}, api.NotImplemented("lb-v2-identity", "external fixture TicketIssue")
}

func (i publicIdentity) IdentitySelf(ctx context.Context, scope api.Scope, _ api.Empty) (api.Scope, error) {
	p := i.transport
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.validateLocked(ctx, scope, scope.Request); err != nil {
		return api.Scope{}, err
	}
	return scope, nil
}
func (i publicIdentity) Authorize(ctx context.Context, scope api.Scope, req api.Request) error {
	p := i.transport
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.validateLocked(ctx, scope, req); err != nil {
		return err
	}
	before, after := p.stored, p.stored
	after.Generation++
	now := time.Now().UTC()
	deadline := now.Add(5 * time.Minute)
	abs, err := time.Parse(time.RFC3339Nano, string(before.Session.ExpiresAt))
	if err != nil {
		return err
	}
	if abs.Before(deadline) {
		deadline = abs
	}
	after.Session.IdleExpiresAt = api.Timestamp(deadline.Format(time.RFC3339Nano))
	if err := api.ValidateReadSessionRefresh(scope, before, after, now); err != nil {
		return err
	}
	if err := p.connection.RefreshReadAuthority(ctx, api.ReadAuthorityUpdate{Before: api.ReadAuthorityFromSession(before), After: api.ReadAuthorityFromSession(after)}); err != nil {
		return err
	}
	p.stored = after
	return nil
}

type publicUnused struct {
	*lifecycle.Service
}

func (publicUnused) Challenge(context.Context, api.Scope, api.HumanChallengeRequest) (api.HumanChallenge, error) {
	return api.HumanChallenge{}, api.NotImplemented("lb-v2-identity", "external fixture Challenge")
}
func (publicUnused) Confirm(context.Context, api.Scope, api.HumanConfirmRequest) (api.ProofRef, error) {
	return api.ProofRef{}, api.NotImplemented("lb-v2-identity", "external fixture Confirm")
}
func (publicUnused) CheckProof(context.Context, api.Scope, api.ProofRef, api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	return api.VerifiedHumanProof{}, api.NotImplemented("lb-v2-identity", "external fixture CheckProof")
}
func (publicUnused) MailSend(context.Context, api.Scope, api.MailSendRequest) (api.Mail, error) {
	return api.Mail{}, api.NotImplemented("lb-v2-messaging", "external fixture MailSend")
}
func (publicUnused) MailList(context.Context, api.Scope, api.ListRequest) (api.MailPage, error) {
	return api.MailPage{}, api.NotImplemented("lb-v2-messaging", "external fixture MailList")
}
func (publicUnused) ReportSubmit(context.Context, api.Scope, api.ReportRequest) (api.Mail, error) {
	return api.Mail{}, api.NotImplemented("lb-v2-messaging", "external fixture ReportSubmit")
}
func (publicUnused) OrgChangePropose(context.Context, api.Scope, api.ChangeProposeRequest) (api.ChangeRequest, error) {
	return api.ChangeRequest{}, api.NotImplemented("lb-v2-approval", "external fixture OrgChangePropose")
}
func (publicUnused) OrgChangeGet(context.Context, api.Scope, api.ChangeGetRequest) (api.ChangeRequest, error) {
	return api.ChangeRequest{}, api.NotImplemented("lb-v2-approval", "external fixture OrgChangeGet")
}
func (publicUnused) OrgChangeApprove(context.Context, api.Scope, api.ChangeApproveRequest) (api.ChangeApproval, error) {
	return api.ChangeApproval{}, api.NotImplemented("lb-v2-approval", "external fixture OrgChangeApprove")
}
func (publicUnused) OrgChangeApply(context.Context, api.Scope, api.ChangeApplyRequest) (api.ChangeReceipt, error) {
	return api.ChangeReceipt{}, api.NotImplemented("lb-v2-approval", "external fixture OrgChangeApply")
}

func TestDashPublicTransport(t *testing.T) {
	p := &publicTransport{connection: &publicConnection{id: "native-original"}, clients: make(map[string]bool)}
	identity, unused := publicIdentity{transport: p}, publicUnused{Service: &lifecycle.Service{}}
	s, err := dashboard.New(dashboard.Dependencies{Transport: p, Store: publicStore{Service: &store.Service{}, transport: p}, Human: unused,
		Identity: identity, Authenticator: identity, Lifecycle: unused, Messaging: unused, Approval: unused})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(s)
	defer server.Close()
	origin := server.URL
	if err := s.ConfigureHTTP("public-fixture", origin, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("TLS fixture did not supply its owned transport")
	}
	transport.DisableKeepAlives, transport.MaxConnsPerHost = true, 6
	defer transport.CloseIdleConnections()
	req := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "public-fixture", Method: "human.session",
		RequestID: "request-public-session-001", IdempotencyKey: "receipt-public-session-001", Params: json.RawMessage(`{}`)}
	req.RequestSHA256, err = api.RequestDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Proof = &api.ProofRef{ID: "credential-public", RequestSHA256: req.RequestSHA256, ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano))}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(http.MethodPost, origin+"/api/v2/rpc", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("external session response read failed: %v %v", readErr, closeErr)
	}
	if response.StatusCode != 200 || len(response.Cookies()) != 1 {
		t.Fatalf("external session setup failed: %d %s", response.StatusCode, body)
	}
	cookie := response.Cookies()[0]
	var group sync.WaitGroup
	for connection := 0; connection < 6; connection++ {
		group.Add(1)
		go func() {
			defer group.Done()
			r, err := http.NewRequest(http.MethodGet, origin+"/api/v2/tree?limit=7", nil)
			if err != nil {
				t.Errorf("public transport request setup failed: %v", err)
				return
			}
			r.AddCookie(cookie)
			response, err := client.Do(r)
			if err != nil {
				t.Errorf("public transport request failed: %v", err)
				return
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil {
				t.Errorf("public transport response read failed: %v %v", readErr, closeErr)
				return
			}
			if response.StatusCode != 200 || !bytes.Contains(body, []byte(`"id":"public-owner"`)) || !bytes.Contains(body, []byte(`"limit":7`)) {
				t.Errorf("public transport lost cookie claim across connections: %d %s", response.StatusCode, body)
			}
		}()
	}
	group.Wait()
	p.mu.Lock()
	clients := len(p.clients)
	p.badActor = true
	p.mu.Unlock()
	if clients != 6 {
		t.Fatal("public transport lost cookie claim across connections")
	}
	r, err = http.NewRequest(http.MethodGet, origin+"/api/v2/tree", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.AddCookie(cookie)
	response, err = client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr = io.Copy(io.Discard, response.Body)
	closeErr = response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("foreign principal response read failed: %v %v", readErr, closeErr)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("public transport admitted a foreign native principal")
	}
}
