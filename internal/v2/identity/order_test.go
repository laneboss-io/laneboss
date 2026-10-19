package identity

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestAuthenticateOrderFixture(t *testing.T) {
	s, store, _ := serviceFixture(t)
	store.enrollment = &api.HumanEnrollment{Config: "fixture", PrincipalID: "human", Generation: 1}
	connection := fixtureUnboundConnection(t, fixtureHumanBinding())
	peers := &fixturePeers{peer: &fixturePeer{facts: api.PeerFacts{HostPID: 42, HostUID: 1234, HostGID: 1234, ProcessGeneration: "boot:1"}}}
	s.deps.Peers = peers
	scope, err := s.Authenticate(context.Background(), connection)
	if err != nil {
		t.Fatalf("fixture check: ordered authentication failed: %v", err)
	}
	if peers.calls != 1 || peers.connection != connection.Conn() || !reflect.DeepEqual(peers.binding, connection.Binding()) ||
		connection.binds != 1 || connection.Peer() != peers.peer || scope.Connection != connection || scope.PolicyGeneration != store.record.PolicyGeneration {
		t.Fatal("fixture check: authentication did not verify the raw bound socket before deriving scope")
	}
	_, err = s.Authenticate(context.Background(), connection)
	errorCode(t, err, api.CodeConflict)
	if peers.calls != 1 || connection.closes != 1 || peers.peer.(*fixturePeer).closes != 1 {
		t.Fatal("fixture check: repeated authentication rebound or retained a rejected connection")
	}
}

func TestAuthenticationCleanupFixture(t *testing.T) {
	for _, phase := range []string{"verify", "bind", "enrollment"} {
		t.Run(phase, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			connection := fixtureUnboundConnection(t, fixtureHumanBinding())
			peer := &fixturePeer{facts: api.PeerFacts{HostPID: 42, HostUID: 1234, HostGID: 1234, ProcessGeneration: "boot:1"}}
			peers := &fixturePeers{peer: peer}
			s.deps.Peers = peers
			sentinel := &api.Error{Code: api.CodeUnavailable, Message: "fixture dependency refused"}
			switch phase {
			case "verify":
				peers.err = sentinel
			case "bind":
				connection.bindErr = sentinel
			case "enrollment":
				store.err = sentinel
			}
			scope, err := s.Authenticate(context.Background(), connection)
			if !errors.Is(err, sentinel) || !reflect.DeepEqual(scope, api.Scope{}) {
				t.Fatal("fixture check: authentication lost its dependency failure or returned authority")
			}
			if connection.closes != 1 || peer.closes != 1 {
				t.Fatal("fixture check: authentication failure leaked its socket or peer lifetime")
			}
		})
	}
}

func TestLaneClaimsFixture(t *testing.T) {
	for _, rule := range []string{"own", "life", "level", "role", "grants", "instance"} {
		t.Run(rule, func(t *testing.T) {
			s, store, scope := serviceFixture(t)
			request := api.BriefingRequest{LifeID: scope.Actor.LifeID, Level: scope.Actor.Level, Role: scope.Actor.Role}
			if rule == "life" {
				request.LifeID = "other-life"
			}
			if rule == "level" {
				request.Level++
			}
			if rule == "role" {
				request.Role = "owner"
			}
			scope = fixtureRequest(t, scope, "brief.start", request)
			if rule == "grants" || rule == "instance" {
				template := api.TemplateRequest{Context: api.RoleContext{Level: scope.Actor.Level, Role: scope.Actor.Role, InstanceID: scope.Actor.ID}, GrantSetID: store.record.GrantSetID}
				if rule == "grants" {
					template.GrantSetID = "other-grants"
				} else {
					template.Context.InstanceID = "other-instance"
				}
				scope = fixtureRequest(t, scope, "brief.render", template)
			}
			// A direct claim-check fixture has an authenticated current launch;
			// no selected foreign life/grant is read to decide these comparisons.
			err := s.authorizeClaims(context.Background(), scope, scope.Request)
			if rule == "own" {
				if err != nil {
					t.Fatalf("fixture check: own briefing was refused: %v", err)
				}
				return
			}
			errorCode(t, err, api.CodeForbidden)
		})
	}
}

func TestTicketEndpointFixture(t *testing.T) {
	for _, method := range []api.Method{"lane.start", "lane.adopt"} {
		t.Run(string(method), func(t *testing.T) {
			s, _, scope := serviceFixture(t)
			grants := api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{}, Secrets: []api.SecretDelegation{},
				Profiles: []api.ProfileDelegation{}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}
			var body any = api.StartRequest{RootTicketID: "ticket", Level: 3, Grants: grants}
			if method == "lane.adopt" {
				body = api.AdoptRequest{RootTicketID: "ticket", Level: 3, Grants: grants}
			}
			scope = fixtureRequest(t, scope, method, body)
			// No ticket fixture/lookup exists: the lane endpoint must be refused
			// before a ticket can select a human root path.
			errorCode(t, s.authorizeClaims(context.Background(), scope, scope.Request), api.CodeForbidden)
		})
	}
}

func TestRootLineageFixture(t *testing.T) {
	for _, rule := range []string{"root", "root-sequence", "child", "child-sequence", "child-parent"} {
		t.Run(rule, func(t *testing.T) {
			_, store, _ := serviceFixture(t)
			record := store.record
			if rule == "root-sequence" {
				record.StarterEventSeq = 1
			}
			if rule == "child" || rule == "child-sequence" || rule == "child-parent" {
				record.ParentLifeID, record.RootLifeID, record.StarterChain, record.StarterEventSeq = "parent", "parent", []api.ID{"parent"}, 7
				if rule == "child-sequence" {
					record.StarterEventSeq = 0
				}
				if rule == "child-parent" {
					record.StarterChain = []api.ID{"other"}
				}
			}
			err := validateLaunch(record)
			if rule == "root" || rule == "child" {
				if err != nil {
					t.Fatalf("fixture check: authentic root or child lineage was refused: %v", err)
				}
				return
			}
			errorCode(t, err, api.CodeInvalid)
		})
	}
}

func TestTicketReceiptProvenanceFixture(t *testing.T) {
	for _, field := range []string{"current", "principal", "config", "endpoint"} {
		t.Run(field, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			request := api.TicketIssueRequest{Level: 6, Role: "supervisor", GrantSetID: "root-grants",
				ExpiresAt: timestamp(s.deps.Clock.Now().Add(time.Minute))}
			store.grants = &api.GrantSet{ID: request.GrantSetID, Generation: 1, ExpiresAt: timestamp(s.deps.Clock.Now().Add(time.Hour))}
			scope := fixtureRequest(t, fixtureHumanScope(t, s, store), "ticket.issue", request)
			scope = fixtureOperationProof(t, s, store, scope)
			calls := 0
			store.transact = func(transaction api.Transaction) (api.Commit, error) {
				calls++
				if len(transaction.Writes.Tickets) != 1 {
					t.Fatal("fixture check: ticket issuance omitted its durable ticket")
				}
				ticket := transaction.Writes.Tickets[0]
				if ticket.PrincipalID != scope.Actor.ID || ticket.Config != scope.Config || ticket.EndpointGeneration != scope.EndpointGeneration {
					t.Fatal("fixture check: issued ticket lost principal, configuration or endpoint provenance")
				}
				switch field {
				case "principal":
					ticket.PrincipalID = "other-principal"
				case "config":
					ticket.Config = "other-config"
				case "endpoint":
					ticket.EndpointGeneration++
				}
				encoded, err := json.Marshal(ticket)
				if err != nil {
					t.Fatal(err)
				}
				return api.Commit{Reply: &api.RPCReply{Result: encoded}, Operation: api.Operation{ID: "receipt", Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}, nil
			}
			ticket, err := s.TicketIssue(context.Background(), scope, request)
			if calls != 1 {
				t.Fatal("fixture check: provenance receipt did not reach its durable handoff")
			}
			if field == "current" {
				if err != nil || ticket.PrincipalID != scope.Actor.ID || ticket.Config != scope.Config || ticket.EndpointGeneration != scope.EndpointGeneration {
					t.Fatalf("fixture check: current ticket provenance was not retained: %v", err)
				}
				return
			}
			errorCode(t, err, api.CodeIntegrity)
			if !reflect.DeepEqual(ticket, api.Ticket{}) {
				t.Fatal("fixture check: foreign retained ticket returned authority")
			}
		})
	}
}

func TestSessionReceiptBindingFixture(t *testing.T) {
	for _, field := range []string{"current", "principal", "connection", "endpoint", "revoked", "expired"} {
		t.Run(field, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureRequest(t, fixtureHumanScope(t, s, store), "human.session", api.HumanSessionRequest{})
			scope = fixtureOperationProof(t, s, store, scope)
			calls := 0
			store.transact = func(transaction api.Transaction) (api.Commit, error) {
				calls++
				if len(transaction.Writes.ReadSessions) != 1 {
					t.Fatal("fixture check: session handoff omitted its stored authority")
				}
				stored := transaction.Writes.ReadSessions[0]
				switch field {
				case "principal":
					stored.PrincipalID = "other-human"
				case "connection":
					stored.ConnectionID = "other-connection"
				case "endpoint":
					stored.EndpointGeneration++
				case "revoked":
					stored.Revoked = true
				case "expired":
					s.deps.Clock = fixtureClock{s.deps.Clock.Now().Add(6 * time.Minute)}
				}
				store.readSession = &stored
				return api.Commit{Reply: transaction.Reply, Operation: api.Operation{ID: "session-receipt", Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}, nil
			}
			session, err := s.HumanSession(context.Background(), scope, api.HumanSessionRequest{})
			connection := scope.Connection.(*fixtureConnection)
			if calls != 1 {
				t.Fatal("fixture check: session receipt did not reach its durable handoff")
			}
			if field == "current" {
				if err != nil || connection.readBindAttempts != 1 || connection.readBinds != 1 || connection.authority.SessionID != session.ID {
					t.Fatalf("fixture check: current session receipt did not bind its connection: %v", err)
				}
				bound, err := api.WithReadAuthority(context.Background(), scope)
				if err != nil || bound.ReadAuthority == nil || bound.ReadAuthority.ConnectionID != connection.ID() {
					t.Fatalf("fixture check: committed session cannot produce the API read-authority snapshot: %v", err)
				}
				if err := s.checkReadSession(context.Background(), bound); err != nil {
					t.Fatalf("fixture check: committed session snapshot was refused: %v", err)
				}
				return
			}
			// Invalid durable receipts must be rejected before the transport is
			// asked to activate them, even if its independent checks also refuse.
			if connection.readBindAttempts != 0 {
				t.Fatalf("fixture check: %s session receipt reached transport activation: attempts=%d binds=%d",
					field, connection.readBindAttempts, connection.readBinds)
			}
			errorCode(t, err, api.CodeUnauthenticated)
			if connection.readBinds != 0 || !reflect.DeepEqual(session, api.HumanSession{}) {
				t.Fatal("fixture check: a foreign or revoked receipt conferred read authority")
			}
		})
	}
}

func TestHumanSelfSessionFixture(t *testing.T) {
	s, store, _ := serviceFixture(t)
	scope := fixtureHumanScope(t, s, store)
	result, err := s.IdentitySelf(context.Background(), scope, api.Empty{})
	errorCode(t, err, api.CodeUnauthenticated)
	if !reflect.DeepEqual(result, api.Scope{}) {
		t.Fatal("fixture check: staging human scope leaked a self projection without a read session")
	}
}

func TestSpawnClaimsFixture(t *testing.T) {
	for _, rule := range []string{"child", "child-level", "human-ticket", "human-no-ticket", "worker-ticket", "l6", "grant-parent"} {
		t.Run(rule, func(t *testing.T) {
			s, _, scope := serviceFixture(t)
			grants := api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{}, Secrets: []api.SecretDelegation{},
				Profiles: []api.ProfileDelegation{}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}
			request := api.StartRequest{Level: scope.Actor.Level - 1, Grants: grants}
			if rule == "child-level" {
				request.Level = scope.Actor.Level
			}
			if rule == "human-ticket" || rule == "human-no-ticket" || rule == "worker-ticket" {
				connection := fixtureUnboundConnection(t, fixtureHumanBinding())
				scope.Connection, scope.Actor.Kind = connection, "human"
				if rule != "human-no-ticket" {
					request.RootTicketID = "ticket"
				}
				if rule == "worker-ticket" {
					scope.Actor.Kind = "worker"
					connection.binding.Class = api.EndpointWorker
				}
			}
			scope = fixtureRequest(t, scope, "lane.start", request)
			if rule == "l6" {
				scope = fixtureRequest(t, scope, "org.change.propose", api.ChangeProposeRequest{Files: []api.ResourceDelta{}})
			}
			if rule == "grant-parent" {
				scope = fixtureRequest(t, scope, "grants.validate", api.GrantValidateRequest{ParentLifeID: "other-life", Requested: grants})
			}
			err := s.authorizeClaims(context.Background(), scope, scope.Request)
			if rule == "child" || rule == "human-ticket" {
				if err != nil {
					t.Fatalf("fixture check: current spawn claims were refused: %v", err)
				}
				return
			}
			want := api.CodeForbidden
			if rule == "human-no-ticket" {
				want = api.CodeUnauthenticated
			}
			errorCode(t, err, want)
		})
	}
}

// Authorization-only projection: encryption validation and actual protected
// secret staging remain the broker's responsibility, not this fixture's claim.
func TestHumanReadStageFixture(t *testing.T) {
	for _, rule := range []string{"current", "no-session", "connection", "revoked"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureHumanScope(t, s, store)
			session := api.HumanSession{ID: "read-session", Config: scope.Config,
				ExpiresAt: timestamp(s.deps.Clock.Now().Add(30 * time.Minute)), IdleExpiresAt: timestamp(s.deps.Clock.Now().Add(5 * time.Minute))}
			store.readSession = &api.StoredReadSession{Session: session, PrincipalID: scope.Actor.ID, CredentialID: "credential",
				ConnectionID: scope.Connection.ID(), EndpointGeneration: scope.EndpointGeneration, Generation: 1}
			connection := scope.Connection.(*fixtureConnection)
			connection.authority = api.ReadAuthority{Generation: 1, ConnectionID: scope.Connection.ID(), SessionID: session.ID, PrincipalID: scope.Actor.ID, CredentialID: "credential",
				Config: scope.Config, EndpointGeneration: scope.EndpointGeneration, ExpiresAt: session.ExpiresAt, IdleExpiresAt: session.IdleExpiresAt}
			if rule == "no-session" {
				connection.authority = api.ReadAuthority{}
			}
			if rule == "connection" {
				store.readSession.ConnectionID = "other-connection"
			}
			if rule == "revoked" {
				store.readSession.Revoked = true
			}
			scope = fixtureRequest(t, scope, "secret.stage", api.SecretStageRequest{KeyID: "stage-key", Name: "fixture", Version: "v1",
				EphemeralPublicKey: make([]byte, 32), Nonce: make([]byte, 12), Ciphertext: make([]byte, 16)})
			err := s.Authorize(context.Background(), scope, scope.Request)
			if rule == "current" {
				if err != nil {
					t.Fatalf("fixture check: current read session could not authorize encrypted staging: %v", err)
				}
				return
			}
			errorCode(t, err, api.CodeUnauthenticated)
		})
	}
}
