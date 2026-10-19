package identity

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Controlled store/connection projections for authorization, not installed
// enrollment, module input validation, atomic effects or hardware evidence.
func fixtureReadScope(t *testing.T, s *Service, store *fixtureStore) api.Scope {
	t.Helper()
	scope := fixtureHumanScope(t, s, store)
	session := api.HumanSession{ID: "session", Config: scope.Config,
		ExpiresAt: timestamp(s.deps.Clock.Now().Add(30 * time.Minute)), IdleExpiresAt: timestamp(s.deps.Clock.Now().Add(5 * time.Minute))}
	store.readSession = &api.StoredReadSession{Session: session, PrincipalID: scope.Actor.ID, CredentialID: "credential",
		ConnectionID: scope.Connection.ID(), EndpointGeneration: scope.EndpointGeneration, Generation: 1}
	if err := scope.Connection.BindReadAuthority(api.ReadAuthority{Generation: 1, ConnectionID: scope.Connection.ID(), SessionID: session.ID,
		PrincipalID: scope.Actor.ID, CredentialID: "credential", Config: scope.Config, EndpointGeneration: scope.EndpointGeneration,
		ExpiresAt: session.ExpiresAt, IdleExpiresAt: session.IdleExpiresAt}); err != nil {
		t.Fatalf("fixture setup: read authority failed: %v", err)
	}
	return scope
}

func fixtureLaneScope(t *testing.T, s *Service, store *fixtureStore, level int) api.Scope {
	t.Helper()
	store.record.Actor.Level, store.lane.Level = level, level
	binding := fixtureHumanBinding()
	binding.Class, binding.LaunchID = api.EndpointLane, store.record.ID
	target := store.record.Target
	binding.Target = &target
	connection := fixtureUnboundConnection(t, binding)
	s.deps.Peers = &fixturePeers{peer: &fixturePeer{facts: api.PeerFacts{HostPID: 42, HostUID: store.record.HostUID,
		HostGID: 1234, ContainmentID: store.record.ContainmentID, ProcessGeneration: "boot:child"}}}
	s.deps.Registry.(*fixtureContainmentRegistry).binding = api.ContainmentBinding{Config: store.record.Config,
		Target: target, Backend: binding.Backend, BootID: "boot", Generation: 1,
		Lease: api.HelperLease{ID: store.record.UIDLeaseID, UID: store.record.HostUID, GID: 1234,
			ContainmentID: store.record.ContainmentID, EndpointGeneration: store.record.EndpointGeneration}}
	scope, err := s.Authenticate(context.Background(), connection)
	if err != nil {
		t.Fatalf("fixture setup: current lane scope failed: %v", err)
	}
	return scope
}

func fixtureAuthorityBody(method api.Method) any {
	grants := api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{}, Secrets: []api.SecretDelegation{},
		Profiles: []api.ProfileDelegation{}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}
	if method == "lane.start" {
		return api.StartRequest{RootTicketID: "ticket", Level: 3, Grants: grants}
	}
	if method == "lane.adopt" {
		return api.AdoptRequest{RootTicketID: "ticket", Level: 3, Grants: grants}
	}
	// Other owners validate these opaque bodies after this authorization gate.
	return api.Empty{}
}

func TestSessionMethodsFixture(t *testing.T) {
	for _, method := range []api.Method{"blob.begin", "blob.chunk", "blob.commit", "policy.evaluate", "guidance.select", "judge.ask", "secret.stage"} {
		t.Run(strings.ReplaceAll(string(method), ".", "-"), func(t *testing.T) {
			if !api.HumanSessionMethod(method) {
				t.Fatal("fixture setup: session method differs from the frozen catalog")
			}
			for _, rule := range []string{"current", "no-session", "proof"} {
				t.Run(rule, func(t *testing.T) {
					s, store, _ := serviceFixture(t)
					scope := fixtureReadScope(t, s, store)
					if rule == "no-session" {
						scope.Connection.(*fixtureConnection).authority = api.ReadAuthority{}
					}
					scope = fixtureRequest(t, scope, method, fixtureAuthorityBody(method))
					if rule == "proof" {
						scope = fixtureOperationProof(t, s, store, scope)
					}
					err := s.Authorize(context.Background(), scope, scope.Request)
					if rule == "current" {
						if err != nil {
							t.Fatalf("fixture check: current human session method was refused: %v", err)
						}
						return
					}
					want := api.CodeUnauthenticated
					if rule == "proof" {
						want = api.CodeForbidden
					}
					errorCode(t, err, want)
				})
			}
		})
	}
}

func TestHumanEnvelopeProofFixture(t *testing.T) {
	for _, method := range []api.Method{"identity.self", "health", "human.challenge", "human.confirm", "lane.start", "lane.adopt"} {
		t.Run(strings.ReplaceAll(string(method), ".", "-"), func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureReadScope(t, s, store)
			scope = fixtureRequest(t, scope, method, fixtureAuthorityBody(method))
			scope = fixtureOperationProof(t, s, store, scope)
			errorCode(t, s.Authorize(context.Background(), scope, scope.Request), api.CodeForbidden)
		})
	}
}

func TestL6AuthorityFixture(t *testing.T) {
	for _, method := range []api.Method{"org.change.propose", "org.change.apply"} {
		t.Run(strings.TrimPrefix(string(method), "org.change."), func(t *testing.T) {
			for _, actor := range []string{"human", "human-proof", "lane5", "lane6", "revoked", "forged-l6", "worker", "service"} {
				t.Run(actor, func(t *testing.T) {
					s, store, _ := serviceFixture(t)
					var scope api.Scope
					if actor == "human" || actor == "human-proof" {
						scope = fixtureHumanScope(t, s, store)
					} else if actor == "worker" || actor == "service" {
						// Class refusal only: no worker authentication is invented.
						scope = api.Scope{Config: "fixture", Actor: api.Actor{Kind: actor, Level: 6}}
					} else {
						level := 6
						if actor == "lane5" || actor == "forged-l6" {
							level = 5
						}
						scope = fixtureLaneScope(t, s, store, level)
					}
					scope = fixtureRequest(t, scope, method, api.Empty{})
					if actor == "human-proof" {
						scope = fixtureOperationProof(t, s, store, scope)
					}
					want := api.CodeForbidden
					if actor == "revoked" {
						store.record.Revoked, want = true, api.CodeUnauthenticated
					}
					if actor == "forged-l6" {
						scope.Actor.Level, want = 6, api.CodeUnauthenticated
					}
					err := s.Authorize(context.Background(), scope, scope.Request)
					if actor == "lane6" {
						if err != nil {
							t.Fatalf("fixture check: current L6 authorization was refused: %v", err)
						}
						return
					}
					errorCode(t, err, want)
				})
			}
		})
	}
}

func TestLaneProofOrderFixture(t *testing.T) {
	for _, method := range []api.Method{"lane.start", "lane.adopt"} {
		t.Run(strings.TrimPrefix(string(method), "lane."), func(t *testing.T) {
			s, _, scope := serviceFixture(t)
			request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: scope.Config,
				Method: method, Params: json.RawMessage("{"), Proof: &api.ProofRef{ID: "stolen"}}
			errorCode(t, s.Authorize(context.Background(), scope, request), api.CodeForbidden)
		})
	}
}

func TestHumanSelfPolicyFixture(t *testing.T) {
	for _, generation := range []api.Generation{3, 9} {
		s, store, _ := serviceFixture(t)
		store.policy = &api.EffectivePolicy{Generation: generation}
		scope := fixtureReadScope(t, s, store)
		projection, err := s.IdentitySelf(context.Background(), scope, api.Empty{})
		if err != nil || projection.PolicyGeneration != generation || projection.Connection != nil || projection.Frame != nil || projection.ReadAuthority != nil {
			t.Fatalf("fixture check: human self lost current policy or leaked internal authority: %v", err)
		}
	}
}
