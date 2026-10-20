//go:build laneboss_e2e_authenticator

package identity

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestTaggedAttestation(t *testing.T) {
	for _, format := range []string{"none", "packed"} {
		t.Run(format, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			s.attestation = attestationTrust{}
			f := newRegistration(t, s.deps.Clock.Now(), "Ed25519", api.SoftwareAuthenticatorAAGUID, api.SoftwareAuthenticatorAttestationMarker)
			if format == "none" {
				f.statement = map[any]any{}
			} else {
				delete(f.statement, "x5c")
			}
			f.encode(t, format)
			store.ceremony = &f.challenge
			install, err := s.ValidateEnrollment(context.Background(), f.request)
			if err != nil || len(install.Enrollment.Credentials) != 1 || !install.Enrollment.Credentials[0].SimulatedPresence ||
				install.Enrollment.Credentials[0].ID != api.SoftwareAuthenticatorCredentialID || install.Enrollment.Credentials[0].AttestationFormat != format {
				t.Fatalf("fixture check: dedicated software attestation was refused or upgraded: %v", err)
			}
		})
	}
}

func TestInvitedAttestation(t *testing.T) {
	s, store, _ := serviceFixture(t)
	s.attestation = attestationTrust{}
	f := newRegistration(t, s.deps.Clock.Now(), "ES256", api.SoftwareAuthenticatorAAGUID, api.SoftwareAuthenticatorAttestationMarker)
	f.challenge.InviteID = "retained-invite"
	delete(f.statement, "x5c")
	f.encode(t, "packed")
	store.ceremony = &f.challenge
	install, err := s.ValidateEnrollment(context.Background(), f.request)
	if err != nil || len(install.Enrollment.Credentials) != 1 {
		t.Fatal("invited self-attestation failed actual verification", err)
	}
	c := install.Enrollment.Credentials[0]
	if c.ID == api.SoftwareAuthenticatorCredentialID || c.ID != api.InvitedCredentialID(c.RawCredentialID) || !c.SimulatedPresence ||
		c.AAGUID != api.SoftwareAuthenticatorAAGUID || c.AttestationMarker != api.SoftwareAuthenticatorAttestationMarker {
		t.Fatal("invited test key lost its unique identity or software-presence markers")
	}
	f.request.AttestationObject[len(f.request.AttestationObject)-1] ^= 1
	if _, err := s.ValidateEnrollment(context.Background(), f.request); err == nil {
		t.Fatal("invited registration accepted a changed attestation")
	}
}

// This tagged crypto/projection fixture traverses real registration and get
// verification. Store callbacks are observed handoffs, not durable one-use or
// hardware-presence evidence. No signer is compiled into a production binary.
func TestTaggedPresenceFlowFixture(t *testing.T) {
	for _, operation := range []string{"ticket", "session"} {
		t.Run(operation, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			human := fixtureHumanScope(t, s, store)
			registration := newRegistration(t, s.deps.Clock.Now(), "Ed25519", api.SoftwareAuthenticatorAAGUID, api.SoftwareAuthenticatorAttestationMarker)
			store.ceremony = &registration.challenge
			install, err := s.ValidateEnrollment(context.Background(), registration.request)
			if err != nil || len(install.Enrollment.Credentials) != 1 || !install.Enrollment.Credentials[0].SimulatedPresence ||
				install.Enrollment.Credentials[0].ID != api.SoftwareAuthenticatorCredentialID {
				t.Fatalf("fixture check: tagged real registration was refused or unmarked: %v", err)
			}
			store.enrollment = &install.Enrollment
			assertion := newAssertion(t, registration.key)
			s.deps.Clock = fixtureClock{assertion.now}
			assertion.request.CredentialID = install.Enrollment.Credentials[0].ID
			assertion.sign(t)
			method := api.Method("ticket.issue")
			var body any = api.TicketIssueRequest{Level: 6, Role: "supervisor", GrantSetID: "root-grants", ExpiresAt: timestamp(s.deps.Clock.Now().Add(time.Minute))}
			if operation == "session" {
				method = "human.session"
				body = api.HumanSessionRequest{}
			} else {
				store.grants = &api.GrantSet{ID: "root-grants", Generation: 1, ExpiresAt: timestamp(s.deps.Clock.Now().Add(time.Hour))}
			}
			future := fixtureRequest(t, human, method, body)
			assertion.challenge.Method = method
			assertion.challenge.RequestSHA256 = future.Request.RequestSHA256
			assertion.challenge.BaseGeneration = 1
			store.challenge = &api.StoredChallenge{EndpointClass: api.EndpointHuman, EndpointGeneration: human.EndpointGeneration, Challenge: assertion.challenge, PrincipalID: human.Actor.ID, ConnectionID: human.Connection.ID(), Generation: 1}
			calls := 0
			store.transact = func(tx api.Transaction) (api.Commit, error) {
				calls++
				presence := false
				for _, proof := range tx.Writes.Proofs {
					if !proof.SimulatedPresence || !proof.Ref.SimulatedPresence {
						t.Fatal("fixture check: tagged confirmation lost presence")
					}
					copy := proof
					store.proof = &copy
					presence = presence || proof.SimulatedPresence
				}
				for _, guard := range tx.Guards {
					if guard.Proof != nil {
						if !guard.Proof.Proof.SimulatedPresence {
							t.Fatal("fixture check: proof-use handoff lost presence")
						}
						presence = presence || guard.Proof.Proof.SimulatedPresence
					}
				}
				for _, stored := range tx.Writes.ReadSessions {
					copy := stored
					store.readSession = &copy
				}
				if !presence {
					t.Fatal("fixture check: simulated operation lost consumed authority mark")
				}
				return api.Commit{Reply: tx.Reply, Operation: api.Operation{ID: "tagged-operation", Status: "succeeded", SimulatedPresence: presence}, FirstSeq: 1, LastSeq: 1}, nil
			}
			confirm := fixtureRequest(t, human, "human.confirm", assertion.request)
			proof, err := s.Confirm(context.Background(), confirm, assertion.request)
			if err != nil || !proof.SimulatedPresence || store.proof == nil || !store.proof.SimulatedPresence {
				t.Fatalf("fixture check: tagged signed confirmation refused or unmarked: %v", err)
			}
			future.Request.Proof = &proof
			future.Frame = &fixtureFrame{raw: launchJSON(t, future.Request)}
			if operation == "ticket" {
				ticket, err := s.TicketIssue(context.Background(), future, body.(api.TicketIssueRequest))
				if err != nil || !ticket.SimulatedPresence {
					t.Fatalf("fixture check: tagged ticket lost provenance: %v", err)
				}
			} else {
				session, err := s.HumanSession(context.Background(), future, api.HumanSessionRequest{})
				if err != nil || !session.SimulatedPresence {
					t.Fatalf("fixture check: tagged session lost provenance: %v", err)
				}
				authority, err := human.Connection.ReadAuthority(context.Background())
				if err != nil || !authority.SimulatedPresence || authority.Generation != store.readSession.Generation {
					t.Fatal("fixture check: tagged read authority lost provenance")
				}
				read := fixtureRequest(t, human, "dashboard.tree", api.DashboardQuery{Limit: 1})
				if err := s.Authorize(context.Background(), read, read.Request); err != nil {
					t.Fatalf("fixture check: tagged read activity refused: %v", err)
				}
				if !store.readSession.Session.SimulatedPresence {
					t.Fatal("fixture check: tagged refresh lost presence")
				}
			}
			if calls != 2 {
				t.Fatal("fixture check: tagged flow did not retain two actual handoffs")
			}
		})
	}
}
