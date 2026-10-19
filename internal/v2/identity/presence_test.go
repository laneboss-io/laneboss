package identity

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestStoredPresenceFixture(t *testing.T) {
	s, store, _ := serviceFixture(t)
	scope := fixtureRequest(t, fixtureHumanScope(t, s, store), "human.session", api.HumanSessionRequest{})
	scope = fixtureOperationProof(t, s, store, scope)
	store.proof.SimulatedPresence = true
	_, err := s.CheckProof(context.Background(), scope, *scope.Request.Proof, store.proof.Target)
	fixtureCode(t, err, api.CodeUnauthenticated)
}

func TestConfirmationPresenceReceiptFixture(t *testing.T) {
	for _, rule := range []string{"operation", "reference"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureHumanScope(t, s, store)
			f := newAssertion(t, nil)
			store.enrollment.Origin, store.enrollment.RPID = f.challenge.Origin, f.challenge.RPID
			store.enrollment.Credentials = []api.HumanCredential{{ID: f.request.CredentialID, RawCredentialID: []byte("public-id"), Algorithm: "ES256", PublicKeyDER: f.public, Counter: 10, Generation: 1}}
			store.challenge = &api.StoredChallenge{EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration, Challenge: f.challenge, PrincipalID: scope.Actor.ID, ConnectionID: scope.Connection.ID(), Generation: 1}
			scope = fixtureRequest(t, scope, "human.confirm", f.request)
			store.transact = func(tx api.Transaction) (api.Commit, error) {
				reply := *tx.Reply
				operation := api.Operation{ID: "confirmation-receipt", Status: "succeeded"}
				if rule == "operation" {
					operation.SimulatedPresence = true
				} else {
					var ref api.ProofRef
					if err := json.Unmarshal(reply.Result, &ref); err != nil {
						t.Fatal(err)
					}
					ref.SimulatedPresence = true
					reply.Result = launchJSON(t, ref)
				}
				return api.Commit{Reply: &reply, Operation: operation, FirstSeq: 1, LastSeq: 1}, nil
			}
			_, err := s.Confirm(context.Background(), scope, f.request)
			fixtureCode(t, err, api.CodeIntegrity)
		})
	}
}
