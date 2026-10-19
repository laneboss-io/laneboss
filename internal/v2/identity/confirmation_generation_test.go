package identity

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// This observes the real signed confirmation's transaction handoff. Durable
// compare-and-consume behavior is covered by the store's separate CAS fixture.
func TestConfirmGenerationFixture(t *testing.T) {
	for _, test := range []struct {
		name       string
		generation api.Generation
		base       api.Generation
	}{
		{"fresh", 1, 0},
		{"advanced", 9, 71},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			assertion := newAssertion(t, nil)
			s.deps.Clock = fixtureClock{assertion.now}
			human := fixtureHumanScope(t, s, store)
			store.enrollment.Origin, store.enrollment.RPID = assertion.challenge.Origin, assertion.challenge.RPID
			store.enrollment.Generation = 19
			store.enrollment.Credentials = []api.HumanCredential{{ID: assertion.request.CredentialID,
				RawCredentialID: []byte("confirmation-credential"), Algorithm: "ES256", PublicKeyDER: assertion.public,
				Counter: 10, Generation: 23}}
			operation := fixtureRequest(t, human, "human.session", api.HumanSessionRequest{})
			assertion.challenge.Method = operation.Request.Method
			assertion.challenge.TargetID = human.Actor.ID
			assertion.challenge.RequestSHA256 = operation.Request.RequestSHA256
			assertion.challenge.BaseGeneration = test.base
			prior := api.StoredChallenge{EndpointClass: api.EndpointHuman, EndpointGeneration: human.EndpointGeneration,
				Challenge: assertion.challenge, PrincipalID: human.Actor.ID, ConnectionID: human.Connection.ID(),
				Generation: test.generation}
			store.challenge = &prior
			scope := fixtureRequest(t, human, "human.confirm", assertion.request)
			calls := 0
			store.transact = func(tx api.Transaction) (api.Commit, error) {
				calls++
				if err := api.ValidateTransactionShape(tx); err != nil {
					t.Fatalf("fixture check: confirmation has invalid atomic handoff: %v", err)
				}
				next := tx.Writes.Challenges[0]
				if next.Generation != prior.Generation+1 {
					t.Fatal("fixture check: confirmation did not advance the challenge revision")
				}
				expected := prior
				expected.Consumed, expected.Generation = true, prior.Generation+1
				if !reflect.DeepEqual(next, expected) {
					t.Fatal("fixture check: confirmation changed immutable challenge facts")
				}
				if prior.Consumed || prior.Generation != test.generation {
					t.Fatal("fixture check: confirmation changed retained challenge before commit")
				}
				counter := tx.Writes.Counters[0]
				if counter.ExpectedGeneration != store.enrollment.Credentials[0].Generation || counter.Before != 10 || counter.After != 11 {
					t.Fatal("fixture check: challenge revision replaced the independent credential counter CAS")
				}
				return api.Commit{Reply: tx.Reply, Operation: api.Operation{ID: "confirmation-operation", Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}, nil
			}
			proof, err := s.Confirm(context.Background(), scope, assertion.request)
			if err != nil || calls != 1 || proof.ID == "" || proof.RequestSHA256 != operation.Request.RequestSHA256 || proof.ExpiresAt != prior.Challenge.ExpiresAt {
				t.Fatalf("fixture check: signed confirmation lost its exact proof or handoff: %v", err)
			}
		})
	}
}
