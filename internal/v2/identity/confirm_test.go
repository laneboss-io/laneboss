package identity

import (
	"context"
	"reflect"
	"strconv"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestConfirmRevision(t *testing.T) {
	for _, generation := range []api.Generation{1, 41} {
		t.Run(strconv.FormatUint(uint64(generation), 10), func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureHumanScope(t, s, store)
			f := newAssertion(t, nil)
			s.deps.Clock = fixtureClock{f.now}
			store.enrollment.Origin, store.enrollment.RPID = f.challenge.Origin, f.challenge.RPID
			store.enrollment.Credentials = []api.HumanCredential{{ID: f.request.CredentialID, RawCredentialID: []byte("registered-credential"), PublicKeyDER: f.public,
				Algorithm: "ES256", Counter: 10, Generation: 3}}
			before := api.StoredChallenge{EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration, Challenge: f.challenge,
				PrincipalID: scope.Actor.ID, ConnectionID: scope.Connection.ID(), Generation: generation}
			store.challenge = &before
			scope = fixtureRequest(t, scope, "human.confirm", f.request)
			calls := 0
			store.transact = func(tx api.Transaction) (api.Commit, error) {
				calls++
				want := before
				want.Consumed, want.Generation = true, before.Generation+1
				if len(tx.Writes.Challenges) != 1 || !reflect.DeepEqual(tx.Writes.Challenges[0], want) {
					t.Fatal("fixture check: confirmation did not advance the consumed challenge revision")
				}
				if len(tx.Writes.Proofs) != 1 || len(tx.Writes.Counters) != 1 || tx.Writes.Counters[0].Before != 10 || tx.Writes.Counters[0].After != 11 ||
					tx.Writes.Proofs[0].NonceID != before.Challenge.ID || len(tx.Writes.Objects) != 1 || tx.Events[0].Origin != "service" {
					t.Fatal("fixture check: challenge revision split from its signed proof and counter")
				}
				return api.Commit{Reply: tx.Reply, Operation: api.Operation{ID: "confirmation-operation", Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}, nil
			}
			proof, err := s.Confirm(context.Background(), scope, f.request)
			if err != nil || proof.ID == "" || calls != 1 || before.Consumed || before.Generation != generation {
				t.Fatalf("fixture check: signed confirmation revision handoff failed: %v", err)
			}
		})
	}
}
