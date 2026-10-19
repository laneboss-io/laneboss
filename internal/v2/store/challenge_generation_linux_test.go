//go:build linux

package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Exercise the real SQLite challenge writer and its CAS. Enrollment/transport
// are explicit component fixtures; this is not native or installed acceptance.
func TestChallengeGenerationCAS(t *testing.T) {
	for _, rule := range []string{"advance", "stale", "jump", "used", "immutable"} {
		t.Run(rule, func(t *testing.T) {
			s, _ := testStore(t)
			ctx := context.Background()
			principal := testID(t)
			connection := &scopeConnection{id: testID(t), binding: api.InstalledBinding{
				Config: s.deps.Config, Class: api.EndpointHuman, EndpointGeneration: 7}}
			enrollment := api.HumanEnrollment{Config: s.deps.Config, PrincipalID: principal,
				Origin: "https://ceremony.invalid", RPID: "ceremony.invalid", Generation: 19}
			fixtureProjection(t, s, "enrollment", principal, enrollment.Generation, enrollment)
			scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "human", ID: principal},
				Connection: connection, EndpointGeneration: 7,
				Request: api.Request{Method: "human.challenge"}}
			prior := api.StoredChallenge{EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration,
				PrincipalID: principal, ConnectionID: connection.ID(), Generation: 1,
				Challenge: api.HumanChallenge{ID: testID(t), Challenge: []byte(testID(t)), Config: scope.Config,
					Method: "human.session", TargetID: principal, RequestSHA256: testDigest([]byte("session operation")),
					Origin: enrollment.Origin, RPID: enrollment.RPID,
					ExpiresAt: api.Timestamp(s.deps.Clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}}
			write := func(value api.StoredChallenge, want api.ErrorCode) {
				t.Helper()
				tx, err := s.db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				input := api.Transaction{Scope: scope, Writes: api.StateWrites{Challenges: []api.StoredChallenge{value}}}
				err = s.identityWrites(ctx, tx, input, "Challenges")
				if err != nil {
					if rollbackErr := tx.Rollback(); rollbackErr != nil {
						t.Fatal(rollbackErr)
					}
					if want == "" {
						t.Fatalf("challenge transition refused valid revision: %v", err)
					}
					expectCode(t, err, want)
					return
				}
				if want != "" {
					if rollbackErr := tx.Rollback(); rollbackErr != nil {
						t.Fatal(rollbackErr)
					}
					t.Fatal("challenge CAS accepted " + rule)
				}
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			// Issue through the production writer; it must retain unused revision 1.
			write(prior, "")
			var issued api.StoredChallenge
			if err := storedProjection(ctx, s.db, "challenge", prior.Challenge.ID, &issued); err != nil || !reflect.DeepEqual(issued, prior) {
				t.Fatal("challenge issue did not retain the unused initial revision", err)
			}
			scope.Request.Method = "human.confirm"
			if rule == "used" {
				prior.Consumed, prior.Generation = true, prior.Generation+1
				write(prior, "")
			}
			next := prior
			next.Consumed, next.Generation = true, prior.Generation+1
			want := api.CodeConflict
			switch rule {
			case "advance":
				want = ""
			case "stale":
				next.Generation = prior.Generation
			case "jump":
				next.Generation++
			case "immutable":
				next.Challenge.TargetID = testID(t)
				want = api.CodeForbidden
			}
			write(next, want)
			expected := prior
			if want == "" {
				expected = next
			}
			var retained api.StoredChallenge
			if err := storedProjection(ctx, s.db, "challenge", prior.Challenge.ID, &retained); err != nil || !reflect.DeepEqual(retained, expected) {
				t.Fatal("challenge CAS changed retained facts after "+rule, err)
			}
		})
	}
}
