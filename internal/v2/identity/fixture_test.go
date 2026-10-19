package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// These are package fixtures, not installed-socket acceptance. In particular,
// a not_implemented result proves only that no authority was manufactured.
func fixtureCode(t *testing.T, err error, want api.ErrorCode) {
	t.Helper()
	got := "success"
	if err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) {
			t.Fatalf("fixture setup: untyped result: %v", err)
		}
		got = string(typed.Code)
	}
	if got != string(want) {
		t.Fatalf("fixture check: want %s, got %s", want, got)
	}
}

func TestHumanReplayFixture(t *testing.T) {
	for _, rule := range []string{"nonce", "counter"} {
		t.Run(rule, func(t *testing.T) {
			f := newAssertion(t, nil)
			counter, err := VerifyAssertion(f.challenge, "credential", f.public, 10, f.request, f.now)
			if err != nil || counter != 11 {
				t.Fatalf("fixture setup: authentic assertion failed: %v", err)
			}
			previous := uint32(10)
			if rule == "nonce" {
				// Replay the old signed bytes under a fresh server challenge ID
				// and nonce. The envelope's challenge ID is not itself signed.
				nonce := make([]byte, 32)
				if _, err := rand.Read(nonce); err != nil || bytes.Equal(nonce, f.challenge.Challenge) {
					t.Fatal("fixture setup: fresh nonce generation failed")
				}
				f.challenge.ID = "fresh-challenge"
				f.challenge.Challenge = nonce
				f.request.ChallengeID = f.challenge.ID
			} else {
				// Use the real counter returned by the first verification. No
				// fixture ticket/proof database substitutes for production state.
				previous = counter
			}
			_, err = VerifyAssertion(f.challenge, "credential", f.public, previous, f.request, f.now)
			fixtureCode(t, err, api.CodeUnauthenticated)
		})
	}
}

func TestSignedJSONFixture(t *testing.T) {
	for _, rule := range []string{"duplicate", "null"} {
		t.Run(rule, func(t *testing.T) {
			f := newAssertion(t, nil)
			if rule == "duplicate" {
				origin, err := json.Marshal(f.challenge.Origin)
				if err != nil {
					t.Fatalf("fixture setup: origin encoding failed: %v", err)
				}
				data := bytes.TrimSuffix(f.request.ClientDataJSON, []byte("}"))
				data = append(data, []byte(",\"origin\":")...)
				data = append(data, origin...)
				f.request.ClientDataJSON = append(data, '}')
			} else {
				var client map[string]any
				if err := json.Unmarshal(f.request.ClientDataJSON, &client); err != nil {
					t.Fatalf("fixture setup: client decoding failed: %v", err)
				}
				client["crossOrigin"] = nil
				data, err := json.Marshal(client)
				if err != nil {
					t.Fatalf("fixture setup: null encoding failed: %v", err)
				}
				f.request.ClientDataJSON = data
			}
			// A valid signature must not mask malformed signed JSON.
			f.sign(t)
			_, err := VerifyAssertion(f.challenge, "credential", f.public, 10, f.request, f.now)
			fixtureCode(t, err, api.CodeInvalid)
		})
	}
}

func TestHumanProofFixture(t *testing.T) {
	for _, rule := range []string{"principal", "config", "digest", "expiry", "proof-id", "commit-gap"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			human := api.Scope{Config: "fixture", Actor: api.Actor{Kind: "human", ID: "human"}}
			intent := api.HumanChallengeRequest{Method: "ticket.issue", TargetID: "root",
				RequestSHA256: store.record.GrantsSHA256, BaseGeneration: 1}
			proof := api.ProofRef{ID: "proof", RequestSHA256: intent.RequestSHA256,
				ExpiresAt: api.Timestamp(s.deps.Clock.Now().Add(time.Minute).Format(time.RFC3339Nano))}
			want := api.CodeUnauthenticated
			switch rule {
			case "principal":
				human.Actor.Kind = "lane"
			case "config":
				human.Config = ""
			case "digest":
				proof.RequestSHA256 = "different-intent"
			case "expiry":
				proof.ExpiresAt = api.Timestamp(s.deps.Clock.Now().Format(time.RFC3339Nano))
			case "proof-id":
				proof.ID = ""
			case "commit-gap":
				want = api.CodeNotImplemented
			}
			_, err := s.CheckProof(context.Background(), human, proof, intent)
			fixtureCode(t, err, want)
		})
	}
}

func TestHumanNoProofFixture(t *testing.T) {
	for _, operation := range []struct {
		name   string
		method api.Method
	}{{"ticket", "ticket.issue"}, {"root", "grants.root"}, {"approval", "org.change.approve"}} {
		t.Run(operation.name, func(t *testing.T) {
			s, _, _ := serviceFixture(t)
			human := api.Scope{Config: "fixture", Actor: api.Actor{Kind: "human", ID: "human"}}
			request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
				Config: human.Config, Method: operation.method, Proof: &api.ProofRef{ID: "proof"}}
			// A label plus a reference still cannot authorize without the
			// missing trusted connection and atomic proof transaction.
			fixtureCode(t, s.Authorize(context.Background(), human, request), api.CodeNotImplemented)
			request.Proof = nil
			fixtureCode(t, s.Authorize(context.Background(), human, request), api.CodeUnauthenticated)
		})
	}
}

func TestTicketGuardsFixture(t *testing.T) {
	for _, rule := range []string{"level-low", "level-high", "role", "grants", "expiry",
		"principal", "method", "proof", "store-gap"} {
		t.Run(rule, func(t *testing.T) {
			s, _, _ := serviceFixture(t)
			scope := api.Scope{Config: "fixture", Actor: api.Actor{Kind: "human", ID: "human"},
				Request: api.Request{Method: "ticket.issue", Proof: &api.ProofRef{ID: "proof"}}}
			request := api.TicketIssueRequest{Level: 6, Role: "supervisor", GrantSetID: "root-grants",
				ExpiresAt: api.Timestamp(s.deps.Clock.Now().Add(time.Minute).Format(time.RFC3339Nano))}
			want := api.CodeInvalid
			switch rule {
			case "level-low":
				request.Level = 2
			case "level-high":
				request.Level = 7
			case "role":
				request.Role = "invalid/role"
			case "grants":
				request.GrantSetID = "invalid/grants"
			case "expiry":
				request.ExpiresAt = api.Timestamp(s.deps.Clock.Now().Format(time.RFC3339Nano))
			case "principal":
				scope.Actor.Kind, want = "lane", api.CodeUnauthenticated
			case "method":
				scope.Request.Method, want = "lane.start", api.CodeUnauthenticated
			case "proof":
				scope.Request.Proof, want = nil, api.CodeUnauthenticated
			case "store-gap":
				want = api.CodeNotImplemented
			}
			ticket, err := s.TicketIssue(context.Background(), scope, request)
			fixtureCode(t, err, want)
			if !reflect.DeepEqual(ticket, api.Ticket{}) {
				t.Fatal("fixture check: refused issuance manufactured a ticket")
			}
		})
	}
}

func TestLabelScopeFixture(t *testing.T) {
	for _, label := range []string{"actor", "level", "role"} {
		t.Run(label, func(t *testing.T) {
			s, _, scope := serviceFixture(t)
			// These task-local forged labels never change the live session's
			// configuration/home binding, and their values are never printed.
			t.Setenv("LANEBOSS_ACTOR", "human")
			t.Setenv("LANEBOSS_LEVEL", "6")
			t.Setenv("LANEBOSS_ROLE", "owner")
			authentic, err := s.IdentitySelf(context.Background(), scope, api.Empty{})
			if err != nil || authentic.Actor != scope.Actor {
				t.Fatal("fixture setup: labels altered the authentic projection")
			}
			switch label {
			case "actor":
				scope.Actor.ID = "other-instance"
			case "level":
				scope.Actor.Level = 6
			case "role":
				scope.Actor.Role = "owner"
			}
			_, err = s.IdentitySelf(context.Background(), scope, api.Empty{})
			fixtureCode(t, err, api.CodeUnauthenticated)
		})
	}
}
