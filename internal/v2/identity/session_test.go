package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func fixtureSession(t *testing.T) (*Service, *fixtureStore, api.Scope) {
	t.Helper()
	s, store, _ := serviceFixture(t)
	scope := fixtureRequest(t, fixtureHumanScope(t, s, store), "human.session", api.HumanSessionRequest{})
	scope = fixtureOperationProof(t, s, store, scope)
	store.strictReads = true
	store.transact = func(tx api.Transaction) (api.Commit, error) {
		if len(tx.Writes.ReadSessions) != 1 || len(tx.Guards) != 1 || tx.Guards[0].Proof == nil ||
			tx.Guards[0].Proof.Proof != store.proof.Ref || tx.Guards[0].Proof.Target != store.proof.Target {
			t.Fatal("fixture setup: session transaction lacks its exact proof and session")
		}
		stored := tx.Writes.ReadSessions[0]
		store.readSession = &stored
		return api.Commit{Reply: tx.Reply, Operation: api.Operation{ID: "session-operation", Status: "succeeded"}, FirstSeq: 2, LastSeq: 2}, nil
	}
	return s, store, scope
}

func TestSessionFinalize(t *testing.T) {
	for _, rule := range []string{"current", "stale", "foreign", "credential", "proof", "receipt", "bytes", "expired", "presence", "read-fail", "missing", "unretained"} {
		t.Run(rule, func(t *testing.T) {
			s, store, scope := fixtureSession(t)
			connection := scope.Connection.(*fixtureConnection)
			want := api.CodeUnauthenticated
			sentinel := api.NotImplemented("lb-v2-service", "fixture private read failure")
			store.sessionRead = func(context.Context, api.Scope) (SessionCommit, error) {
				if store.sessionCommit == nil {
					t.Fatal("fixture setup: no committed session snapshot")
				}
				snapshot := *store.sessionCommit
				snapshot.Enrollment.Credentials = append([]api.HumanCredential(nil), snapshot.Enrollment.Credentials...)
				switch rule {
				case "stale":
					snapshot.Session.Generation++
				case "foreign":
					snapshot.Session.ConnectionID = "foreign-connection"
				case "credential":
					snapshot.Enrollment.Credentials[0].Revoked = true
				case "proof":
					snapshot.Proof.ConsumedBy = "foreign-operation"
				case "receipt":
					snapshot.Receipt.Key.IdempotencyKey = "foreign-key"
				case "bytes":
					snapshot.Receipt.RawRequest = append(append([]byte(nil), snapshot.Receipt.RawRequest...), ' ')
				case "expired":
					s.deps.Clock = fixtureClock{s.deps.Clock.Now().Add(6 * time.Minute)}
				case "presence":
					snapshot.Receipt.SimulatedPresence = true
				case "read-fail":
					return SessionCommit{}, sentinel
				}
				return snapshot, nil
			}
			if rule == "receipt" || rule == "bytes" || rule == "unretained" {
				want = api.CodeIntegrity
			}
			if rule == "missing" {
				s.deps.Sessions = nil
				want = api.CodeNotImplemented
			}
			if rule == "unretained" {
				connection.readBindApply = func(api.ReadAuthority) error { return nil }
			}
			result, err := s.HumanSession(context.Background(), scope, api.HumanSessionRequest{})
			if rule == "current" {
				if err != nil || result.ID == "" || connection.readBinds != 1 || store.privateReads != 1 || store.publicReads != 0 {
					t.Fatalf("fixture check: private session finalization failed: %v", err)
				}
				read := fixtureRequest(t, scope, "identity.self", api.Empty{})
				view, err := s.IdentitySelf(context.Background(), read, api.Empty{})
				if err != nil || view.Actor != scope.Actor || store.publicReads != 1 {
					t.Fatalf("fixture check: finalized connection cannot read itself: %v", err)
				}
				return
			}
			if rule == "read-fail" {
				if !errors.Is(err, sentinel) || store.sessionCommit == nil {
					t.Fatal("fixture check: durable receipt masked private finalization refusal")
				}
			} else {
				fixtureCode(t, err, want)
			}
			if rule != "unretained" && connection.readBindAttempts != 0 {
				t.Fatal("fixture check: invalid finalization reached connection binding")
			}
			if !reflect.DeepEqual(result, api.HumanSession{}) || connection.readBinds != 0 || store.publicReads != 0 {
				t.Fatal("fixture check: failed finalization returned or bound authority")
			}
			if rule == "unretained" && connection.closes != 1 {
				t.Fatal("fixture check: false transport bind left the connection open")
			}
			if rule == "missing" && store.transaction != nil {
				t.Fatal("fixture check: session committed without private read-back capability")
			}
		})
	}
}

func TestSessionReplay(t *testing.T) {
	for _, rule := range []string{"same", "foreign"} {
		t.Run(rule, func(t *testing.T) {
			s, store, scope := fixtureSession(t)
			first, err := s.HumanSession(context.Background(), scope, api.HumanSessionRequest{})
			if err != nil {
				t.Fatalf("fixture setup: initial finalization failed: %v", err)
			}
			connection := scope.Connection.(*fixtureConnection)
			if rule == "foreign" {
				other := fixtureHumanScope(t, s, store)
				other.Request, other.Frame, other.Source = scope.Request, scope.Frame, scope.Source
				scope, connection = other, other.Connection.(*fixtureConnection)
			}
			result, err := s.FinalizeHumanSession(context.Background(), scope)
			if rule == "same" {
				if err != nil || result != first || connection.readBinds != 1 || connection.readBindAttempts != 1 || store.privateReads != 2 {
					t.Fatalf("fixture check: exact finalization replay replaced or lost authority: %v", err)
				}
			} else {
				fixtureCode(t, err, api.CodeUnauthenticated)
				if connection.readBindAttempts != 0 || result != (api.HumanSession{}) {
					t.Fatal("fixture check: foreign socket reached committed-session activation")
				}
			}
		})
	}
}

func TestRootPrelude(t *testing.T) {
	for _, rule := range []string{"current", "ticket-only", "envelope"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureReadScope(t, s, store)
			connection := scope.Connection.(*fixtureConnection)
			if rule == "ticket-only" {
				connection.authority = api.ReadAuthority{}
			}
			scope = fixtureRequest(t, scope, "lane.start", fixtureAuthorityBody("lane.start"))
			if rule == "envelope" {
				scope = fixtureOperationProof(t, s, store, scope)
			}
			err := s.Authorize(context.Background(), scope, scope.Request)
			if rule == "current" {
				if err != nil || connection.refreshes != 1 || store.transaction != nil {
					t.Fatalf("fixture check: root prelude did not authorize read-only preflight: %v", err)
				}
				return
			}
			want := api.CodeUnauthenticated
			if rule == "envelope" {
				want = api.CodeForbidden
			}
			fixtureCode(t, err, want)
			if connection.refreshes != 0 || store.transaction != nil {
				t.Fatal("fixture check: root ticket or envelope became preflight read authority")
			}
		})
	}
}

func TestHumanEventSource(t *testing.T) {
	s, store, scope := fixtureSession(t)
	result, err := s.HumanSession(context.Background(), scope, api.HumanSessionRequest{})
	if err != nil || result.ID == "" || store.transaction == nil {
		t.Fatalf("fixture check: service-origin human event failed: %v", err)
	}
	events := store.transaction.Events
	if len(events) != 1 || events[0].Origin != "service" || events[0].Actor != scope.Actor || events[0].RequestedBy != scope.Actor || scope.Source != "cli" {
		t.Fatal("fixture check: human event changed trust origin or authenticated requester")
	}
}
