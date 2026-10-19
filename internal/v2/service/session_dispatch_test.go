package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// An observed receipt ledger isolates dispatch's post-commit behavior. Actual
// session/proof persistence is exercised by the separate store regressions.
type sessionDispatchStore struct {
	unusedStore
	receipt      api.MutationReceipt
	reserved     bool
	errorCommits int
}

func (s *sessionDispatchStore) LookupReceipt(_ context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	if !s.reserved {
		return api.MutationReceipt{}, serviceError(api.CodeNotFound, "fixture session has no reservation")
	}
	if scope.Config != s.receipt.Config || scope.Actor != s.receipt.Actor || key != s.receipt.Key {
		return api.MutationReceipt{}, serviceError(api.CodeForbidden, "fixture session receipt belongs to another request")
	}
	return s.receipt, nil
}
func (s *sessionDispatchStore) ReserveMutation(_ context.Context, input api.RequestReservation) (api.MutationReceipt, bool, error) {
	if s.reserved {
		return s.receipt, false, nil
	}
	s.reserved = true
	s.receipt.Config, s.receipt.Actor = input.Scope.Config, input.Scope.Actor
	s.receipt.Key = api.RequestKey{Method: input.Scope.Request.Method, IdempotencyKey: input.Scope.Request.IdempotencyKey, RequestSHA256: input.Scope.Request.RequestSHA256}
	s.receipt.RawRequest = append([]byte(nil), input.RawRequest...)
	s.receipt.Operation.Status = "pending"
	return s.receipt, true, nil
}
func (s *sessionDispatchStore) Transact(ctx context.Context, input api.Transaction) (api.Commit, error) {
	s.errorCommits++
	if err := ctx.Err(); err != nil {
		return api.Commit{}, err
	}
	if input.Scope.Config != s.receipt.Config || input.Scope.Actor != s.receipt.Actor || input.Reply == nil || input.Reply.Error == nil ||
		input.Scope.Request.IdempotencyKey != s.receipt.Key.IdempotencyKey || !bytes.Equal(input.RawRequest, s.receipt.RawRequest) {
		return api.Commit{}, serviceError(api.CodeIntegrity, "fixture received an unrelated failure transaction")
	}
	// This models the old erroneous failure-commit attempt replaying the actual
	// completed success, making the lost-handler-error regression observable.
	return api.Commit{Operation: s.receipt.Operation, Reply: s.receipt.Reply}, nil
}

type sessionDispatchAuth struct {
	*authFixture
	finalize func(context.Context, api.Scope) (api.HumanSession, error)
}

func (a *sessionDispatchAuth) FinalizeHumanSession(ctx context.Context, scope api.Scope) (api.HumanSession, error) {
	return a.finalize(ctx, scope)
}

type sessionDispatchFrame struct{ raw []byte }

func (f sessionDispatchFrame) Bytes() []byte { return append([]byte(nil), f.raw...) }
func (f sessionDispatchFrame) Verify(ctx context.Context, connection api.ConnectionContext) error {
	if connection == nil || connection.Peer() == nil {
		return serviceError(api.CodeUnauthenticated, "fixture session frame has no peer")
	}
	return connection.Peer().Alive(ctx)
}

func sessionDispatchFixture(t *testing.T) (*Server, *sessionDispatchStore, api.Scope, api.HumanSession) {
	t.Helper()
	host := fixtureServer(t)
	a, b := net.Pipe()
	binding := api.InstalledBinding{Config: host.options.Config, Class: api.EndpointHuman, EndpointGeneration: 1}
	connection, err := newConnection(a, binding, fixtureClock{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close(); b.Close() })
	base := &authFixture{scope: api.Scope{Config: host.options.Config, Actor: api.Actor{Kind: "human", ID: fixtureID(t)}, EndpointGeneration: 1, PolicyGeneration: 1}}
	scope, err := base.Authenticate(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request = requestFor(t, "human.session", api.HumanSessionRequest{})
	scope.Request.Proof = &api.ProofRef{ID: fixtureID(t), RequestSHA256: scope.Request.RequestSHA256,
		ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}
	raw, err := json.Marshal(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame, scope.Source = &sessionDispatchFrame{raw: raw}, "cli"
	session := api.HumanSession{ID: fixtureID(t), Config: scope.Config,
		ExpiresAt:     api.Timestamp(time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339Nano)),
		IdleExpiresAt: api.Timestamp(time.Now().Add(4 * time.Minute).UTC().Format(time.RFC3339Nano))}
	ledger := &sessionDispatchStore{receipt: api.MutationReceipt{Operation: api.Operation{ID: fixtureID(t)}}}
	host.deps.Store, host.deps.Authenticator, host.deps.Binding = ledger, base, binding
	return host, ledger, scope, session
}

func finishSessionDispatch(t *testing.T, ledger *sessionDispatchStore, session api.HumanSession) []byte {
	t.Helper()
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	ledger.receipt.Operation.Status = "succeeded"
	ledger.receipt.Reply = &api.RPCReply{Result: raw}
	ledger.receipt.FirstSeq, ledger.receipt.LastSeq = 1, 2
	return raw
}

func TestSessionDispatchPostCommitError(t *testing.T) {
	host, ledger, scope, session := sessionDispatchFixture(t)
	sentinel := serviceError(api.CodeUnauthenticated, "fixture connection finalization failed")
	called, finalized := 0, 0
	base := host.deps.Authenticator.(*authFixture)
	host.deps.Authenticator = &sessionDispatchAuth{authFixture: base, finalize: func(context.Context, api.Scope) (api.HumanSession, error) {
		finalized++
		return session, nil
	}}
	if err := host.Register("human.session", func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
		called++
		finishSessionDispatch(t, ledger, session)
		return nil, sentinel
	}); err != nil {
		t.Fatal(err)
	}
	reply, _, err := host.dispatchMutation(context.Background(), scope, scope.Request)
	if !errors.Is(err, sentinel) || len(reply) != 0 || called != 1 || finalized != 0 || ledger.errorCommits != 0 ||
		ledger.receipt.Reply == nil || ledger.receipt.Reply.Error != nil || ledger.receipt.Operation.Status != "succeeded" {
		t.Fatal("successful durable receipt masked the post-commit finalization error", err)
	}
}

func TestSessionDispatchFinalization(t *testing.T) {
	for _, rule := range []string{"new", "replay", "refused", "missing", "different"} {
		t.Run(rule, func(t *testing.T) {
			host, ledger, scope, session := sessionDispatchFixture(t)
			base := host.deps.Authenticator.(*authFixture)
			calls, finalized := 0, 0
			sentinel := serviceError(api.CodeUnauthenticated, "fixture replay finalization refused")
			if rule != "missing" {
				host.deps.Authenticator = &sessionDispatchAuth{authFixture: base, finalize: func(_ context.Context, actual api.Scope) (api.HumanSession, error) {
					finalized++
					if actual.Connection != scope.Connection || actual.Frame != scope.Frame || actual.Actor != scope.Actor || actual.Request.RequestID != scope.Request.RequestID {
						t.Fatal("session finalizer lost the original authenticated frame or connection")
					}
					if rule == "refused" {
						return api.HumanSession{}, sentinel
					}
					if rule == "different" {
						other := session
						other.ID = fixtureID(t)
						return other, nil
					}
					authority := api.ReadAuthority{SessionID: session.ID, Config: scope.Config, PrincipalID: scope.Actor.ID,
						CredentialID: scope.Request.Proof.ID, ConnectionID: scope.Connection.ID(), EndpointGeneration: scope.EndpointGeneration,
						Generation: 1, ExpiresAt: session.ExpiresAt, IdleExpiresAt: session.IdleExpiresAt}
					if err := actual.Connection.BindReadAuthority(authority); err != nil {
						return api.HumanSession{}, err
					}
					return session, nil
				}}
			}
			if err := host.Register("human.session", func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
				calls++
				return finishSessionDispatch(t, ledger, session), nil
			}); err != nil {
				t.Fatal(err)
			}
			if rule != "new" {
				if _, _, err := ledger.ReserveMutation(context.Background(), api.RequestReservation{Scope: scope, RawRequest: scope.Frame.Bytes()}); err != nil {
					t.Fatal(err)
				}
				finishSessionDispatch(t, ledger, session)
			}
			reply, _, err := host.dispatchMutation(context.Background(), scope, scope.Request)
			if rule == "new" || rule == "replay" {
				wantCalls := 0
				if rule == "new" {
					wantCalls = 1
				}
				if err != nil || !bytes.Equal(reply, ledger.receipt.Reply.Result) || finalized != 1 || calls != wantCalls {
					t.Fatal("successful session receipt bypassed connection finalization", err)
				}
				if authority, err := scope.Connection.ReadAuthority(context.Background()); err != nil || authority.SessionID != session.ID {
					t.Fatal("successful session dispatch left an unusable connection", err)
				}
				return
			}
			if err == nil || len(reply) != 0 || calls != 0 || ledger.errorCommits != 0 {
				t.Fatal("session replay credited a failed finalizer", err)
			}
			if rule == "refused" && !errors.Is(err, sentinel) {
				t.Fatal("session replay lost its exact finalization refusal", err)
			}
		})
	}
}
