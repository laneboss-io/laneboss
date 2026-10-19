package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type noRefreshConnection struct{ api.ConnectionContext }

func TestReadRefreshFixture(t *testing.T) {
	for _, rule := range []string{"valid", "cap", "absolute", "connection", "transport", "noop", "conflict", "expired", "missing"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureReadScope(t, s, store)
			connection := scope.Connection.(*fixtureConnection)
			store.readSession.Session.IdleExpiresAt = timestamp(s.deps.Clock.Now().Add(time.Minute))
			if rule == "cap" {
				store.readSession.Session.ExpiresAt = timestamp(s.deps.Clock.Now().Add(2 * time.Minute))
			}
			if rule == "expired" {
				store.readSession.Session.IdleExpiresAt = timestamp(s.deps.Clock.Now())
			}
			connection.authority = api.ReadAuthorityFromSession(*store.readSession)
			snapshot := connection.authority
			scope.ReadAuthority = &snapshot
			before := *store.readSession
			original := store.refresh
			calls := 0
			sentinel := api.NotImplemented("lb-v2-service", "fixture local refresh failed")
			store.refresh = func(ctx context.Context, scope api.Scope, request api.ReadSessionRefreshRequest) (api.StoredReadSession, error) {
				calls++
				after, err := original(ctx, scope, request)
				if err != nil {
					return after, err
				}
				switch rule {
				case "absolute":
					after.Session.ExpiresAt = timestamp(s.deps.Clock.Now().Add(time.Hour))
				case "connection":
					after.ConnectionID = "foreign-connection"
				}
				store.readSession = &after
				if rule == "conflict" {
					return api.StoredReadSession{}, &api.Error{Code: api.CodeConflict, Message: "fixture concurrent commit"}
				}
				return after, nil
			}
			if rule == "absolute" || rule == "connection" {
				// A controlled transport projection lets the identity consumer's
				// validators decide, without masking them behind another mock gate.
				connection.refreshApply = func(update api.ReadAuthorityUpdate) error {
					connection.authority = update.After
					connection.refreshes++
					return nil
				}
			}
			if rule == "transport" {
				connection.refreshErr = sentinel
			}
			if rule == "noop" {
				connection.refreshApply = func(update api.ReadAuthorityUpdate) error {
					if err := api.ValidateReadAuthorityUpdate(connection.authority, update); err != nil {
						return err
					}
					connection.refreshes++
					return nil
				}
			}
			if rule == "missing" {
				scope.Connection = noRefreshConnection{scope.Connection}
			}
			scope = fixtureRequest(t, scope, "dashboard.tree", api.DashboardQuery{Limit: 1})
			err := s.Authorize(context.Background(), scope, scope.Request)
			switch rule {
			case "absolute", "connection":
				fixtureCode(t, err, api.CodeInvalid)
				if connection.closes != 1 {
					t.Fatal("fixture check: invalid committed refresh left its connection open")
				}
				return
			case "transport":
				if !errors.Is(err, sentinel) || connection.closes != 1 || store.readSession.Generation != before.Generation+1 {
					t.Fatal("fixture check: failed local refresh lost commit or connection closure")
				}
				return
			case "noop":
				fixtureCode(t, err, api.CodeIntegrity)
				if connection.closes != 1 {
					t.Fatal("fixture check: false local refresh success left connection open")
				}
				return
			case "expired":
				fixtureCode(t, err, api.CodeUnauthenticated)
				if calls != 0 || store.readSession.Generation != before.Generation {
					t.Fatal("fixture check: expired session was refreshed")
				}
				return
			case "missing":
				fixtureCode(t, err, api.CodeNotImplemented)
				if calls != 0 {
					t.Fatal("fixture check: store changed without transport refresh capability")
				}
				return
			}
			if err != nil || calls != 1 || connection.refreshes != 1 || connection.readBinds != 1 || store.readSession.Generation != before.Generation+1 ||
				store.readSession.Session.ExpiresAt != before.Session.ExpiresAt || connection.authority != api.ReadAuthorityFromSession(*store.readSession) || snapshot != connection.authority {
				t.Fatalf("fixture check: same-session activity was not committed and refreshed: %v", err)
			}
			if rule == "cap" && store.readSession.Session.IdleExpiresAt != before.Session.ExpiresAt {
				t.Fatal("fixture check: idle refresh exceeded absolute expiry")
			}
		})
	}
}
