package store

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type readSessionConnection struct {
	api.ConnectionContext
	id      api.ID
	binding api.InstalledBinding
}

func (c readSessionConnection) ID() api.ID                    { return c.id }
func (c readSessionConnection) Binding() api.InstalledBinding { return c.binding }

func (s *Service) RefreshReadSession(ctx context.Context, scope api.Scope, request api.ReadSessionRefreshRequest) (api.StoredReadSession, error) {
	// Transport callbacks precede the writer lock. The connection serializes
	// activity; no store writer calls back into transport while holding mu.
	if scope.Connection == nil || scope.Connection.Peer() == nil {
		return api.StoredReadSession{}, fault(api.CodeUnauthenticated, "session refresh requires the bound human connection")
	}
	if err := scope.Connection.Peer().Alive(ctx); err != nil {
		return api.StoredReadSession{}, err
	}
	authority, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return api.StoredReadSession{}, err
	}
	scope.Connection = readSessionConnection{id: scope.Connection.ID(), binding: scope.Connection.Binding()}
	s.mu.Lock()
	defer s.mu.Unlock()
	var before api.StoredReadSession
	if err := s.available(); err != nil {
		return before, err
	}
	if scope.Actor.Kind != "human" || scope.Config != s.deps.Config || authority.SessionID != request.SessionID || authority.ConnectionID != scope.Connection.ID() || authority.PrincipalID != scope.Actor.ID || scope.Connection.Binding().Class != api.EndpointHuman || scope.Connection.Binding().Config != scope.Config || scope.Connection.Binding().EndpointGeneration != scope.EndpointGeneration {
		return before, fault(api.CodeUnauthenticated, "session refresh belongs to another installed connection")
	}
	if err := storedProjection(ctx, s.db, "read_session", request.SessionID, &before); err != nil {
		return before, err
	}
	if before.Generation != request.ExpectedGeneration || api.ReadAuthorityFromSession(before) != authority {
		return api.StoredReadSession{}, fault(api.CodeConflict, "session refresh revision changed")
	}
	var enrollment api.HumanEnrollment
	if err := storedProjection(ctx, s.db, "enrollment", scope.Actor.ID, &enrollment); err != nil {
		return before, err
	}
	found := false
	for _, key := range enrollment.Credentials {
		if key.ID == before.CredentialID && !key.Revoked {
			if err := api.ValidateCredentialPresence(key); err != nil {
				return before, err
			}
			if key.SimulatedPresence != before.Session.SimulatedPresence {
				return before, fault(api.CodeForbidden, "session lost enrolled presence provenance")
			}
			found = true
		}
	}
	if !found {
		return before, fault(api.CodeUnauthenticated, "session refresh credential was revoked")
	}
	now := s.deps.Clock.Now()
	deadline := now.Add(5 * time.Minute)
	absolute, err := time.Parse(time.RFC3339Nano, string(before.Session.ExpiresAt))
	if err != nil {
		return before, err
	}
	if absolute.Before(deadline) {
		deadline = absolute
	}
	after := before
	after.Generation++
	after.Session.IdleExpiresAt = api.Timestamp(deadline.UTC().Format(time.RFC3339Nano))
	if err := api.ValidateReadSessionRefresh(scope, before, after, now); err != nil {
		return api.StoredReadSession{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return before, err
	}
	defer tx.Rollback()
	if err := s.compare(ctx, tx, []api.Compare{{Kind: "read_session", ID: request.SessionID, Generation: request.ExpectedGeneration}}); err != nil {
		return before, err
	}
	if err := put(ctx, tx, "read_session", request.SessionID, after.Generation, after); err != nil {
		return before, err
	}
	if err := tx.Commit(); err != nil {
		return before, err
	}
	return after, nil
}
