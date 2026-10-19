package api

import (
	"context"
	"reflect"
	"time"
)

type ReadSessionRefreshRequest struct {
	SessionID          ID
	ExpectedGeneration Generation
}

type ReadSessionStore interface {
	// Identity-only, atomic current-authority/CAS update. Store owns the clock.
	RefreshReadSession(context.Context, Scope, ReadSessionRefreshRequest) (StoredReadSession, error)
}

type ReadAuthorityUpdate struct {
	Before ReadAuthority
	After  ReadAuthority
}

// A required capability of the installed transport, separate from the one-use
// BindReadAuthority. Absence is an owning unavailable/not_implemented error.
type ReadAuthorityRefresher interface {
	RefreshReadAuthority(context.Context, ReadAuthorityUpdate) error
}

func ReadAuthorityFromSession(s StoredReadSession) ReadAuthority {
	return ReadAuthority{ConnectionID: s.ConnectionID, SessionID: s.Session.ID, PrincipalID: s.PrincipalID,
		CredentialID: s.CredentialID, Config: s.Session.Config, EndpointGeneration: s.EndpointGeneration,
		Generation: s.Generation, SimulatedPresence: s.Session.SimulatedPresence,
		IdleExpiresAt: s.Session.IdleExpiresAt, ExpiresAt: s.Session.ExpiresAt}
}

func ValidateReadSessionRefresh(scope Scope, before, after StoredReadSession, now time.Time) error {
	idle, errIdle := time.Parse(time.RFC3339Nano, string(before.Session.IdleExpiresAt))
	abs, errAbs := time.Parse(time.RFC3339Nano, string(before.Session.ExpiresAt))
	if scope.Connection == nil || scope.Actor.Kind != "human" || before.PrincipalID != scope.Actor.ID ||
		before.Session.Config != scope.Config || before.ConnectionID != scope.Connection.ID() || before.EndpointGeneration != scope.EndpointGeneration ||
		!launchID(before.Session.ID) || !launchID(before.CredentialID) || before.Revoked || !launchGeneration(before.Generation) || before.Generation >= launchMaxInteger ||
		errIdle != nil || errAbs != nil || !now.Before(idle) || !now.Before(abs) {
		return launchInvalid("read session refresh lacks current same-connection authority")
	}
	deadline := now.Add(5 * time.Minute)
	if abs.Before(deadline) {
		deadline = abs
	}
	want := before
	want.Generation++
	want.Session.IdleExpiresAt = Timestamp(deadline.UTC().Format(time.RFC3339Nano))
	if !reflect.DeepEqual(after, want) {
		return launchInvalid("read session refresh changed identity, revision or expiry")
	}
	return nil
}

func ValidateReadAuthorityUpdate(current ReadAuthority, update ReadAuthorityUpdate) error {
	if current != update.Before || !launchGeneration(current.Generation) || current.Generation >= launchMaxInteger {
		return launchInvalid("read authority refresh lost its current session revision")
	}
	want := current
	want.Generation++
	want.IdleExpiresAt = update.After.IdleExpiresAt
	deadline, err := time.Parse(time.RFC3339Nano, string(want.IdleExpiresAt))
	abs, absErr := time.Parse(time.RFC3339Nano, string(current.ExpiresAt))
	if update.After != want || err != nil || absErr != nil || deadline.After(abs) {
		return launchInvalid("read authority refresh replaced its bound identity or absolute expiry")
	}
	return nil
}
