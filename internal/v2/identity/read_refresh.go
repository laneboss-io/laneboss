package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) refreshReadSession(ctx context.Context, scope api.Scope) error {
	if nilDependency(scope.Connection) {
		return refusal(api.CodeUnauthenticated, "read refresh requires its live connection")
	}
	key := sha256.Sum256([]byte(scope.Connection.ID()))
	lock := &s.readLocks[int(key[0])%len(s.readLocks)]
	lock.Lock()
	defer lock.Unlock()
	return s.withReadSession(ctx, scope, func(authority api.ReadAuthority, before api.StoredReadSession) error {
		refresher, ok := scope.Connection.(api.ReadAuthorityRefresher)
		if !ok || nilDependency(refresher) {
			return api.NotImplemented("lb-v2-service", "same-connection read authority refresh")
		}
		started := s.deps.Clock.Now()
		after, err := s.deps.Store.RefreshReadSession(ctx, scope, api.ReadSessionRefreshRequest{SessionID: before.Session.ID, ExpectedGeneration: before.Generation})
		if err != nil {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeConflict {
				return errors.Join(err, scope.Connection.Close())
			}
			// Reconcile only the same committed next revision. Never replace the
			// one-use bind or invent a refresh after a stale CAS.
			reloaded, readErr := s.deps.Store.ReadSession(ctx, scope, before.Session.ID)
			if readErr != nil {
				return errors.Join(readErr, scope.Connection.Close())
			}
			if reflect.DeepEqual(before, reloaded) {
				return err
			}
			after = reloaded
		}
		ended := s.deps.Clock.Now()
		if err := validateCommittedRefresh(scope, before, after, started, ended); err != nil {
			return errors.Join(err, scope.Connection.Close())
		}
		update := api.ReadAuthorityUpdate{Before: authority, After: api.ReadAuthorityFromSession(after)}
		if err := api.ValidateReadAuthorityUpdate(authority, update); err != nil {
			return errors.Join(err, scope.Connection.Close())
		}
		if err := refresher.RefreshReadAuthority(ctx, update); err != nil {
			return errors.Join(err, scope.Connection.Close())
		}
		current, err := scope.Connection.ReadAuthority(ctx)
		if err != nil || current != update.After {
			return errors.Join(refusal(api.CodeIntegrity, "transport did not retain the committed session refresh"), err, scope.Connection.Close())
		}
		if scope.ReadAuthority != nil {
			*scope.ReadAuthority = current
		}
		return nil
	})
}

// Store owns the clock used for the atomic commit. Its returned idle deadline
// determines that instant, bounded by the observed call interval; capped idle
// uses the unchanged absolute expiry. This avoids equating two independent
// time.Now calls to the nanosecond while still checking the exact shared rule.
func validateCommittedRefresh(scope api.Scope, before, after api.StoredReadSession, started, ended time.Time) error {
	idle, err := utcTime(after.Session.IdleExpiresAt)
	abs, absErr := utcTime(before.Session.ExpiresAt)
	if err != nil || absErr != nil || ended.Before(started) {
		return refusal(api.CodeIntegrity, "invalid committed session refresh clock")
	}
	committed := idle.Add(-5 * time.Minute)
	if idle.Equal(abs) {
		committed = ended
	}
	if committed.Before(started) || committed.After(ended) {
		return refusal(api.CodeIntegrity, "session refresh is outside its observed commit interval")
	}
	return api.ValidateReadSessionRefresh(scope, before, after, committed)
}
