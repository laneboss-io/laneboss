//go:build linux

package store

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
	"net"
	"testing"
	"time"
)

func sessionFixture(t *testing.T) (*Service, api.Scope, api.StoredReadSession) {
	t.Helper()
	s, _ := testStore(t)
	input := validatedEnrollmentInput(t, s)
	if _, err := commitEnrollmentFixture(context.Background(), s, input); err != nil {
		t.Fatal(err)
	}
	principal := input.Writes.Enrollments[0].Enrollment
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	connection := &scopeConnection{id: testID(t), conn: a, peer: &scopePeer{}, binding: api.InstalledBinding{Config: s.deps.Config, Class: api.EndpointHuman, EndpointGeneration: 7}}
	session := api.StoredReadSession{Session: api.HumanSession{ID: testID(t), Config: s.deps.Config, IdleExpiresAt: api.Timestamp(time.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}, PrincipalID: principal.PrincipalID, CredentialID: principal.Credentials[0].ID, ConnectionID: connection.id, EndpointGeneration: 7, Generation: 1}
	fixtureProjection(t, s, "read_session", session.Session.ID, 1, session)
	authority := api.ReadAuthorityFromSession(session)
	connection.authority = &authority
	scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "human", ID: principal.PrincipalID}, Connection: connection, EndpointGeneration: 7}
	return s, scope, session
}

func TestDurableSessionRefresh(t *testing.T) {
	s, scope, before := sessionFixture(t)
	actual, err := s.RefreshReadSession(context.Background(), scope, api.ReadSessionRefreshRequest{SessionID: before.Session.ID, ExpectedGeneration: 1})
	if err != nil || actual.Generation != 2 || actual.Session.IdleExpiresAt != before.Session.ExpiresAt || actual.Session.ExpiresAt != before.Session.ExpiresAt || actual.ConnectionID != before.ConnectionID {
		t.Fatal("durable session refresh lost its absolute cap or bound identity", err)
	}
	if _, err := s.RefreshReadSession(context.Background(), scope, api.ReadSessionRefreshRequest{SessionID: before.Session.ID, ExpectedGeneration: 1}); err == nil {
		t.Fatal("session refresh replay accepted a stale revision")
	}
}

func TestSessionRefreshFences(t *testing.T) {
	for _, fault := range []string{"expired_idle", "expired_absolute", "revoked", "foreign_connection", "foreign_binding", "stale_revision", "revoked_credential"} {
		t.Run(fault, func(t *testing.T) {
			s, scope, before := sessionFixture(t)
			request := api.ReadSessionRefreshRequest{SessionID: before.Session.ID, ExpectedGeneration: 1}
			switch fault {
			case "expired_idle":
				before.Session.IdleExpiresAt = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
			case "expired_absolute":
				before.Session.ExpiresAt = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
			case "revoked":
				before.Revoked = true
			case "foreign_connection":
				before.ConnectionID = testID(t)
			case "foreign_binding":
				scope.Connection.(*scopeConnection).binding.Config = "other-config"
			case "stale_revision":
				request.ExpectedGeneration++
			case "revoked_credential":
				var enrollment api.HumanEnrollment
				if err := storedProjection(context.Background(), s.db, "enrollment", before.PrincipalID, &enrollment); err != nil {
					t.Fatal(err)
				}
				enrollment.Credentials[0].Revoked = true
				fixtureProjection(t, s, "enrollment", enrollment.PrincipalID, 1, enrollment)
			}
			fixtureProjection(t, s, "read_session", before.Session.ID, before.Generation, before)
			a := api.ReadAuthorityFromSession(before)
			scope.Connection.(*scopeConnection).authority = &a
			if _, err := s.RefreshReadSession(context.Background(), scope, request); err == nil {
				t.Fatal("durable session refresh accepted " + fault)
			}
		})
	}
}

func TestProofPresenceFences(t *testing.T) {
	for _, fault := range []string{"credential_mark", "reference_mark", "foreign_enrollment", "revoked_credential"} {
		t.Run(fault, func(t *testing.T) {
			s, scope, session := sessionFixture(t)
			proof := api.VerifiedHumanProof{Config: s.deps.Config, PrincipalID: scope.Actor.ID, CredentialID: session.CredentialID, Ref: api.ProofRef{ID: testID(t)}}
			if _, err := s.proofCredential(context.Background(), s.db, proof); err != nil {
				t.Fatal("proof presence positive control failed", err)
			}
			if fault == "foreign_enrollment" || fault == "revoked_credential" {
				var enrollment api.HumanEnrollment
				if err := storedProjection(context.Background(), s.db, "enrollment", scope.Actor.ID, &enrollment); err != nil {
					t.Fatal(err)
				}
				if fault == "foreign_enrollment" {
					enrollment.Config = "other-config"
				} else {
					enrollment.Credentials[0].Revoked = true
				}
				fixtureProjection(t, s, "enrollment", enrollment.PrincipalID, 1, enrollment)
			} else if fault == "credential_mark" {
				proof.SimulatedPresence = true
				proof.Ref.SimulatedPresence = true
			} else {
				proof.Ref.SimulatedPresence = true
			}
			if _, err := s.proofCredential(context.Background(), s.db, proof); err == nil {
				t.Fatal("proof accepted changed " + fault)
			}
		})
	}
}
