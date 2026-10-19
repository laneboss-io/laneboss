package store

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) identityWrites(ctx context.Context, tx *sql.Tx, input api.Transaction, kind string) error {
	scope := input.Scope
	if scope.Actor.Kind != "human" || scope.Connection == nil || scope.Connection.Binding().Class != api.EndpointHuman {
		return fault(api.CodeForbidden, "identity write requires its authenticated human endpoint")
	}
	var enrollment api.HumanEnrollment
	if err := storedProjection(ctx, tx, "enrollment", scope.Actor.ID, &enrollment); err != nil {
		return err
	}
	if enrollment.Config != s.deps.Config || enrollment.PrincipalID != scope.Actor.ID {
		return fault(api.CodeForbidden, "enrollment provenance differs from caller")
	}
	switch kind {
	case "Challenges":
		for _, challenge := range input.Writes.Challenges {
			if challenge.PrincipalID != scope.Actor.ID || challenge.EndpointClass != api.EndpointHuman || challenge.EndpointGeneration != scope.EndpointGeneration ||
				challenge.Challenge.Config != s.deps.Config || challenge.Challenge.Origin != enrollment.Origin || challenge.Challenge.RPID != enrollment.RPID || len(challenge.Challenge.Challenge) < 32 || !future(challenge.Challenge.ExpiresAt, s.deps.Clock.Now()) {
				return fault(api.CodeForbidden, "challenge differs from pinned enrollment")
			}
			var prior api.StoredChallenge
			err := storedProjection(ctx, tx, "challenge", challenge.Challenge.ID, &prior)
			if err == nil {
				if scope.Request.Method != "human.confirm" || prior.Consumed || !challenge.Consumed || challenge.Generation != prior.Generation+1 {
					return fault(api.CodeConflict, "challenge already consumed or generation changed")
				}
				copy := challenge
				copy.Consumed, copy.Generation = prior.Consumed, prior.Generation
				if !sameValue(copy, prior) {
					return fault(api.CodeForbidden, "challenge confirmation changed immutable facts")
				}
			} else {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
					return err
				}
				if scope.Request.Method != "human.challenge" || challenge.Consumed || challenge.Generation != 1 || challenge.ConnectionID != scope.Connection.ID() {
					return fault(api.CodeForbidden, "new challenge lacks current connection")
				}
			}
			if err := put(ctx, tx, "challenge", challenge.Challenge.ID, challenge.Generation, challenge); err != nil {
				return err
			}
		}
	case "Proofs":
		for _, proof := range input.Writes.Proofs {
			var challenge api.StoredChallenge
			if err := storedProjection(ctx, tx, "challenge", proof.NonceID, &challenge); err != nil {
				return err
			}
			target := api.HumanChallengeRequest{Method: challenge.Challenge.Method, TargetID: challenge.Challenge.TargetID, RequestSHA256: challenge.Challenge.RequestSHA256, BaseGeneration: challenge.Challenge.BaseGeneration}
			if scope.Request.Method != "human.confirm" || proof.PrincipalID != scope.Actor.ID || proof.Config != scope.Config || proof.EndpointClass != api.EndpointHuman ||
				proof.EndpointGeneration != scope.EndpointGeneration || proof.Target != target || proof.Ref.RequestSHA256 != target.RequestSHA256 || !challenge.Consumed || proof.ConsumedBy != "" || !future(proof.Ref.ExpiresAt, s.deps.Clock.Now()) {
				return fault(api.CodeForbidden, "verified proof differs from consumed challenge")
			}
			var count int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='proof' AND (id=? OR json_extract(data,'$.NonceID')=?)", string(proof.Ref.ID), string(proof.NonceID)).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				return fault(api.CodeConflict, "challenge already has its proof")
			}
			credential := false
			for _, key := range enrollment.Credentials {
				credential = credential || key.ID == proof.CredentialID && !key.Revoked
			}
			if !credential {
				return fault(api.CodeForbidden, "proof credential is absent or revoked")
			}
			if _, err := s.proofCredential(ctx, tx, proof); err != nil {
				return err
			}
			proof.VerifiedAt = api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
			if err := put(ctx, tx, "proof", proof.Ref.ID, 1, proof); err != nil {
				return err
			}
		}
	case "ReadSessions":
		for _, session := range input.Writes.ReadSessions {
			if scope.Request.Method != "human.session" || session.PrincipalID != scope.Actor.ID || session.ConnectionID != scope.Connection.ID() || session.EndpointGeneration != scope.EndpointGeneration || session.Revoked || session.Generation != 1 || session.Session.Config != scope.Config {
				return fault(api.CodeForbidden, "read session does not belong to current human connection")
			}
			end, err := time.Parse(time.RFC3339Nano, string(session.Session.ExpiresAt))
			if err != nil || !end.After(s.deps.Clock.Now()) || end.After(s.deps.Clock.Now().Add(30*time.Minute)) {
				return wire.Invalid("read session absolute expiry exceeds bound")
			}
			idle, err := time.Parse(time.RFC3339Nano, string(session.Session.IdleExpiresAt))
			if err != nil || !idle.After(s.deps.Clock.Now()) || idle.After(end) || idle.After(s.deps.Clock.Now().Add(5*time.Minute)) {
				return wire.Invalid("read session idle expiry exceeds bound")
			}
			if err := put(ctx, tx, "read_session", session.Session.ID, session.Generation, session); err != nil {
				return err
			}
		}
	case "Tickets":
		for _, ticket := range input.Writes.Tickets {
			if scope.Request.Method != "ticket.issue" || ticket.Level < 3 || ticket.Level > 6 || ticket.Role == "" || ticket.Redeemed || !future(ticket.ExpiresAt, s.deps.Clock.Now()) {
				return wire.Invalid("invalid root ticket")
			}
			value := reflect.ValueOf(&ticket).Elem()
			for name, expected := range map[string]any{"PrincipalID": scope.Actor.ID, "Config": scope.Config, "EndpointGeneration": scope.EndpointGeneration} {
				field := value.FieldByName(name)
				if field.IsValid() {
					if field.Interface() != expected {
						return fault(api.CodeForbidden, "ticket write carries foreign provenance")
					}
				}
			}
			retained := ticketRecord{PrincipalID: scope.Actor.ID, Config: scope.Config, EndpointGeneration: scope.EndpointGeneration, Ticket: ticket}
			if err := put(ctx, tx, "ticket", ticket.ID, 1, retained); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) counterWrites(ctx context.Context, tx *sql.Tx, input api.Transaction) error {
	for _, change := range input.Writes.Counters {
		if input.Scope.Actor.Kind != "human" || input.Scope.Request.Method != "human.confirm" {
			return fault(api.CodeForbidden, "counter update requires verified confirmation")
		}
		var enrollment api.HumanEnrollment
		if err := storedProjection(ctx, tx, "enrollment", input.Scope.Actor.ID, &enrollment); err != nil {
			return err
		}
		found := false
		for index := range enrollment.Credentials {
			credential := &enrollment.Credentials[index]
			if credential.ID != change.CredentialID {
				continue
			}
			found = true
			if credential.Revoked || credential.Generation != change.ExpectedGeneration || credential.Counter != change.Before || change.After <= change.Before && (change.After != 0 || change.Before != 0) {
				return fault(api.CodeConflict, "credential signature counter changed or regressed")
			}
			credential.Counter, credential.Generation = change.After, credential.Generation+1
		}
		if !found {
			return fault(api.CodeNotFound, "credential is not enrolled")
		}
		if err := put(ctx, tx, "enrollment", enrollment.PrincipalID, enrollment.Generation, enrollment); err != nil {
			return err
		}
	}
	return nil
}
