package store

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Called with the store read lock and a verified native human connection.
// Selecting a credential supplies staging only: it cannot create a session,
// consume a proof, return content, or select an unapproved/revoked key.
func (s *Service) selectedHuman(ctx context.Context, scope api.Scope) (api.HumanEnrollment, bool, error) {
	var empty api.HumanEnrollment
	var principal, credential api.ID
	if a, err := scope.Connection.ReadAuthority(ctx); err == nil {
		if a.Config != scope.Config || a.ConnectionID != scope.Connection.ID() || a.EndpointGeneration != scope.EndpointGeneration {
			return empty, false, fault(api.CodeUnauthenticated, "human selection has foreign read authority")
		}
		principal, credential = a.PrincipalID, a.CredentialID
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeUnauthenticated {
			return empty, false, err
		}
	}
	var selected api.ID
	staged := false
	frame := api.HumanEntryFrame(ctx)
	if source, ok := scope.Connection.(api.HumanStagingSource); ok {
		bound, err := source.HumanStaging(ctx)
		if err == nil {
			if !wire.ValidID(string(bound.PrincipalID)) || bound.Frame == nil || principal != "" && principal != bound.PrincipalID {
				return empty, false, fault(api.CodeUnauthenticated, "human staging differs from the authenticated principal")
			}
			frame, selected, principal = bound.Frame, bound.CredentialID, bound.PrincipalID
			staged = true
		} else {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
				return empty, false, err
			}
		}
	}
	if frame != nil {
		if err := frame.Verify(ctx, scope.Connection); err != nil {
			return empty, false, err
		}
		if selected == "" && !staged {
			selected = api.HumanEntryCredential(ctx)
		}
		if selected == "" && !staged {
			request, err := wire.DecodeRequest(frame.Bytes())
			if err != nil {
				return empty, false, err
			}
			if request.Config != scope.Config {
				return empty, false, fault(api.CodeForbidden, "human selection belongs to another configuration")
			}
			switch request.Method {
			case "human.challenge":
				var input api.HumanChallengeRequest
				if err := wire.Decode(request.Params, &input); err != nil {
					return empty, false, err
				}
				selected = input.CredentialID
			case "human.confirm":
				var input api.HumanConfirmRequest
				if err := wire.Decode(request.Params, &input); err != nil {
					return empty, false, err
				}
				selected = input.CredentialID
			}
			if request.Proof != nil {
				var proof api.VerifiedHumanProof
				if err := storedProjection(ctx, s.db, "proof", request.Proof.ID, &proof); err != nil {
					return empty, false, err
				}
				if proof.Config != scope.Config || proof.Ref != *request.Proof || proof.Target.Method != request.Method || proof.Target.RequestSHA256 != request.RequestSHA256 ||
					principal != "" && principal != proof.PrincipalID {
					return empty, false, fault(api.CodeUnauthenticated, "human selection proof belongs to another principal or operation")
				}
				principal, selected = proof.PrincipalID, proof.CredentialID
			}
		}
	}
	if selected != "" {
		if credential != "" && credential != selected {
			return empty, false, fault(api.CodeUnauthenticated, "human credential differs from this connection's session")
		}
		credential = selected
	}
	if principal == "" && credential == "" {
		return empty, false, nil
	}
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='enrollment'")
	if err != nil {
		return empty, false, err
	}
	defer rows.Close()
	var result api.HumanEnrollment
	matches := 0
	for rows.Next() {
		var raw []byte
		var e api.HumanEnrollment
		if err := rows.Scan(&raw); err != nil {
			return empty, false, err
		}
		if err := decodeStored(raw, &e); err != nil {
			return empty, false, err
		}
		if e.Config != scope.Config || principal != "" && principal != e.PrincipalID {
			continue
		}
		for _, c := range e.Credentials {
			if !c.Revoked && (credential == "" || c.ID == credential) {
				matches++
				result = e
				if credential == "" {
					break
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return empty, false, err
	}
	if matches != 1 {
		return empty, false, fault(api.CodeUnauthenticated, "selected human credential is absent, pending, revoked or ambiguous")
	}
	if err := validateEnrollment(result); err != nil {
		return empty, false, err
	}
	return result, true, nil
}
