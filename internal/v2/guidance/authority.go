package guidance

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func forbidden(message string) *api.Error {
	return &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-guidance", Message: message,
		Instead: "Use the authenticated own-life scope or a current bound human read session."}
}

// authorizeTarget implements the catalog's self access before any object read.
// Scope.Source and caller-supplied role/target labels confer no authority.
func authorizeTarget(ctx context.Context, scope api.Scope, target api.LifeRef) (api.Scope, error) {
	if scope.Config == "" || !validID(scope.Actor.ID) {
		return api.Scope{}, &api.Error{Code: api.CodeUnauthenticated, Owner: "lb-v2-guidance",
			Message: "guidance requires an authenticated configuration scope",
			Instead: "Use the installed, authenticated service endpoint."}
	}
	if scope.Request.Method != "" && (scope.Request.Method != "guidance.select" ||
		scope.Request.Config != "" && scope.Request.Config != scope.Config) {
		return api.Scope{}, forbidden("guidance scope carries a different method or configuration")
	}
	if scope.Request.Proof != nil {
		return api.Scope{}, forbidden("guidance preview does not consume an operation proof")
	}
	switch scope.Actor.Kind {
	case "lane":
		if !validID(scope.Actor.LifeID) || scope.Actor.LifeID != target.LifeID || scope.ReadAuthority != nil {
			return api.Scope{}, forbidden("guidance target must be the authenticated lane's own life")
		}
		if scope.Connection != nil {
			binding := scope.Connection.Binding()
			if binding.Class != api.EndpointLane || binding.Config != scope.Config || binding.Target == nil || *binding.Target != target {
				return api.Scope{}, forbidden("guidance target differs from its authenticated run binding")
			}
		}
	case "human":
		if scope.Connection == nil {
			return api.Scope{}, forbidden("human guidance requires a current read connection")
		}
		if authority := scope.ReadAuthority; authority != nil &&
			(authority.ConnectionID != scope.Connection.ID() || authority.PrincipalID != scope.Actor.ID ||
				authority.Config != scope.Config || authority.EndpointGeneration != scope.EndpointGeneration) {
			return api.Scope{}, forbidden("human guidance read authority is bound to another connection or scope")
		}
		resolved, err := api.WithReadAuthority(ctx, scope)
		if err != nil {
			return api.Scope{}, err
		}
		if scope.ReadAuthority != nil && (scope.ReadAuthority.SessionID != resolved.ReadAuthority.SessionID ||
			scope.ReadAuthority.CredentialID != resolved.ReadAuthority.CredentialID) {
			return api.Scope{}, forbidden("human guidance read authority differs from the live session")
		}
		scope = resolved
	default:
		return api.Scope{}, forbidden("guidance self access requires a lane or verified human")
	}
	return scope, nil
}

func authorizeJudge(ctx context.Context, scope api.Scope, request api.JudgeRequest) (api.Scope, error) {
	if request.Context.Config != scope.Config {
		return api.Scope{}, forbidden("guidance judge context differs from the authenticated configuration")
	}
	return authorizeTarget(ctx, scope, request.Context.Target)
}
