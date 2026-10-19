package api

import "context"

// WithReadAuthority is called by transport/dispatch before reserving a human
// staging/preview request, outside the store write lock. ReadAuthority must
// check current connection/session lifetime, expiry and revocation. The store
// rechecks these retained session facts under commit without a callback into
// transport while holding its lock. No public body supplies this Scope field.
func WithReadAuthority(ctx context.Context, scope Scope) (Scope, error) {
	if scope.Actor.Kind != "human" || scope.Connection == nil {
		return Scope{}, &Error{Code: CodeForbidden, Message: "verified human connection required", Instead: "Establish human.session on the installed human endpoint."}
	}
	authority, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return Scope{}, err
	}
	scope.ReadAuthority = &authority
	if !boundReadAuthority(scope) {
		return Scope{}, &Error{Code: CodeForbidden, Message: "human read authority belongs to another connection or scope", Instead: "Establish a current session for this principal, configuration and endpoint."}
	}
	return scope, nil
}

// This is structural binding only. Current session/credential revocation and
// expiry remain mandatory dispatcher/store checks, including before replay.
func boundReadAuthority(scope Scope) bool {
	if scope.Actor.Kind != "human" || scope.Actor.ID == "" || scope.Config == "" || scope.Connection == nil || scope.ReadAuthority == nil {
		return false
	}
	binding, authority := scope.Connection.Binding(), scope.ReadAuthority
	return binding.Class == EndpointHuman && binding.Config == scope.Config &&
		binding.EndpointGeneration == scope.EndpointGeneration && scope.EndpointGeneration != 0 &&
		authority.ConnectionID != "" && authority.ConnectionID == scope.Connection.ID() &&
		authority.SessionID != "" && authority.CredentialID != "" && authority.PrincipalID == scope.Actor.ID &&
		authority.Config == scope.Config && authority.EndpointGeneration == scope.EndpointGeneration &&
		authority.IdleExpiresAt != "" && authority.ExpiresAt != ""
}
