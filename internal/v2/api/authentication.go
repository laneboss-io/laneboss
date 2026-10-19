package api

import "context"

// HumanPolicySource is a private identity bootstrap read. It returns only the
// current generation for an already verified native human connection and its
// retained principal. It grants no session, proof or public object read.
type HumanPolicySource interface {
	HumanPolicyGeneration(context.Context, ConnectionContext, ID) (Generation, error)
}

// ConnectionScopeSource rechecks an existing pinned peer without acquiring or
// rebinding it. Authenticate remains the one-time native peer entry.
type ConnectionScopeSource interface {
	CurrentConnectionScope(context.Context, ConnectionContext) (Scope, error)
}
