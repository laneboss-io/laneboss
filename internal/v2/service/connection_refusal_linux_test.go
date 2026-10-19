//go:build linux

package service

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type privateCauseAuthenticator struct {
	*refusingHealthAuth
	cause *api.Error
}

func (a *privateCauseAuthenticator) Authenticate(_ context.Context, connection api.ConnectionContext) (api.Scope, error) {
	a.authentications.Add(1)
	return api.Scope{}, errors.Join(a.cause, connection.Close())
}

// Exercise the production native framing and refusal writer. Every cause
// string carries a fresh harmless canary, so moving detail to another response
// field cannot satisfy the assertion by hiding only the message.
func TestAuthenticationRefusalPrivacy(t *testing.T) {
	h := newPublicHealthHarness(t, true)
	canary := fixtureID(t)
	cause := &api.Error{Code: api.CodeUnauthenticated, Owner: "lb-v2-identity",
		Message: string(canary), Instead: string(canary), OperationID: canary, Retryable: true}
	h.server.deps.Authenticator = &privateCauseAuthenticator{refusingHealthAuth: h.auth, cause: cause}
	client, done := h.connect(t)
	request := requestFor(t, "identity.self", api.Empty{})
	if err := wire.WriteFrame(client, publicFrame(t, request)); err != nil {
		t.Fatal("authentication refusal request did not reach the native socket", err)
	}
	data, err := wire.ReadFrame(client)
	if err != nil {
		t.Fatal("authentication refusal did not return its correlated frame", err)
	}
	if bytes.Contains(data, []byte(canary)) {
		t.Fatal("authentication refusal disclosed internal cause")
	}
	response, err := wire.DecodeResponse(data, request)
	if err != nil || response.Error == nil || response.Error.Code != cause.Code || response.Error.Owner != cause.Owner ||
		response.Error.Message != "service connection refused at authentication" || response.Error.Instead != "" ||
		response.Error.OperationID != "" || response.Error.Retryable || len(response.Result) != 0 || response.LastSeq != 0 {
		t.Fatal("authentication refusal lost its fixed public verdict", err)
	}
	waitHealthClosed(t, client, done)
	if h.auth.authentications.Load() != 1 || h.auth.authorizations.Load() != 0 || h.dispatched.Load() != 0 ||
		h.state.snapshots.Load() != 0 || h.state.forbidden.Load() != 0 {
		t.Fatal("authentication refusal reached authority or state")
	}
	if cause.Message != string(canary) || cause.Instead != string(canary) || cause.OperationID != canary || !cause.Retryable {
		t.Fatal("public refusal mutated the private cause")
	}
}
