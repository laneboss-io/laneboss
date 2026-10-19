package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type connectionEntryFailure struct {
	stage string
	cause error
}

// Correlate native authentication latency without logging peer facts or input.
func (s *Server) journalAuthenticationStart(ctx context.Context, connection api.ConnectionContext, request api.ID) {
	var connectionID api.ID
	if connection != nil {
		connectionID = connection.ID()
	}
	var budget int64
	if deadline, ok := ctx.Deadline(); ok {
		budget = time.Until(deadline).Milliseconds()
	}
	data, err := json.Marshal(struct {
		Event         string `json:"event"`
		RequestID     api.ID `json:"request_id"`
		ConnectionID  api.ID `json:"connection_id"`
		StartedUnixMS int64  `json:"started_unix_ms"`
		BudgetMS      int64  `json:"budget_ms"`
	}{"authentication_start", request, connectionID, time.Now().UnixMilli(), budget})
	if err == nil {
		_, _ = os.Stderr.Write(append(data, '\n'))
	}
}

func (e *connectionEntryFailure) Error() string {
	return "service connection entry refused at " + e.stage
}
func (e *connectionEntryFailure) Unwrap() error { return e.cause }

// Bound connections revalidate current authority without acquiring a new peer.
type connectionScopeSource interface {
	CurrentConnectionScope(context.Context, api.ConnectionContext) (api.Scope, error)
}

type authenticationConnection struct {
	api.ConnectionContext
	closeRequested atomic.Bool
}

func (c *authenticationConnection) Close() error {
	c.closeRequested.Store(true)
	return c.ConnectionContext.Close()
}

type authenticationReplyKey struct{}

// Only a socket dispatcher creates this window and owns the deferred physical
// close after its single bounded refusal. Direct ingress has no such window.
type authenticationReplyWindow struct {
	api.ConnectionContext
	closeRequested atomic.Bool
}

func (w *authenticationReplyWindow) Close() error {
	w.closeRequested.Store(true)
	return nil
}

func (s *Server) authenticateConnection(ctx context.Context, connection api.ConnectionContext) (api.Scope, error) {
	if connection == nil {
		return s.deps.Authenticator.Authenticate(ctx, connection)
	}
	entry := &authenticationConnection{ConnectionContext: connection}
	if window, ok := ctx.Value(authenticationReplyKey{}).(*authenticationReplyWindow); ok && window.ConnectionContext == connection {
		entry.ConnectionContext = window
	}
	var scope api.Scope
	var err error
	if connection.Peer() != nil {
		source, ok := s.deps.Authenticator.(connectionScopeSource)
		if !ok {
			err = errors.Join(serviceError(api.CodePrerequisite, "bound connection requires current-scope revalidation"), entry.Close())
		} else {
			scope, err = source.CurrentConnectionScope(ctx, entry)
		}
	} else {
		scope, err = s.deps.Authenticator.Authenticate(ctx, entry)
	}
	if err != nil {
		return api.Scope{}, &connectionEntryFailure{stage: "authentication", cause: err}
	}
	if entry.closeRequested.Load() {
		return api.Scope{}, &connectionEntryFailure{stage: "authentication", cause: serviceError(api.CodeIntegrity, "authentication requested closure without a refusal")}
	}
	if scope.Connection != nil && scope.Connection != entry && scope.Connection != connection {
		return api.Scope{}, &connectionEntryFailure{stage: "authentication", cause: serviceError(api.CodeIntegrity, "authentication returned another connection")}
	}
	scope.Connection = connection
	return scope, nil
}

func connectionRefusal(stage string, err error) *api.Error {
	cause := typedError(err)
	// The peer has not established authority. Copy only the typed verdict;
	// neither the message nor any other cause field belongs on this wire.
	return &api.Error{Code: cause.Code, Owner: cause.Owner,
		Message: "service connection refused at " + stage}
}

// The service's private journal retains the typed cause, separately from the
// fixed public refusal. Do not pass the public response back as this cause.
func (s *Server) journalConnection(stage string, refusal *api.Error) {
	switch stage {
	case "connection", "peer_credentials", "frame", "deadline", "authentication", "admission", "response_write":
	default:
		stage = "connection"
	}
	data, err := json.Marshal(struct {
		Code    api.ErrorCode `json:"code"`
		Owner   string        `json:"owner"`
		Stage   string        `json:"stage"`
		Message string        `json:"message"`
	}{refusal.Code, refusal.Owner, stage, refusal.Message})
	if err == nil {
		data = append(data, '\n')
		var count int
		count, err = os.Stderr.Write(data)
		if err == nil && count != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		s.recordFault(serviceError(api.CodeIntegrity, "service connection journal failed"))
	}
}
