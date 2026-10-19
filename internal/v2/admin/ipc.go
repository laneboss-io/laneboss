package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Each caller covers its callee's work, refusal write and one hop of slack.
// The service work budget stays ten seconds; ceremony expiry is independent.
const (
	helperReplyTimeout       = time.Second
	enrollmentWorkTimeout    = 10 * time.Second
	serviceCallBudget        = enrollmentWorkTimeout + helperReplyTimeout
	enrollmentForwardTimeout = enrollmentWorkTimeout + 2*helperReplyTimeout
	helperWorkTimeout        = enrollmentForwardTimeout + helperReplyTimeout
	helperCallTimeout        = helperWorkTimeout + 2*helperReplyTimeout
)

// Work expiry leaves the caller-facing socket open for its reserved reply.
// The transport's hard bound and parent cancellation still close it. The
// durations are private composition inputs, never caller-selectable fields.
type helperWindow struct {
	work       context.Context
	transport  context.Context
	connection net.Conn
	replyLimit time.Duration
	finish     func()
}

func openHelperWindow(parent context.Context, connection net.Conn, workLimit, replyLimit time.Duration) (*helperWindow, error) {
	transport, cancelTransport := context.WithTimeout(parent, workLimit+replyLimit)
	transportDeadline, _ := transport.Deadline()
	work, cancelWork := context.WithDeadline(transport, transportDeadline.Add(-replyLimit))
	stop := context.AfterFunc(transport, func() { connection.Close() })
	w := &helperWindow{work: work, transport: transport, connection: connection, replyLimit: replyLimit}
	w.finish = func() {
		stop()
		cancelWork()
		cancelTransport()
	}
	deadline, _ := work.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		w.finish()
		return nil, failure(api.CodeUnavailable, "cannot bound helper request transport")
	}
	return w, nil
}

func (w *helperWindow) write(response helperResponse) error {
	deadline := time.Now().Add(w.replyLimit)
	if hard, ok := w.transport.Deadline(); ok && hard.Before(deadline) {
		deadline = hard
	}
	if err := w.connection.SetWriteDeadline(deadline); err != nil {
		return api.WithHelperReason(helperWriteFailure(response, failure(api.CodeUnavailable, "cannot bound helper reply transport")), "reply_transport")
	}
	if err := writeFrame(w.connection, response); err != nil {
		return api.WithHelperReason(helperWriteFailure(response, err), "reply_transport")
	}
	return nil
}

func (w *helperWindow) refuse(protocol string, nonce api.ID, err error) error {
	var typed *api.Error
	if !errors.As(err, &typed) {
		typed = failure(api.CodeIntegrity, "internal helper operation failed")
	} else if typed.Owner == "" {
		owned := *typed
		owned.Owner = owner
		typed = &owned
	}
	reason := api.HelperReason(err)
	wireReason := ""
	if protocol == helperProtocol {
		wireReason = reason
	}
	if err := w.write(helperResponse{Protocol: protocol, Revision: api.ContractRevision, Nonce: nonce, Error: typed, Reason: wireReason}); err != nil {
		return err
	}
	return api.WithHelperReason(typed, reason)
}

func helperWriteFailure(response helperResponse, err error) error {
	refusal := response.Error
	if refusal == nil && !errors.As(err, &refusal) {
		refusal = failure(api.CodeUnavailable, "helper reply transport failed")
	}
	if diagnosticErr := json.NewEncoder(os.Stderr).Encode(helperReplyDiagnostic(refusal, err)); diagnosticErr != nil {
		return failure(api.CodeUnavailable, "cannot retain helper reply diagnostic")
	}
	return err
}

// These fields describe the refusal that could not be delivered. No message,
// nonce, configuration, native error or caller-controlled owner is logged.
func helperReplyDiagnostic(refusal *api.Error, transport ...error) any {
	code := refusal.Code
	switch code {
	case api.CodeNotImplemented, api.CodeInvalid, api.CodeUnauthenticated, api.CodeForbidden,
		api.CodeNotFound, api.CodeConflict, api.CodeIdempotencyConflict, api.CodeVersion,
		api.CodeUnavailable, api.CodePrerequisite, api.CodeUnsupported, api.CodeIntegrity,
		api.CodeBudget, api.CodeUnscored, api.CodeCursorExpired, api.CodeContainmentUnknown,
		api.CodeCancelled, api.CodeDeadline, CodeArchiveLiveWriter, CodeCleanupUnmerged:
	default:
		code = api.CodeIntegrity
	}
	refusalOwner := refusal.Owner
	switch refusalOwner {
	case owner, "lb-v2-service", "lb-v2-identity", "lb-v2-policy", "lb-v2-templates", "lb-v2-grants":
	default:
		refusalOwner = owner
	}
	frame, reason := api.JSONFailureFacts(refusal)
	if len(transport) != 0 {
		if actualFrame, actualReason := api.JSONFailureFacts(transport[0]); actualFrame != "" {
			frame, reason = actualFrame, actualReason
		}
	}
	return struct {
		Stage  string            `json:"stage"`
		Code   api.ErrorCode     `json:"code"`
		Owner  string            `json:"owner"`
		Frame  api.JSONFrameKind `json:"frame,omitempty"`
		Reason string            `json:"reason,omitempty"`
	}{"response_write", code, refusalOwner, frame, reason}
}

// A forwarding hop reserves time for its caller to finish and reply, even
// when the caller was itself shortened by an earlier parent deadline.
func helperForwardContext(parent context.Context) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(enrollmentForwardTimeout)
	if outer, ok := parent.Deadline(); ok {
		reserved := outer.Add(-helperReplyTimeout)
		if reserved.Before(deadline) {
			deadline = reserved
		}
	}
	return context.WithDeadline(parent, deadline)
}

func helperServiceBudget(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= serviceCallBudget {
		return failure(api.CodeDeadline, "administrator relay lacks a complete service reply budget")
	}
	return nil
}
