package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// This private channel carries fixed enrollment and initial publication forms. It
// never enters the public method catalog or accepts a serialized Scope/Intent.
type enrollmentFrame = api.AdminEnrollmentFrame
type enrollmentResponse = api.AdminEnrollmentReply

func (s *Server) startEnrollment(ctx context.Context) (func() error, error) {
	if s.options.AdminEnrollment == nil {
		return func() error { return nil }, nil
	}
	e := *s.options.AdminEnrollment
	if err := api.ValidateAdminEnrollmentEndpoint(e); err != nil {
		return nil, err
	}
	if e.Config != s.options.Config || e.ServiceUID != s.deps.Binding.ServiceUID || e.InstallationGeneration != s.deps.Binding.InstallationGeneration || e.Socket == s.deps.Binding.Socket {
		return nil, serviceError(api.CodeForbidden, "administrator endpoint differs from the installed service")
	}
	if err := runtimeDirectory(filepath.Dir(e.Socket), e.ServiceUID); err != nil {
		return nil, err
	}
	binding := s.deps.Binding
	binding.Socket = e.Socket
	binding.Class = api.EndpointHuman
	binding.LaunchID = ""
	binding.Target = nil
	binding.WorkerLeaseID = ""
	listener, err := listenAdministrator(ctx, binding)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(e.Socket)
	if err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	s.mu.Lock()
	s.workers.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.workers.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
					s.recordFault(err)
				}
				return
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				s.writeEnrollmentReply(connection, enrollmentResponse{Protocol: api.AdminEnrollmentProtocol, Revision: api.ContractRevision},
					"connection", serviceError(api.CodeUnavailable, "administrator enrollment is stopping"))
				connection.Close()
				return
			}
			s.workers.Add(1)
			s.mu.Unlock()
			go func() { defer s.workers.Done(); defer connection.Close(); s.serveEnrollment(ctx, connection, binding) }()
		}
	}()
	return func() error {
		stop()
		err := listener.Close()
		if errors.Is(err, net.ErrClosed) {
			err = nil
		}
		current, statErr := os.Lstat(e.Socket)
		if statErr == nil && os.SameFile(info, current) {
			err = errors.Join(err, os.Remove(e.Socket))
		}
		return err
	}, nil
}

func (s *Server) serveEnrollment(parent context.Context, connection net.Conn, binding api.InstalledBinding) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	// Request expiry cancels work, while the bounded refusal writer still owns
	// its existing one-second reply window. Transport has its own hard bound,
	// and parent shutdown must continue to close it immediately.
	transport, cancelTransport := context.WithTimeout(parent, 11*time.Second)
	defer cancelTransport()
	stopClose := context.AfterFunc(transport, func() { connection.Close() })
	defer stopClose()
	response := enrollmentResponse{Protocol: api.AdminEnrollmentProtocol, Revision: api.ContractRevision}
	field := "deadline"
	var peer api.VerifiedPeer
	var lifetime *connectionContext
	defer func() {
		if lifetime != nil {
			s.closeResource(lifetime)
		} else if peer != nil {
			s.closeResource(peer)
		}
	}()
	err := func() error {
		if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		field = "connection"
		socket, ok := connection.(*net.UnixConn)
		if !ok {
			return serviceError(api.CodeInvalid, "administrator enrollment requires a Unix endpoint")
		}
		field = "peer_credentials"
		credentials, err := wire.PeerCredentials(socket)
		if err != nil {
			return err
		}
		field = "frame"
		frame, err := wire.ReadPinnedFrame(socket, credentials)
		if err != nil {
			return err
		}
		response.Nonce = wire.AdminEnrollmentNonce(frame.Bytes())
		var input enrollmentFrame
		if err := wire.DecodeAdminEnrollmentFrame(frame.Bytes(), &input); err != nil {
			return err
		}
		field = "admin_enrollment"
		if s.options.AdminEnrollment == nil {
			return api.NotImplemented("lb-v2-admin", "protected administrator enrollment endpoint")
		}
		if err := api.ValidateAdminEnrollmentFrame(input, *s.options.AdminEnrollment); err != nil {
			return err
		}
		// Parsing a diagnostic nonce grants no authority. The actual connector,
		// writer, lifetime and executing artifact must pass before any handler.
		field = "peer_lifetime"
		peer, err = wire.NewAdministratorPeer(ctx, socket)
		if err != nil {
			return err
		}
		field = "connection"
		lifetime, err = newConnection(socket, binding, s.deps.Clock)
		if err != nil {
			return err
		}
		field = "peer_lifetime"
		if err := lifetime.BindPeer(peer); err != nil {
			s.closeResource(peer)
			peer = nil
			return err
		}
		call := &administratorCall{Context: ctx, scope: api.Scope{Config: s.options.Config, Actor: api.Actor{Kind: "service", ID: s.controller}, Connection: lifetime, Frame: frame, Source: "worker"}}
		field = "scope"
		if _, err := s.administratorScope(call); err != nil {
			return err
		}
		field = input.Method
		result, err := s.enrollmentResult(call, input)
		if err != nil {
			return err
		}
		field = "scope"
		if _, err := s.administratorScope(call); err != nil {
			return err
		}
		field = "response"
		response.Result, err = json.Marshal(result)
		return err
	}()
	s.writeEnrollmentReply(connection, response, field, err)
}

func (s *Server) enrollmentResult(call *administratorCall, input enrollmentFrame) (any, error) {
	switch input.Method {
	case "spend_reconcile":
		var reading api.SpendReading
		if err := wire.Decode(input.Params, &reading); err != nil {
			return nil, api.AdminEnrollmentFailure("params", err)
		}
		return s.ReconcileSpendFrame(call, *s.options.AdminEnrollment, call.scope, reading)
	case "initial_publish":
		var request admin.InitialRequest
		if err := wire.Decode(input.Params, &request); err != nil {
			return nil, api.AdminEnrollmentFailure("params", err)
		}
		return s.PublishInitialFrame(call, *s.options.AdminEnrollment, call.scope, request)
	case "enroll_begin":
		var request api.EnrollmentCeremonyRequest
		if err := wire.Decode(input.Params, &request); err != nil {
			return nil, api.AdminEnrollmentFailure("params", err)
		}
		return s.BeginHumanEnrollment(call, request)
	case "enroll_complete":
		var request api.EnrollmentValidationRequest
		if err := wire.Decode(input.Params, &request); err != nil {
			return nil, api.AdminEnrollmentFailure("params", err)
		}
		return s.CompleteHumanEnrollment(call, request)
	default:
		return nil, api.AdminEnrollmentFailure("method", serviceError(api.CodeForbidden, "administrator enrollment method refused"))
	}
}

func enrollmentError(field string, err error) *api.Error {
	var typed *api.Error
	if errors.As(err, &typed) {
		copy := *typed
		if copy.Owner == "" {
			copy.Owner = "lb-v2-admin"
		}
		copy.Message = "administrator enrollment refused at " + field + ": " + copy.Message
		return &copy
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		refusal := contextError(err)
		refusal.Message = "administrator enrollment refused at " + field + ": " + refusal.Message
		return refusal
	}
	code, message := api.CodeIntegrity, "administrator enrollment native check failed at "+field
	var timeout net.Error
	if errors.Is(err, os.ErrPermission) {
		code, message = api.CodePrerequisite, "administrator enrollment native access denied at "+field
	} else if errors.Is(err, os.ErrNotExist) {
		code, message = api.CodePrerequisite, "administrator enrollment prerequisite is missing at "+field
	} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		code, message = api.CodeInvalid, "administrator enrollment frame is incomplete at "+field
	} else if errors.As(err, &timeout) && timeout.Timeout() {
		code, message = api.CodeDeadline, "administrator enrollment timed out at "+field
	}
	return &api.Error{Code: code, Owner: "lb-v2-admin", Message: message,
		Instead: "Retain the private channel evidence and repair the named installed prerequisite; keep its integrity checks."}
}

func enrollmentJournal(field string, refusal *api.Error) ([]byte, error) {
	return json.Marshal(struct {
		Code    api.ErrorCode `json:"code"`
		Owner   string        `json:"owner"`
		Field   string        `json:"field"`
		Message string        `json:"message"`
	}{refusal.Code, refusal.Owner, field, "administrator enrollment refused"})
}

func (s *Server) journalEnrollment(field string, refusal *api.Error) {
	data, err := enrollmentJournal(field, refusal)
	if err == nil {
		data = append(data, '\n')
		var count int
		count, err = os.Stderr.Write(data)
		if err == nil && count != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		s.recordFault(serviceError(api.CodeIntegrity, "administrator enrollment journal write failed"))
	}
}

func (s *Server) writeEnrollmentReply(connection net.Conn, response enrollmentResponse, field string, err error) {
	if err != nil {
		if failed := api.AdminEnrollmentFailedField(err); failed != "" {
			field = failed
		}
		field = api.AdminEnrollmentFailedField(api.AdminEnrollmentFailure(field, err))
		response.Result = nil
		response.FailureField = field
		response.Error = enrollmentError(field, err)
		s.journalEnrollment(field, response.Error)
	}
	data, encodeErr := json.Marshal(response)
	if encodeErr == nil && len(data) > api.MaxFrameBytes {
		encodeErr = serviceError(api.CodeIntegrity, "administrator enrollment response exceeds its frame bound")
	}
	if encodeErr != nil {
		response.Result = nil
		response.FailureField = "response"
		response.Error = enrollmentError("response", encodeErr)
		s.journalEnrollment("response", response.Error)
		data, encodeErr = json.Marshal(response)
		if encodeErr != nil {
			s.recordFault(serviceError(api.CodeIntegrity, "administrator enrollment refusal encoding failed"))
			return
		}
	}
	// A failed read deadline must not make an otherwise writable refusal silent.
	// Closed/unwritable transports can only retain their journal diagnostic.
	if err := connection.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		s.journalEnrollment("deadline", enrollmentError("deadline", err))
		return
	}
	if err := wire.WriteFrame(connection, data); err != nil {
		s.journalEnrollment("response_write", enrollmentError("response_write", err))
	}
}
