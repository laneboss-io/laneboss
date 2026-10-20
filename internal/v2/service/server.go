package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type Options struct {
	AdminEnrollment *api.AdminEnrollmentEndpoint
	Config          string
	BindingFile     string
}

const rpcReplyTimeout = 5 * time.Second

type Server struct {
	judgeWorker         *nativeJudge
	usageSource         usageSource
	usageJobs           map[api.ID]*usageSession
	initialProfiles     admin.InitialProfileEnrollment
	deps                Dependencies
	controller          api.ID
	options             Options
	mu                  sync.RWMutex
	handlers            map[api.Method]api.Handler
	streams             map[api.Method]api.StreamHandler
	serving             bool
	starting            bool
	verified            bool
	watchers            chan struct{}
	runtime             api.RuntimeServices
	bound               bool
	reconciling         bool
	launchConfigured    bool
	launchJobsActive    bool
	launchJobsHealthy   bool
	closed              bool
	listener            net.Listener
	cancel              context.CancelFunc
	connections         map[api.ID]*connectionContext
	revokedLaunches     map[api.ID]bool
	workers             sync.WaitGroup
	flights             map[string]chan struct{}
	workerStops         map[api.ID]context.CancelFunc
	workerTurns         map[api.ID]*workerTurnInfo
	laneEndpoints       map[api.ID]*laneEndpoint
	fault               error
	admissions          map[string]int
	refusalActive       int
	refusalDrops        uint64
	principalWatchers   map[string]int
	closeDone           chan struct{}
	closeResult         error
	dashboardHandler    http.Handler
	dashboardBootstraps map[api.ID]dashboardBootstrap
	dispatchMu          sync.Mutex
	dispatchPaused      bool
	freeze              *api.FreezeReceipt
	activeDispatches    int
	activityChanged     chan struct{}
	scheduler           *schedulerSource
}

// BindDashboard installs the configured human dashboard as an external HTTPS
// handoff. The listener and certificate remain administrator-owned resources.
func (s *Server) BindDashboard(handler http.Handler) error {
	if handler == nil {
		return serviceError(api.CodeInvalid, "dashboard HTTP handler is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.serving || s.dashboardHandler != nil {
		return serviceError(api.CodeConflict, "dashboard HTTP handoff is already bound or host is serving")
	}
	s.dashboardHandler = handler
	return nil
}

// DashboardHandler returns the handler for the administrator's pinned HTTPS
// listener. It never creates a listener.
func (s *Server) DashboardHandler() (http.Handler, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.dashboardHandler == nil {
		return nil, api.NotImplemented("lb-v2-service", "dashboard HTTPS listener handoff")
	}
	return s.dashboardHandler, nil
}

var _ api.Registrar = (*Server)(nil)

func NewServer(options Options, deps Dependencies) (*Server, error) {
	if !wire.ValidID(options.Config) || deps.Store == nil || deps.Authenticator == nil || deps.Clock == nil {
		return nil, wire.Invalid("server requires explicit config and all dependencies")
	}
	return installedServer(options, deps)
}

func (s *Server) Register(method api.Method, handler api.Handler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := api.Methods[method]; !ok || handler == nil {
		return wire.Invalid("unknown method or nil RPC handler")
	}
	if s.closed || s.serving || s.handlers[method] != nil {
		return serviceError(api.CodeConflict, "RPC route is already registered or frozen")
	}
	if s.handlers == nil {
		s.handlers = make(map[api.Method]api.Handler)
	}
	s.handlers[method] = handler
	return nil
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.mu.Lock()
	if !s.verified || !s.bound {
		s.mu.Unlock()
		return api.NotImplemented("lb-v2-service", "service.installed-binding")
	}
	if s.closed || s.serving {
		s.mu.Unlock()
		return serviceError(api.CodeConflict, "server is already serving")
	}
	if _, ok := listener.(*net.UnixListener); !ok {
		s.mu.Unlock()
		return wire.Invalid("service requires the installed Unix listener")
	}
	if listener.Addr().String() != s.deps.Binding.Socket {
		s.mu.Unlock()
		return serviceError(api.CodeForbidden, "listener differs from installed socket")
	}
	if err := wire.EnableCredentials(listener.(*net.UnixListener)); err != nil {
		s.mu.Unlock()
		return err
	}
	s.serving = true
	if s.starting && s.cancel != nil {
		startupCancel := s.cancel
		s.cancel = func() { cancel(); startupCancel() }
	} else {
		s.cancel = cancel
	}
	s.listener = listener
	s.watchers = make(chan struct{}, 32)
	// This sentinel remains positive while the accept loop may admit workers.
	// Close and every Add are serialized by mu, so Wait cannot observe zero
	// before a late startup or connection admission.
	s.workers.Add(1)
	s.mu.Unlock()
	defer s.workers.Done()
	defer func() { s.mu.Lock(); s.serving = false; s.mu.Unlock() }()
	var workers sync.WaitGroup
	connections := make(chan struct{}, 128)
	stop := context.AfterFunc(runCtx, func() { s.closeResource(listener) })
	defer stop()
	defer workers.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return contextError(ctx.Err())
			}
			return serviceError(api.CodeUnavailable, "service listener failed")
		}
		select {
		case connections <- struct{}{}:
			s.mu.Lock()
			if s.closed || runCtx.Err() != nil {
				s.mu.Unlock()
				<-connections
				s.closeResource(connection)
				return contextError(context.Canceled)
			}
			workers.Add(1)
			s.workers.Add(1)
			s.mu.Unlock()
			go func() {
				defer workers.Done()
				defer s.workers.Done()
				defer func() { <-connections }()
				s.serveConnection(runCtx, connection)
			}()
		default:
			s.refuseOverload(runCtx, connection, serviceError(api.CodeUnavailable, "service connection admission limit reached"), &workers)
		}
	}
}

func serviceError(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Owner: "lb-v2-service", Message: message,
		Instead: "Retain the receipt and repair the installed service through its supervisor."}
}

func contextError(err error) *api.Error {
	if errors.Is(err, context.DeadlineExceeded) {
		return serviceError(api.CodeDeadline, "request deadline exceeded")
	}
	return serviceError(api.CodeCancelled, "request cancelled")
}

func typedError(err error) *api.Error {
	var typed *api.Error
	if errors.As(err, &typed) {
		if typed.Owner == "" {
			owned := *typed
			owned.Owner = "lb-v2-service"
			return &owned
		}
		return typed
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return contextError(err)
	}
	return serviceError(api.CodeIntegrity, "internal service operation failed")
}

func (s *Server) serveConnection(ctx context.Context, connection net.Conn) {
	s.serveBoundConnection(ctx, connection, s.deps.Binding)
}

func (s *Server) serveBoundConnection(ctx context.Context, connection net.Conn, binding api.InstalledBinding) {
	lifetime, err := newConnection(connection, binding, s.deps.Clock)
	if err != nil {
		s.journalConnection("connection", typedError(err))
		s.closeResource(connection)
		return
	}
	defer s.closeResource(lifetime)
	ctx, cancelLifetime := context.WithCancel(ctx)
	lifetime.cancel = cancelLifetime
	lifetime.finished = make(chan struct{})
	defer close(lifetime.finished)
	defer cancelLifetime()
	s.mu.Lock()
	if s.closed || s.revokedLaunches[lifetime.Binding().LaunchID] {
		reason := "revoked_entry"
		if s.closed {
			reason = "closed_entry"
		}
		s.mu.Unlock()
		s.journalLaneClose(binding, lifetime.ID(), reason)
		return
	}
	if s.connections == nil {
		s.connections = make(map[api.ID]*connectionContext)
	}
	s.connections[lifetime.ID()] = lifetime
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.connections, lifetime.ID()); s.mu.Unlock() }()
	var expected wire.SocketPeer
	unixConn, native := connection.(*net.UnixConn)
	if s.verified && !native {
		s.journalConnection("connection", serviceError(api.CodeForbidden, "installed connection is not native"))
		return
	}
	if native {
		expected, err = wire.PeerCredentials(unixConn)
		if err != nil {
			s.journalConnection("peer_credentials", typedError(err))
			return
		}
	}
	admissionKey := ""
	if native {
		admissionKey = "uid:" + fmt.Sprint(expected.UID)
		s.mu.Lock()
		if s.admissions == nil {
			s.admissions = make(map[string]int)
		}
		if s.admissions[admissionKey] >= 8 {
			s.mu.Unlock()
			s.refuseAdmission(connection, serviceError(api.CodeUnavailable, "native connection admission limit reached"))
			return
		}
		s.admissions[admissionKey]++
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			s.admissions[admissionKey]--
			if s.admissions[admissionKey] == 0 {
				delete(s.admissions, admissionKey)
			}
			s.mu.Unlock()
		}()
	}
	stop := context.AfterFunc(ctx, func() {
		// Cancel work and interrupt a pending read, but retain the existing
		// bounded write window for a correlated refusal. Closing here races
		// authentication's refusal and turns a named error into an EOF.
		select {
		case <-lifetime.finished:
			return
		default:
		}
		if err := connection.SetReadDeadline(time.Now()); err != nil && !errors.Is(err, net.ErrClosed) {
			s.journalConnection("deadline", typedError(err))
		}
		timer := time.NewTimer(rpcReplyTimeout)
		defer timer.Stop()
		select {
		case <-lifetime.finished:
		case <-timer.C:
			s.closeResource(lifetime)
		}
	})
	defer stop()
	first := true
	admitted := false
	for {
		if err := connection.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			s.journalConnection("deadline", typedError(err))
			return
		}
		// Cancellation may have interrupted the previous turn just before
		// this deadline reset. Do not start another idle read after it.
		if ctx.Err() != nil {
			s.journalLaneClose(binding, lifetime.ID(), "cancelled_idle")
			return
		}
		var data []byte
		var frame api.FrameContext
		var err error
		if native {
			frame, err = wire.ReadPinnedFrame(unixConn, expected)
			if err == nil {
				data = frame.Bytes()
			}
		} else {
			data, err = wire.ReadFrame(connection)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.journalConnection("frame", typedError(err))
				if writeErr := s.writeResponse(connection, api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion,
					RequestID: "invalid-frame", Error: typedError(err)}); writeErr != nil {
					return
				}
			}
			return
		}
		request, err := wire.DecodeRequest(data)
		response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID}
		if !wire.ValidID(string(response.RequestID)) {
			response.RequestID = "invalid-request"
		}
		if err != nil {
			response.Error = typedError(err)
			if s.writeResponse(connection, response) != nil {
				return
			}
			return // Do not resynchronize after a protocol violation.
		}
		if first && request.Method == "health" {
			healthCtx, healthCancel := context.WithTimeout(ctx, 5*time.Second)
			result, head, healthErr := s.publicHealth(healthCtx, request, frame, expected)
			healthCancel()
			response.LastSeq = head
			if healthErr != nil {
				response.Error = typedError(healthErr)
			} else {
				response.Result = result
			}
			if err := s.writeResponse(connection, response); err != nil {
				return
			}
			return // A public-health connection never reads a second frame.
		}
		// A pre-authentication refusal can keep this socket open. Retain the
		// UID slot and require admission until this connection actually moves.
		var admit func(context.Context) error
		if native && !admitted {
			admit = func(entryCtx context.Context) error {
				nextKey, err := s.authenticatedAdmission(entryCtx, lifetime, expected, admissionKey)
				if err == nil {
					admissionKey = nextKey
					admitted = true
				}
				return err
			}
		}
		first = false
		requestCtx, requestCancel := context.WithTimeout(context.WithValue(ctx, requestFrameKey{}, frame), 30*time.Second)
		closeWindow := &authenticationReplyWindow{ConnectionContext: lifetime}
		requestCtx = context.WithValue(requestCtx, authenticationReplyKey{}, closeWindow)
		result, scope, err := s.dispatchWithAdmission(requestCtx, lifetime, request, admit)
		if err == nil && requestCtx.Err() != nil {
			result, err = nil, contextError(requestCtx.Err())
		}
		requestCancel()
		if scope.ReadView != nil {
			response.LastSeq = scope.ReadView.Snapshot().LastSeq
		}
		if err != nil {
			response.Error = typedError(err)
		} else {
			response.Result = result
		}
		var entry *connectionEntryFailure
		entryFailed := errors.As(err, &entry)
		if entryFailed {
			response.Error = connectionRefusal(entry.stage, entry.cause)
			s.journalConnection(entry.stage, typedError(entry.cause))
		}
		if writeErr := s.writeResponse(connection, response); writeErr != nil {
			s.journalConnection("response_write", typedError(writeErr))
			return
		}
		if entryFailed || closeWindow.closeRequested.Load() {
			return // The deferred lifetime close follows this single refusal.
		}
		if response.Error == nil && isStreaming(request) {
			s.serveStream(ctx, connection, scope, request, result)
			return
		}
	}
}

// Move the temporary UID slot to the authenticated containment atomically.
// Established lanes no longer consume another lane's public-health UID slots.
func (s *Server) authenticatedAdmission(ctx context.Context, connection api.ConnectionContext, expected wire.SocketPeer, previous string) (string, error) {
	peer := connection.Peer()
	if peer == nil {
		return previous, serviceError(api.CodeUnauthenticated, "authenticated admission requires a verified peer")
	}
	if err := peer.Alive(ctx); err != nil {
		return previous, err
	}
	facts, err := peer.Facts(ctx)
	if err != nil {
		return previous, err
	}
	if facts.HostUID != expected.UID || facts.HostGID != expected.GID || facts.HostPID != expected.PID || facts.ProcessGeneration == "" {
		return previous, serviceError(api.CodeUnauthenticated, "admission peer differs from native writer")
	}
	if connection.Binding().Class != api.EndpointHuman && !wire.ValidID(string(facts.ContainmentID)) {
		return previous, serviceError(api.CodeUnauthenticated, "lane admission requires verified containment")
	}
	key := "uid:" + fmt.Sprint(expected.UID) + ":" + string(facts.ContainmentID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.admissions[previous] < 1 {
		return previous, serviceError(api.CodeUnavailable, "connection admission is closed")
	}
	if s.admissions[key] >= 8 {
		return previous, serviceError(api.CodeUnavailable, "authenticated peer admission limit reached")
	}
	s.admissions[key]++
	s.admissions[previous]--
	if s.admissions[previous] == 0 {
		delete(s.admissions, previous)
	}
	return key, nil
}

func (s *Server) dispatch(ctx context.Context, connection api.ConnectionContext, request api.Request) (json.RawMessage, api.Scope, error) {
	return s.dispatchWithAdmission(ctx, connection, request, nil)
}

func (s *Server) dispatchWithAdmission(ctx context.Context, connection api.ConnectionContext, request api.Request, admit func(context.Context) error) (json.RawMessage, api.Scope, error) {
	var scope api.Scope
	if err := wire.ValidateRequest(request); err != nil {
		return nil, scope, err
	}
	if request.Config != s.options.Config {
		return nil, scope, serviceError(api.CodeForbidden, "request conflicts with installed configuration")
	}
	if request.Method == "health" {
		return nil, scope, serviceError(api.CodeForbidden, "health requires a new public-health connection")
	}
	class := s.deps.Binding.Class
	if connection != nil {
		class = connection.Binding().Class
	}
	if (class == api.EndpointLane || class == api.EndpointWorker) &&
		(request.Proof != nil || stringsHumanMethod(request.Method)) {
		return nil, scope, serviceError(api.CodeForbidden, "endpoint class cannot use human administration")
	}
	entryCtx, entryCancel := context.WithTimeout(ctx, 5*time.Second)
	s.journalAuthenticationStart(entryCtx, connection, request.RequestID)
	scope, err := s.authenticateConnection(entryCtx, connection)
	if err != nil {
		entryCancel()
		return nil, scope, &connectionEntryFailure{stage: "authentication", cause: err}
	}
	if admit != nil {
		if err := admit(entryCtx); err != nil {
			entryCancel()
			return nil, api.Scope{}, &connectionEntryFailure{stage: "admission", cause: err}
		}
	}
	entryCancel()
	if scope.Config != s.options.Config {
		return nil, scope, serviceError(api.CodeForbidden, "peer configuration binding mismatch")
	}
	if connection != nil && (scope.EndpointGeneration != connection.Binding().EndpointGeneration || scope.Actor.Kind != string(connection.Binding().Class)) {
		return nil, scope, serviceError(api.CodeUnauthenticated, "principal does not match installed endpoint")
	}
	scope.Connection = connection
	// Request and source can only be filled by this endpoint dispatcher.
	scope.Request = request
	scope.Source = dispatchSource(ctx)
	scope.Frame = frameFromContext(ctx)
	if scope.Frame != nil {
		if err := scope.Frame.Verify(ctx, connection); err != nil {
			return nil, scope, err
		}
	}
	if scope.Actor.Kind == "lane" && (request.Proof != nil || stringsHumanMethod(request.Method)) {
		return nil, scope, serviceError(api.CodeForbidden, "lane endpoint cannot use human administration")
	}
	if err := s.deps.Authenticator.Authorize(ctx, scope, request); err != nil {
		return nil, scope, err
	}
	if api.Methods[request.Method].Mutation {
		return s.dispatchMutation(ctx, scope, request)
	}
	s.mu.RLock()
	handler := s.handlers[request.Method]
	s.mu.RUnlock()
	if handler == nil {
		return nil, scope, api.NotImplemented(api.Methods[request.Method].Owner, string(request.Method))
	}
	if isStreaming(request) {
		s.mu.RLock()
		available := s.streams[request.Method] != nil
		s.mu.RUnlock()
		if !available {
			return nil, scope, api.NotImplemented(api.Methods[request.Method].Owner, "stream producer")
		}
	}
	view, err := s.deps.Store.BeginRead(ctx, scope)
	if err != nil {
		return nil, scope, err
	}
	scope.ReadView = view
	defer func() {
		if err := view.Close(); err != nil {
			s.recordFault(err)
		}
	}()
	result, err := handler(ctx, scope, request.Params)
	if err != nil {
		return nil, scope, err
	}
	if err := wire.ValidateResult(request.Method, result); err != nil {
		return nil, scope, serviceError(api.CodeIntegrity, "handler returned an invalid result schema")
	}
	current, err := s.authenticateConnection(ctx, connection)
	if err != nil {
		return nil, scope, err
	}
	if current.Actor != scope.Actor || current.Config != scope.Config || current.LaunchID != scope.LaunchID || current.EndpointGeneration != scope.EndpointGeneration || current.PolicyGeneration != scope.PolicyGeneration {
		return nil, scope, serviceError(api.CodeUnauthenticated, "peer binding changed before reply")
	}
	current.Request, current.Source = request, scope.Source
	current.Connection, current.Frame = scope.Connection, scope.Frame
	if scope.Frame != nil {
		if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
			return nil, scope, err
		}
	}
	if err := s.deps.Authenticator.Authorize(ctx, current, request); err != nil {
		return nil, scope, err
	}
	return result, scope, nil
}

func stringsHumanMethod(method api.Method) bool {
	switch api.Methods[method].Access {
	case "human-endpoint", "human-proof", "human-read":
		return true
	}
	return false
}

func (s *Server) writeResponse(connection net.Conn, response api.Response) error {
	if err := connection.SetWriteDeadline(time.Now().Add(rpcReplyTimeout)); err != nil {
		return err
	}
	data, err := json.Marshal(response)
	if err != nil {
		return err
	}
	return wire.WriteFrame(connection, data)
}
