package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// DashboardEntryProtocol is a native, human-only connection handoff. Public
// RPCs retain their ordinary frames, catalog, authorization and dispatcher.
const DashboardEntryProtocol = "laneboss.dashboard-entry.v1"

type DashboardEntryRequest struct {
	Protocol string       `json:"protocol"`
	Action   string       `json:"action"`
	RedeemID api.ID       `json:"redeem_id,omitempty"`
	Nonce    []byte       `json:"nonce,omitempty"`
	Session  *api.Request `json:"session,omitempty"`
	Target   *api.LifeRef `json:"target,omitempty"`
}

type DashboardEntryReply struct {
	Protocol string          `json:"protocol"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    *api.Error      `json:"error,omitempty"`
}

type DashboardConnection struct {
	Config       string    `json:"config"`
	ConnectionID api.ID    `json:"connection_id"`
	Actor        api.Actor `json:"actor"`
}

// DashboardEntry owns two protected Unix listeners. TLS terminates in the
// matched installed CLI; this backend serves the actual bound dashboard.
// Browser authority remains the original verified native human connection.
type DashboardEntry struct {
	server   *Server
	native   net.Listener
	web      net.Listener
	http     *http.Server
	paths    map[string]os.FileInfo
	cancel   context.CancelFunc
	once     sync.Once
	closeErr error
	wg       sync.WaitGroup
}

func (s *Server) OpenDashboardEntry(ctx context.Context) (_ *DashboardEntry, resultErr error) {
	s.mu.RLock()
	ready := s.verified && s.bound && !s.closed && s.deps.Binding.Class == api.EndpointHuman
	s.mu.RUnlock()
	if !ready || s.options.AdminEnrollment == nil {
		return nil, serviceError(api.CodePrerequisite, "dashboard entry requires the installed human host and relying party")
	}
	handler, err := s.DashboardHandler()
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	e := &DashboardEntry{server: s, paths: make(map[string]os.FileInfo), cancel: cancel}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, e.Close())
		}
	}()
	for _, item := range []struct {
		suffix string
		target *net.Listener
	}{{".browser", &e.native}, {".web", &e.web}} {
		binding := s.deps.Binding
		binding.Socket += item.suffix
		listener, err := listenInstalled(ctx, binding)
		if err != nil {
			return nil, err
		}
		*item.target = listener
		info, err := os.Lstat(binding.Socket)
		if err != nil {
			return nil, err
		}
		e.paths[binding.Socket] = info
	}
	e.http = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute,
		MaxHeaderBytes: 1 << 16}
	e.wg.Add(2)
	go func() {
		defer e.wg.Done()
		err := e.http.Serve(e.web)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			s.recordFault(err)
		}
	}()
	go func() { defer e.wg.Done(); e.accept(runCtx) }()
	context.AfterFunc(runCtx, func() { _ = e.Close() })
	return e, nil
}

func (e *DashboardEntry) accept(ctx context.Context) {
	for {
		connection, err := e.native.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				e.server.recordFault(err)
			}
			return
		}
		s := e.server
		s.mu.Lock()
		if s.closed || ctx.Err() != nil {
			s.mu.Unlock()
			_ = connection.Close()
			continue
		}
		s.workers.Add(1)
		s.mu.Unlock()
		go func() { defer s.workers.Done(); s.serveDashboardEntry(ctx, connection) }()
	}
}

func (e *DashboardEntry) Close() error {
	e.once.Do(func() {
		if e.cancel != nil {
			e.cancel()
		}
		if e.http != nil {
			e.closeErr = errors.Join(e.closeErr, e.http.Close())
		}
		for _, listener := range []net.Listener{e.native, e.web} {
			if listener != nil {
				if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					e.closeErr = errors.Join(e.closeErr, err)
				}
			}
		}
		e.wg.Wait()
		for path, original := range e.paths {
			current, err := os.Lstat(path)
			if err == nil && os.SameFile(original, current) {
				e.closeErr = errors.Join(e.closeErr, os.Remove(path))
			} else if err != nil && !errors.Is(err, os.ErrNotExist) {
				e.closeErr = errors.Join(e.closeErr, err)
			}
		}
	})
	return e.closeErr
}

func (s *Server) dashboardEntryCall(ctx context.Context, connection *connectionContext, frame api.FrameContext, input DashboardEntryRequest) (any, error) {
	if input.Protocol != DashboardEntryProtocol || connection == nil || frame == nil || connection.Binding().Class != api.EndpointHuman {
		return nil, serviceError(api.CodeForbidden, "dashboard entry requires its exact native human frame")
	}
	var retained DashboardEntryRequest
	if err := api.DecodeObject(frame.Bytes(), &retained); err != nil || !reflect.DeepEqual(retained, input) {
		return nil, wire.Invalid("dashboard entry differs from its received frame")
	}
	scope, err := s.authenticateConnection(ctx, connection)
	if err != nil {
		return nil, err
	}
	if scope.Actor.Kind != "human" || scope.Config != s.options.Config || scope.EndpointGeneration != connection.Binding().EndpointGeneration {
		return nil, serviceError(api.CodeForbidden, "dashboard entry authenticated another endpoint")
	}
	if err := frame.Verify(ctx, connection); err != nil {
		return nil, err
	}
	switch input.Action {
	case "open", "ping":
		if input.Session != nil || input.RedeemID != "" || len(input.Nonce) != 0 || input.Target != nil {
			return nil, wire.Invalid("dashboard open/ping accepts no authority labels")
		}
		return DashboardConnection{Config: scope.Config, ConnectionID: connection.ID(), Actor: scope.Actor}, nil
	case "review-inputs":
		if input.Target == nil || input.Session != nil || input.RedeemID != "" || len(input.Nonce) != 0 {
			return nil, wire.Invalid("dashboard review inputs require only the actual target")
		}
		return s.prepareDashboardReview(ctx, scope, *input.Target)
	case "bootstrap":
		if input.Session == nil || input.Session.Method != "human.session" || input.Session.Config != scope.Config ||
			input.Session.Proof == nil || input.RedeemID == "" || len(input.Nonce) < 16 {
			return nil, wire.Invalid("dashboard bootstrap requires the exact redemption session intent")
		}
		raw, err := json.Marshal(input.Session)
		if err != nil {
			return nil, err
		}
		request, err := wire.DecodeRequest(raw)
		if err != nil {
			return nil, err
		}
		scope.Request, scope.Frame, scope.Source = request, frame, "cli"
		return s.IssueDashboardBootstrap(ctx, scope, input.RedeemID, input.Nonce)
	}
	return nil, wire.Invalid("unknown dashboard native entry action")
}

func (s *Server) serveDashboardEntry(parent context.Context, raw net.Conn) {
	defer raw.Close()
	socket, ok := raw.(*net.UnixConn)
	if !ok {
		return
	}
	connection, err := newConnection(socket, s.deps.Binding, s.deps.Clock)
	if err != nil {
		return
	}
	defer s.closeResource(connection)
	expected, err := wire.PeerCredentials(socket)
	if err != nil {
		return
	}
	key := "dashboard-uid:" + fmtDashboardUID(expected.UID)
	s.mu.Lock()
	if s.admissions == nil {
		s.admissions = make(map[string]int)
	}
	if s.closed || s.admissions[key] >= 8 {
		s.mu.Unlock()
		return
	}
	s.admissions[key]++
	if s.connections == nil {
		s.connections = make(map[api.ID]*connectionContext)
	}
	s.connections[connection.ID()] = connection
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.connections, connection.ID()); s.admissions[key]--; s.mu.Unlock() }()
	stop := context.AfterFunc(parent, func() { _ = connection.Close() })
	defer stop()
	for {
		if err := socket.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}
		frame, err := wire.ReadPinnedFrame(socket, expected)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.journalConnection("frame", typedError(err))
			}
			return
		}
		ctx, cancel := context.WithTimeout(context.WithValue(parent, requestFrameKey{}, frame), 30*time.Second)
		closeWindow := &authenticationReplyWindow{ConnectionContext: connection}
		ctx = context.WithValue(ctx, authenticationReplyKey{}, closeWindow)
		var header struct {
			Protocol string `json:"protocol"`
		}
		if err := json.Unmarshal(frame.Bytes(), &header); err != nil {
			cancel()
			return
		}
		var reply any
		if header.Protocol == api.Protocol {
			request, err := wire.DecodeRequest(frame.Bytes())
			response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID}
			if err == nil {
				var scope api.Scope
				response.Result, scope, err = s.dispatch(ctx, connection, request)
				if scope.ReadView != nil {
					response.LastSeq = scope.ReadView.Snapshot().LastSeq
				}
			}
			if err != nil {
				response.Error = s.dashboardEntryError(err)
			}
			reply = response
		} else {
			var request DashboardEntryRequest
			response := DashboardEntryReply{Protocol: DashboardEntryProtocol}
			err := api.DecodeObject(frame.Bytes(), &request)
			if err == nil {
				var result any
				result, err = s.dashboardEntryCall(ctx, connection, frame, request)
				if err == nil {
					response.Result, err = json.Marshal(result)
				}
			}
			if err != nil {
				response.Error = s.dashboardEntryError(err)
			}
			reply = response
		}
		cancel()
		encoded, err := json.Marshal(reply)
		if err != nil || socket.SetWriteDeadline(time.Now().Add(time.Second)) != nil || wire.WriteFrame(socket, encoded) != nil {
			return
		}
		if closeWindow.closeRequested.Load() {
			return
		}
	}
}

func (s *Server) dashboardEntryError(err error) *api.Error {
	var entry *connectionEntryFailure
	if errors.As(err, &entry) {
		s.journalConnection(entry.stage, typedError(entry.cause))
		return connectionRefusal(entry.stage, entry.cause)
	}
	return typedError(err)
}

func fmtDashboardUID(uid uint32) string {
	// Keep the admission selector internal; never publish process settings.
	return strconv.FormatUint(uint64(uid), 10)
}
