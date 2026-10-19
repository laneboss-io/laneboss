// Package client owns the socket-only v2 client. It never opens a state database.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type Options struct {
	Config      string
	BindingFile string
}

type Client struct {
	Options            Options
	mu                 sync.Mutex
	closed             bool
	connections        map[net.Conn]struct{}
	dial               func(context.Context) (net.Conn, error)
	callMu             sync.Mutex
	primary            net.Conn
	primaryReadSession bool
	binding            *api.InstalledBinding
	endpoint           *wire.Endpoint
}

func Open(ctx context.Context, options Options) (*Client, error) {
	if !wire.ValidID(options.Config) {
		return nil, wire.Invalid("client requires an explicit configuration")
	}
	if err := ctx.Err(); err != nil {
		return nil, transportError(err)
	}
	if bound := os.Getenv("LANEBOSS_CONFIG"); bound != "" && bound != options.Config {
		return nil, &api.Error{Code: api.CodeConflict, Message: "client conflicts with active configuration", Instead: "Keep this process bound and use a separately bound process."}
	}
	if options.BindingFile == "" {
		options.BindingFile = filepath.Join("/etc", "laneboss-v2", "bindings", options.Config+".json")
		projection := wire.LaneBindingPath
		if _, err := os.Lstat(projection); err == nil {
			options.BindingFile = projection
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, transportError(err)
		}
	}
	binding, err := wire.ReadBinding(options.BindingFile, options.Config, release.Version)
	if err != nil {
		return nil, transportAt(err, "binding")
	}
	digest, err := wire.ArtifactDigest()
	if err != nil {
		return nil, transportAt(err, "artifact")
	}
	if binding.ArtifactSHA256 != digest {
		return nil, &api.Error{Code: api.CodeVersion, Message: "client artifact differs from installed binding", Instead: "Use the matched installed release generation."}
	}
	endpoint, err := wire.PinEndpoint(options.BindingFile, binding)
	if err != nil {
		return nil, transportAt(err, "binding")
	}
	c := &Client{Options: options, binding: &binding, endpoint: endpoint, connections: make(map[net.Conn]struct{})}
	c.dial = func(ctx context.Context) (net.Conn, error) {
		current, err := wire.ReadBinding(options.BindingFile, options.Config, release.Version)
		if err != nil {
			return nil, transportAt(err, "binding")
		}
		if !reflect.DeepEqual(current, binding) {
			return nil, wire.Invalid("installed binding changed while client was open")
		}
		dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
			if err := wire.EnableRawCredentials(raw); err != nil {
				return transportAt(err, "credentials")
			}
			return nil
		}}
		conn, err := endpoint.DialContext(ctx, &dialer)
		if err != nil {
			return nil, transportAt(err, "dial")
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			return nil, errors.Join(wire.Invalid("installed endpoint is not a Unix socket"), conn.Close())
		}
		peer, err := endpoint.PeerCredentials(unixConn)
		if err != nil {
			return nil, errors.Join(transportAt(err, "server_identity"), conn.Close())
		}
		if peer.UID != binding.MappedServiceUID || peer.GID != binding.MappedServiceGID {
			return nil, errors.Join(&api.Error{Code: api.CodeUnauthenticated, Owner: "lb-v2-service", Message: "socket server identity differs from protected binding", Instead: "Repair the installed endpoint; do not fall back to local state."}, conn.Close())
		}
		return &peerConnection{UnixConn: unixConn, peer: peer}, nil
	}
	c.primary, err = c.connect(ctx)
	if err != nil {
		return nil, errors.Join(err, c.Close())
	}
	return c, nil
}

type peerConnection struct {
	*net.UnixConn
	peer wire.SocketPeer
}

func (c *peerConnection) Read(data []byte) (int, error) {
	return wire.ReadPeerBytes(c.UnixConn, c.peer, data)
}

func (c *Client) Call(ctx context.Context, request api.Request) (response api.Response, resultErr error) {
	if c == nil {
		return response, &api.Error{Code: api.CodePrerequisite, Message: "client is missing", Instead: "Open the installed client."}
	}
	c.callMu.Lock()
	defer c.callMu.Unlock()
	var err error
	request, err = c.PrepareRequest(request)
	if err != nil {
		return response, err
	}
	if err := c.validate(request); err != nil {
		return response, err
	}
	if request.Method == "lane.attach" {
		return response, wire.Invalid("use a dedicated streaming connection for attach")
	}
	if request.Method == "event.tail" {
		var tail api.EventTailRequest
		if err := wire.Decode(request.Params, &tail); err != nil {
			return response, err
		}
		if tail.Follow {
			return response, wire.Invalid("use a dedicated streaming connection for follow")
		}
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return response, transportError(net.ErrClosed)
	}
	connection, persistent := c.primary, c.binding != nil
	if request.Method == "health" {
		// Public health owns a one-request socket. Preserve any authenticated
		// primary (including its human read session) for ordinary RPCs.
		connection, persistent = nil, false
	}
	c.mu.Unlock()
	if connection == nil {
		connection, err = c.connect(ctx)
	}
	if err != nil {
		return response, err
	}
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	defer func() {
		if persistent && ctx.Err() == nil && (resultErr == nil || response.Error != nil) {
			c.mu.Lock()
			if !c.closed {
				c.primary = connection
				if request.Method == "human.session" && resultErr == nil && response.Error == nil {
					c.primaryReadSession = true
				}
			}
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		if c.primary == connection {
			c.primary = nil
			c.primaryReadSession = false
		}
		c.mu.Unlock()
		if err := c.release(connection); err != nil && resultErr == nil {
			response, resultErr = api.Response{}, transportError(err)
		}
	}()
	return exchange(ctx, connection, request)
}

func (c *Client) Stream(ctx context.Context, request api.Request) (api.EventStream, error) {
	var err error
	request, err = c.PrepareRequest(request)
	if err != nil {
		return nil, err
	}
	if err := c.validate(request); err != nil {
		return nil, err
	}
	if request.Method == "event.tail" {
		var tail api.EventTailRequest
		if err := wire.Decode(request.Params, &tail); err != nil {
			return nil, err
		}
		if !tail.Follow {
			return nil, wire.Invalid("streaming event tail requires follow")
		}
	} else if request.Method != "lane.attach" {
		return nil, wire.Invalid("method does not support streaming")
	}
	// A human follow must keep the socket that consumed human.session. Transfer
	// that socket exclusively to the stream so ordinary calls cannot interleave.
	c.callMu.Lock()
	defer c.callMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, transportError(net.ErrClosed)
	}
	var connection net.Conn
	if c.binding != nil && c.binding.Class == api.EndpointHuman && c.primaryReadSession && c.primary != nil {
		connection, c.primary, c.primaryReadSession = c.primary, nil, false
	}
	c.mu.Unlock()
	if connection == nil {
		connection, err = c.connect(ctx)
	}
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	response, err := exchange(ctx, connection, request)
	if err != nil {
		stop()
		if closeErr := c.release(connection); closeErr != nil {
			return nil, transportError(closeErr)
		}
		return nil, err
	}
	stream := &eventStream{client: c, connection: connection, request: request,
		response: response, stop: stop}
	if request.Method == "lane.attach" {
		frame, err := wire.DecodeStream(response.Result, request.RequestID, 1)
		if err != nil {
			stop()
			if closeErr := c.release(connection); closeErr != nil {
				return nil, transportError(closeErr)
			}
			return nil, err
		}
		// The response is the attach snapshot; subsequent stream frames start
		// their own index at one, matching event.tail and the shared CLI.
		if frame.End || frame.Error != nil {
			stop()
			if err := c.release(connection); err != nil {
				return nil, transportError(err)
			}
			stream.ended = frame.End
			if frame.Error != nil {
				stream.failure = frame.Error
			}
		}
	}
	return stream, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.primary = nil
	c.primaryReadSession = false
	var result error
	for connection := range c.connections {
		if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
		delete(c.connections, connection)
	}
	result = errors.Join(result, c.endpoint.Close())
	if result != nil {
		return transportError(result)
	}
	return nil
}

func (c *Client) validate(request api.Request) error {
	if request.Config != c.Options.Config {
		return &api.Error{Code: api.CodeForbidden, Message: "request conflicts with client configuration",
			Instead: "Use the bound configuration without changing a live session."}
	}
	data, err := json.Marshal(request)
	if err != nil {
		return wire.Invalid("request encoding failed")
	}
	_, err = wire.DecodeRequest(data)
	return err
}

func (c *Client) connect(ctx context.Context) (net.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, transportError(net.ErrClosed)
	}
	dial := c.dial
	c.mu.Unlock()
	if dial == nil {
		return nil, &api.Error{Code: api.CodePrerequisite, Message: "client has not opened its protected installed connection", Instead: "Open the installed client before borrowing it."}
	}
	connection, err := dial(ctx)
	if err != nil {
		return nil, transportError(err)
	}
	if connection == nil {
		return nil, transportError(net.ErrClosed)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		if err := connection.Close(); err != nil {
			return nil, transportError(err)
		}
		return nil, transportError(net.ErrClosed)
	}
	if c.connections == nil {
		c.connections = make(map[net.Conn]struct{})
	}
	c.connections[connection] = struct{}{}
	return connection, nil
}

func (c *Client) release(connection net.Conn) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.connections[connection]; !exists {
		return nil // Close already collected this owned connection.
	}
	delete(c.connections, connection)
	err := connection.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil // Context cancellation already closed this owned connection.
	}
	return err
}

func exchange(ctx context.Context, connection net.Conn, request api.Request) (api.Response, error) {
	deadline := time.Now().Add(30 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return api.Response{}, transportAt(err, "deadline")
	}
	data, err := json.Marshal(request)
	if err != nil {
		return api.Response{}, wire.Invalid("request cannot be encoded")
	}
	if err := wire.WriteFrame(connection, data); err != nil {
		return api.Response{}, transportAt(err, "request_write")
	}
	data, err = wire.ReadFrame(connection)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return api.Response{}, transportAt(err, "response_read")
	}
	response, err := wire.DecodeResponse(data, request)
	if err != nil {
		return api.Response{}, transportAt(err, "response_read")
	}
	if response.Error != nil {
		return response, response.Error
	}
	return response, nil
}

func transportError(err error) *api.Error {
	var typed *api.Error
	if errors.As(err, &typed) {
		if typed.Owner == "" {
			owned := *typed
			owned.Owner = "lb-v2-service"
			return &owned
		}
		return typed
	}
	code, message := api.CodeUnavailable, "service connection failed"
	if errors.Is(err, context.Canceled) {
		code, message = api.CodeCancelled, "service request cancelled"
	} else if errors.Is(err, context.DeadlineExceeded) {
		code, message = api.CodeDeadline, "service request deadline exceeded"
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			code, message = api.CodeDeadline, "service connection timed out"
		}
	}
	return &api.Error{Code: code, Owner: "lb-v2-service", Message: message,
		Instead: "Inspect the installed service and any durable receipt before retrying the same request/key."}
}

// Stages are authored transport locations. Never expose net.OpError's path,
// arguments or native error string, and never retry a refused connection here.
func transportAt(err error, stage string) *api.Error {
	var typed *api.Error
	if errors.As(err, &typed) && typed.Owner != "" {
		return typed
	}
	refusal := *transportError(err)
	switch stage {
	case "binding", "artifact", "credentials", "dial", "server_identity", "deadline", "request_write", "response_read":
	default:
		stage = "connection"
	}
	refusal.Message += " at " + stage
	if stage == "dial" && errors.Is(err, os.ErrPermission) {
		refusal.Code, refusal.Owner = api.CodePrerequisite, "lb-v2-admin"
		refusal.Message = "installed socket access denied at dial"
		refusal.Instead = "Inspect the protected socket and ancestor ownership/modes for this caller; retain the installed binding."
	} else if stage == "dial" && errors.Is(err, os.ErrNotExist) {
		refusal.Message = "installed service socket is missing at dial"
	} else if stage == "response_read" && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		refusal.Message = "service connection closed before a complete response at response_read"
	}
	return &refusal
}

type eventStream struct {
	client     *Client
	connection net.Conn
	request    api.Request
	response   api.Response
	initial    *api.StreamFrame
	index      uint64
	mu         sync.Mutex
	closed     bool
	ended      bool
	failure    error
	stop       func() bool
}

var _ api.ResponseStream = (*eventStream)(nil)

func (s *eventStream) Initial() api.Response {
	response := s.response
	response.Result = append(json.RawMessage(nil), response.Result...)
	if response.Error != nil {
		copied := *response.Error
		response.Error = &copied
	}
	return response
}

func (s *eventStream) Next(ctx context.Context) (api.StreamFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return api.StreamFrame{}, s.failure
	}
	if err := ctx.Err(); err != nil {
		return s.fail(api.StreamFrame{}, transportError(err))
	}
	if s.ended {
		return api.StreamFrame{}, io.EOF
	}
	if s.closed {
		return api.StreamFrame{}, transportError(net.ErrClosed)
	}
	var frame api.StreamFrame
	if s.initial != nil {
		frame, s.initial = *s.initial, nil
	} else {
		deadline := time.Now().Add(30 * time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		if err := s.connection.SetReadDeadline(deadline); err != nil {
			return s.fail(frame, transportError(err))
		}
		stop := context.AfterFunc(ctx, func() { s.connection.Close() })
		data, err := wire.ReadFrame(s.connection)
		stop()
		if err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			return s.fail(frame, transportError(err)) // EOF without an end frame is failure.
		}
		frame, err = wire.DecodeStream(data, s.request.RequestID, s.index+1)
		if err != nil {
			return s.fail(frame, err)
		}
		s.index = frame.Index
	}
	if frame.Error != nil {
		return s.fail(frame, frame.Error)
	}
	if frame.End {
		s.stop()
		if err := s.client.release(s.connection); err != nil {
			return s.fail(frame, transportError(err))
		}
		s.ended = true
	}
	return frame, nil
}

func (s *eventStream) fail(frame api.StreamFrame, err error) (api.StreamFrame, error) {
	s.stop()
	s.failure = err
	if closeErr := s.client.release(s.connection); closeErr != nil {
		s.failure = errors.Join(err, transportError(closeErr))
	}
	return frame, s.failure
}

func (s *eventStream) Close() error {
	// Close the descriptor first so a concurrent Next unblocks before its lock.
	s.stop()
	err := s.client.release(s.connection)
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if err != nil {
		return transportError(err)
	}
	return nil
}
