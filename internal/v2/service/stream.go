package service

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Server) RegisterStream(method api.Method, handler api.StreamHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if (method != "event.tail" && method != "lane.attach") || handler == nil {
		return wire.Invalid("method does not support streaming or handler is nil")
	}
	if s.closed || s.serving || s.streams[method] != nil {
		return serviceError(api.CodeConflict, "stream route is already registered or frozen")
	}
	if s.streams == nil {
		s.streams = make(map[api.Method]api.StreamHandler)
	}
	s.streams[method] = handler
	return nil
}

func isStreaming(request api.Request) bool {
	if request.Method == "lane.attach" {
		return true
	}
	if request.Method == "event.tail" {
		var tail api.EventTailRequest
		return wire.Decode(request.Params, &tail) == nil && tail.Follow
	}
	return false
}

type queuedFrame struct {
	frame api.StreamFrame
	bytes int
}

func (s *Server) serveStream(ctx context.Context, connection net.Conn, scope api.Scope, request api.Request, initial json.RawMessage) {
	scope.ReadView = nil // The initial pinned snapshot has closed before live delivery.
	s.mu.RLock()
	streamHandler := s.streams[request.Method]
	slots := s.watchers
	s.mu.RUnlock()
	var tail api.EventTailRequest
	var selection api.EventTailRequest
	params := request.Params
	index := uint64(0)
	cursor := ""
	if request.Method == "event.tail" {
		var snapshot api.EventPage
		if wire.Decode(initial, &snapshot) != nil || wire.Decode(params, &tail) != nil {
			return
		}
		cursor = snapshot.Cursor
		selection = tail
		for _, event := range snapshot.Events {
			if selectedEnd(tail, event) {
				if err := s.writeStream(connection, api.StreamFrame{RequestID: request.RequestID, Index: 1, Cursor: cursor, End: true}); err != nil {
					return
				}
				return
			}
		}
		// Subscribe from the committed snapshot's exclusive cursor, closing the
		// snapshot/subscription race without changing authority or request digest.
		tail.Cursor = snapshot.Cursor
		tail.Since = 0
		var err error
		params, err = json.Marshal(tail)
		if err != nil {
			return
		}
	} else {
		frame, err := wire.DecodeStream(initial, request.RequestID, 1)
		if err != nil {
			return
		}
		if frame.End || frame.Error != nil {
			return
		}
		cursor = frame.Cursor
	}
	terminated := false
	sendError := func(err error) {
		if terminated {
			return
		}
		terminated = true
		// If the peer has stopped reading, the bounded write deadline closes only
		// this watcher. A client reports its EOF as failure, never as lane end.
		if writeErr := s.writeStream(connection, api.StreamFrame{RequestID: request.RequestID,
			Index: index + 1, Cursor: cursor, Error: typedError(err)}); writeErr != nil {
			return
		}
	}
	if streamHandler == nil {
		sendError(api.NotImplemented(api.Methods[request.Method].Owner, "stream producer"))
		return
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		sendError(serviceError(api.CodeUnavailable, "watcher capacity exhausted"))
		return
	}
	principal := scope.Actor.Kind + ":" + string(scope.Actor.ID) + ":" + string(scope.Actor.LifeID)
	s.mu.Lock()
	if s.principalWatchers == nil {
		s.principalWatchers = make(map[string]int)
	}
	if s.principalWatchers[principal] >= 2 {
		s.mu.Unlock()
		sendError(serviceError(api.CodeUnavailable, "principal watcher capacity exhausted"))
		return
	}
	s.principalWatchers[principal]++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.principalWatchers[principal]--
		if s.principalWatchers[principal] == 0 {
			delete(s.principalWatchers, principal)
		}
		s.mu.Unlock()
	}()
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if tail.DeadlineMS > 0 {
		var deadlineCancel context.CancelFunc
		streamCtx, deadlineCancel = context.WithTimeout(streamCtx, time.Duration(tail.DeadlineMS)*time.Millisecond)
		defer deadlineCancel()
	}
	stream, err := streamHandler(streamCtx, scope, params)
	if err != nil {
		sendError(err)
		return
	}
	if stream == nil {
		sendError(serviceError(api.CodeIntegrity, "stream producer returned no stream"))
		return
	}
	queue := newStreamQueue()
	terminal := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			frame, err := stream.Next(streamCtx)
			if err != nil {
				terminal <- err
				return
			}
			select {
			case <-streamCtx.Done():
				return
			default:
			}
			if err := queue.push(frame); err != nil {
				terminal <- err
				return
			}
			if frame.End || frame.Error != nil {
				return
			}
		}
	}()
	defer func() {
		cancel()
		closed := make(chan error, 1)
		go func() { closed <- stream.Close() }()
		select {
		case err := <-closed:
			if err != nil {
				s.recordFault(err)
				sendError(err)
			}
		case <-time.After(time.Second):
			s.recordFault(serviceError(api.CodeIntegrity, "stream close did not drain"))
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			s.recordFault(serviceError(api.CodeIntegrity, "stream producer did not drain"))
		}
	}()
	var producerError error
	terminalInput := (<-chan error)(terminal)
	for {
		if producerError != nil && len(queue.frames) == 0 {
			sendError(producerError)
			return
		}
		select {
		case err := <-terminalInput:
			producerError, terminalInput = err, nil
			continue
		case <-streamCtx.Done():
			sendError(contextError(streamCtx.Err()))
			return
		case item := <-queue.frames:
			queue.release(item)
			frame := item.frame
			if request.Method == "event.tail" && frame.Chunk != nil || request.Method == "lane.attach" && frame.Event != nil {
				sendError(serviceError(api.CodeIntegrity, "stream producer returned the wrong payload kind"))
				return
			}
			if frame.Event != nil && request.Method == "event.tail" &&
				(frame.Event.LifeID != tail.LifeID || frame.Event.Run != tail.Run || frame.Event.Seq <= selection.Since) {
				continue
			}
			closeWindow := &authenticationReplyWindow{ConnectionContext: scope.Connection}
			authCtx := context.WithValue(streamCtx, authenticationReplyKey{}, closeWindow)
			current, err := s.authenticateConnection(authCtx, scope.Connection)
			if err != nil {
				sendError(err)
				if closeWindow.closeRequested.Load() {
					s.closeResource(scope.Connection)
				}
				return
			}
			if current.Actor != scope.Actor || current.Config != scope.Config || current.LaunchID != scope.LaunchID || current.EndpointGeneration != scope.EndpointGeneration {
				sendError(serviceError(api.CodeUnauthenticated, "watcher identity changed"))
				return
			}
			if current.PolicyGeneration != scope.PolicyGeneration {
				allowAndLog("watcher_policy_generation")
			}
			current.Request, current.Source = request, scope.Source
			current.Connection, current.Frame = scope.Connection, scope.Frame
			if err := s.deps.Authenticator.Authorize(streamCtx, current, request); err != nil {
				sendError(err)
				return
			}
			if scope.Frame != nil {
				if err := scope.Frame.Verify(streamCtx, scope.Connection); err != nil {
					sendError(err)
					return
				}
			}
			if frame.Event != nil {
				visible, err := wire.EventVisible(streamCtx, current, *frame.Event)
				if checker, ok := s.deps.Store.(interface {
					EventVisible(context.Context, api.Scope, api.Event) (bool, error)
				}); ok {
					visible, err = checker.EventVisible(streamCtx, current, *frame.Event)
				}
				if err != nil {
					sendError(err)
					return
				}
				if !visible {
					continue
				}
			}
			if frame.End && tail.Until != "" {
				sendError(serviceError(api.CodeUnavailable, "watcher ended before the selected service event"))
				return
			}
			frame.RequestID, frame.Index = request.RequestID, index+1
			data, err := json.Marshal(frame)
			if err != nil {
				sendError(serviceError(api.CodeIntegrity, "stream frame encoding failed"))
				return
			}
			if _, err := wire.DecodeStream(data, request.RequestID, index+1); err != nil {
				sendError(serviceError(api.CodeIntegrity, "invalid stream frame schema"))
				return
			}
			if err := s.writeStream(connection, frame); err != nil {
				return
			}
			index, cursor = frame.Index, frame.Cursor
			if frame.End || frame.Error != nil {
				terminated = true
				return
			}
			if frame.Event != nil && selectedEnd(selection, *frame.Event) {
				if err := s.writeStream(connection, api.StreamFrame{RequestID: request.RequestID, Index: index + 1, Cursor: cursor, End: true}); err != nil {
					return
				}
				terminated = true
				return
			}
		}
	}
}

func selectedEnd(request api.EventTailRequest, event api.Event) bool {
	return request.Until != "" && event.Kind == request.Until && event.LifeID == request.LifeID &&
		event.Run == request.Run && event.Origin == "service" && event.Seq > request.Since
}

func (s *Server) writeStream(connection net.Conn, frame api.StreamFrame) error {
	if err := connection.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		return err
	}
	data, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	return wire.WriteFrame(connection, data)
}
