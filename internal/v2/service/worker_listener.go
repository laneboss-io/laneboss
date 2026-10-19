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

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/judge/job"
)

func (s *Server) startDataEndpoint(parent context.Context, stage api.LaunchDataStage, sealed api.InstalledBinding) error {
	return s.startWorkerEndpoint(parent, stage.Worker.ID, sealed)
}

func (s *Server) startWorkerEndpoint(parent context.Context, leaseID api.ID, sealed api.InstalledBinding) error {
	key := "worker-endpoint:" + string(leaseID)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return contextError(context.Canceled)
	}
	if s.flights == nil {
		s.flights = make(map[string]chan struct{})
	}
	if s.flights[key] != nil {
		s.mu.Unlock()
		return nil
	}
	s.flights[key] = make(chan struct{})
	s.mu.Unlock()
	started := false
	defer func() {
		if !started {
			s.mu.Lock()
			close(s.flights[key])
			delete(s.flights, key)
			s.mu.Unlock()
		}
	}()
	base := filepath.Join(filepath.Dir(s.deps.Binding.Socket), "workers")
	if err := os.Mkdir(base, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return serviceError(api.CodePrerequisite, "worker endpoint directory is unavailable")
	}
	if err := runtimeDirectory(base, sealed.ServiceUID); err != nil {
		return err
	}
	info, err := os.Lstat(base)
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return serviceError(api.CodeIntegrity, "worker endpoint parent must be private to its service")
	}
	host := sealed
	host.Socket = filepath.Join(base, string(leaseID)+".sock")
	ctx, cancel := context.WithCancel(parent)
	listener, err := listenWorker(ctx, host)
	if err != nil {
		cancel()
		return err
	}
	inode, err := os.Lstat(host.Socket)
	if err != nil {
		cancel()
		return errors.Join(err, listener.Close())
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		stop()
		cancel()
		listener.Close()
		return contextError(context.Canceled)
	}
	if s.workerStops == nil {
		s.workerStops = map[api.ID]context.CancelFunc{}
	}
	s.workerStops[leaseID] = cancel
	s.workers.Add(1)
	s.mu.Unlock()
	started = true
	go func() {
		defer s.workers.Done()
		defer cancel()
		defer stop()
		defer func() {
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				s.recordFault(err)
			}
			current, err := os.Lstat(host.Socket)
			if err == nil && os.SameFile(inode, current) {
				if err := os.Remove(host.Socket); err != nil {
					s.recordFault(err)
				}
			}
			s.mu.Lock()
			close(s.flights[key])
			delete(s.flights, key)
			delete(s.workerStops, leaseID)
			s.mu.Unlock()
		}()
		slots := make(chan struct{}, 8)
		for {
			connection, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
					s.recordFault(err)
				}
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				connection.Close()
				continue
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				<-slots
				connection.Close()
				return
			}
			s.workers.Add(1)
			s.mu.Unlock()
			s.journalWorkerStage("accepted")
			go func() { defer s.workers.Done(); defer func() { <-slots }(); s.serveDataWorker(ctx, connection, sealed) }()
		}
	}()
	return nil
}

func (s *Server) stopWorkerEndpoint(ctx context.Context, leaseID api.ID) error {
	s.mu.RLock()
	cancel, done := s.workerStops[leaseID], s.flights["worker-endpoint:"+string(leaseID)]
	s.mu.RUnlock()
	if cancel == nil || done == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// The current holder owns a FIFO of waiting turns. Both the queue and the
// diagnostic metadata are protected by the existing server mutex.
type workerTurnInfo struct {
	operation string
	started   time.Time
	ended     time.Time
	ready     chan struct{}
	waiters   []*workerTurnInfo
}

type workerTurnLogKey struct{}

func workerTurnWriter(ctx context.Context) io.Writer {
	if writer, ok := ctx.Value(workerTurnLogKey{}).(io.Writer); ok {
		return writer
	}
	return os.Stderr
}

func workerTurnOperation(operation string) string {
	switch api.WorkerOperation(operation) {
	case api.WorkerPrincipalRead, api.WorkerInputRead, api.WorkerObjectRead, api.WorkerArchivePart,
		api.WorkerResultAppend, api.WorkerChannelContext, api.WorkerChannelReceipt, api.WorkerJudgeContext, api.WorkerJudgeRetain:
		return operation
	}
	if operation == "archive_observe" || operation == "judge_observe" {
		return operation
	}
	return "unknown"
}

// A worker's native rechecks share the serialized helper with archive's full
// storage scan. Finish the current frame and its delivery recheck before an
// observation. Running observations do not scan storage; terminal ones still
// measure the full fence. An idle socket must not retain a completed turn.
// This coordinates work only; both paths retain every authority check. No
// server mutex is held across helper calls, socket I/O or a cancellable wait.
// Release reserves the next turn for the oldest waiter before waking it, so
// an observer cannot reacquire ahead of a worker that is already waiting.
func (s *Server) workerTurn(ctx context.Context, leaseID api.ID, operation string) (func(), error) {
	key := "worker-call:" + string(leaseID)
	started := time.Now()
	var holder *workerTurnInfo
	defer func() {
		wait := time.Since(started)
		if wait <= time.Second || holder == nil {
			return
		}
		// The pointer survives deletion of its map entry at handoff. Snapshot
		// it under the same lock used by request updates and the original owner.
		s.mu.RLock()
		observed := *holder
		s.mu.RUnlock()
		ended := observed.ended
		if ended.IsZero() {
			ended = time.Now()
		}
		journalWorkerTurn(workerTurnWriter(ctx), operation, observed.operation, wait, ended.Sub(observed.started))
	}()
	if err := ctx.Err(); err != nil {
		return nil, contextError(err)
	}
	s.mu.Lock()
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return nil, contextError(err)
	}
	if s.closed {
		s.mu.Unlock()
		return nil, contextError(context.Canceled)
	}
	info := &workerTurnInfo{operation: workerTurnOperation(operation), ready: make(chan struct{})}
	finish := func() {
		s.mu.Lock()
		s.endWorkerTurn(leaseID, info)
		s.mu.Unlock()
	}
	holder = s.workerTurns[leaseID]
	if holder == nil {
		if s.flights == nil {
			s.flights = make(map[string]chan struct{})
		}
		s.flights[key] = make(chan struct{})
		if s.workerTurns == nil {
			s.workerTurns = make(map[api.ID]*workerTurnInfo)
		}
		info.started = time.Now()
		s.workerTurns[leaseID] = info
		s.mu.Unlock()
		return finish, nil
	}
	holder.waiters = append(holder.waiters, info)
	s.mu.Unlock()
	select {
	case <-info.ready:
	case <-ctx.Done():
	}
	s.mu.Lock()
	err := ctx.Err()
	if err == nil && s.closed {
		err = context.Canceled
	}
	if err != nil {
		if current := s.workerTurns[leaseID]; current == info {
			// Cancellation can race the handoff. Relinquish an already
			// reserved turn rather than leaving its successors blocked.
			s.endWorkerTurn(leaseID, info)
		} else if current != nil {
			for i, waiter := range current.waiters {
				if waiter == info {
					copy(current.waiters[i:], current.waiters[i+1:])
					current.waiters[len(current.waiters)-1] = nil
					current.waiters = current.waiters[:len(current.waiters)-1]
					break
				}
			}
		}
		s.mu.Unlock()
		return nil, contextError(err)
	}
	s.mu.Unlock()
	return finish, nil
}

// Called with s.mu held. Keep the lease occupied throughout the handoff;
// only the reserved waiter is woken. An old finish cannot release a new owner.
func (s *Server) endWorkerTurn(leaseID api.ID, info *workerTurnInfo) {
	if s.workerTurns[leaseID] != info {
		return
	}
	info.ended = time.Now()
	key := "worker-call:" + string(leaseID)
	close(s.flights[key])
	if len(info.waiters) == 0 {
		delete(s.workerTurns, leaseID)
		delete(s.flights, key)
		return
	}
	next := info.waiters[0]
	next.waiters = info.waiters[1:]
	info.waiters[0] = nil
	info.waiters = nil
	next.started = info.ended
	s.workerTurns[leaseID] = next
	s.flights[key] = make(chan struct{})
	close(next.ready)
}

// One line per slow wait, including cancellation, before turn_refused or turn
// is emitted by the request handler. Only allowlisted operation names escape.
func journalWorkerTurn(writer io.Writer, operation, holder string, wait, hold time.Duration) {
	data, err := json.Marshal(struct {
		Event     string `json:"event"`
		Stage     string `json:"stage"`
		Operation string `json:"operation"`
		Holder    string `json:"holder"`
		WaitMS    int64  `json:"wait_ms"`
		HoldMS    int64  `json:"hold_ms"`
	}{"worker_call", "turn_wait", workerTurnOperation(operation), workerTurnOperation(holder), wait.Milliseconds(), hold.Milliseconds()})
	if err == nil {
		_, _ = writer.Write(append(data, '\n'))
	}
}

// journalWorkerStage records where a worker conversation is (item 1 diagnosis, box 93: the archive worker
// waited silently until lane archive's receipt deadline). Fixed stage names only, never request or lane bytes.
func (s *Server) journalWorkerStage(stage string) {
	data, err := json.Marshal(struct {
		Event string `json:"event"`
		Stage string `json:"stage"`
	}{"worker_call", stage})
	if err == nil {
		_, _ = os.Stderr.Write(append(data, '\n'))
	}
}

// journalWorkerTiming records how long a fixed worker-request stage took (item 1 diagnosis, box 96: every worker
// request costs about 2 s whatever its operation). Fixed stage names and milliseconds only.
func (s *Server) journalWorkerTiming(stage string, elapsed time.Duration) {
	data, err := json.Marshal(struct {
		Event     string `json:"event"`
		Stage     string `json:"stage"`
		ElapsedMS int64  `json:"elapsed_ms"`
	}{"worker_timing", stage, elapsed.Milliseconds()})
	if err == nil {
		_, _ = os.Stderr.Write(append(data, '\n'))
	}
}

type workerCostKey struct{}

type workerCost struct {
	scope, authorize, handler, delivery time.Duration
	count                               uint64
}

func (s *Server) journalWorkerCost(operation api.WorkerOperation, cost workerCost) {
	switch operation {
	case api.WorkerPrincipalRead, api.WorkerInputRead, api.WorkerObjectRead, api.WorkerArchivePart,
		api.WorkerResultAppend, api.WorkerChannelContext, api.WorkerChannelReceipt, api.WorkerJudgeContext, api.WorkerJudgeRetain:
	default:
		return
	}
	data, err := json.Marshal(struct {
		Event     string              `json:"event"`
		Operation api.WorkerOperation `json:"operation"`
		Count     uint64              `json:"count"`
		Scope     int64               `json:"scope_us"`
		Authorize int64               `json:"authorize_us"`
		Handler   int64               `json:"handler_us"`
		Delivery  int64               `json:"delivery_us"`
	}{"worker_cost", operation, cost.count, cost.scope.Microseconds(), cost.authorize.Microseconds(),
		cost.handler.Microseconds(), cost.delivery.Microseconds()})
	if err == nil {
		_, _ = os.Stderr.Write(append(data, '\n'))
	}
}

func (s *Server) serveDataWorker(parent context.Context, connection net.Conn, binding api.InstalledBinding) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	socket, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return
	}
	lifetime, err := newConnection(socket, binding, s.deps.Clock)
	if err != nil {
		connection.Close()
		return
	}
	lifetime.cancel, lifetime.finished = cancel, make(chan struct{})
	defer close(lifetime.finished)
	defer lifetime.Close()
	s.mu.Lock()
	if s.closed || s.revokedLaunches[binding.LaunchID] {
		s.mu.Unlock()
		return
	}
	if s.connections == nil {
		s.connections = make(map[api.ID]*connectionContext)
	}
	s.connections[lifetime.ID()] = lifetime
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.connections, lifetime.ID()); s.mu.Unlock() }()
	stop := context.AfterFunc(ctx, func() { lifetime.Close() })
	defer stop()
	if err := socket.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return
	}
	peer, err := wire.PeerCredentials(socket)
	if err != nil {
		s.journalWorkerStage("peer_refused")
		return
	}
	var finish func()
	costs := map[api.WorkerOperation]workerCost{
		api.WorkerPrincipalRead: {}, api.WorkerInputRead: {}, api.WorkerObjectRead: {},
		api.WorkerArchivePart: {}, api.WorkerResultAppend: {},
		api.WorkerChannelContext: {}, api.WorkerChannelReceipt: {},
		api.WorkerJudgeContext: {}, api.WorkerJudgeRetain: {},
	}
	defer func() {
		for _, operation := range []api.WorkerOperation{api.WorkerPrincipalRead, api.WorkerInputRead,
			api.WorkerObjectRead, api.WorkerArchivePart, api.WorkerResultAppend,
			api.WorkerChannelContext, api.WorkerChannelReceipt, api.WorkerJudgeContext, api.WorkerJudgeRetain} {
			if cost := costs[operation]; cost.count != 0 {
				s.journalWorkerCost(operation, cost)
			}
		}
		if finish != nil {
			finish()
		}
	}()
	for {
		frame, err := wire.ReadPinnedFrame(socket, peer)
		if err != nil {
			return
		}
		var request api.Request
		if err := api.DecodeObject(frame.Bytes(), &request); err != nil {
			return
		}
		if request.Protocol != api.Protocol || request.Schema != api.SchemaVersion || request.Config != binding.Config {
			return
		}
		digest, err := api.RequestDigest(request)
		if err != nil || digest != request.RequestSHA256 {
			return
		}
		s.journalWorkerStage("request")
		if finish == nil {
			finish, err = s.workerTurn(ctx, binding.WorkerLeaseID, string(request.Method))
			if err != nil {
				s.journalWorkerStage("turn_refused")
				return
			}
			s.journalWorkerStage("turn")
		}
		turnStarted := time.Now()
		s.mu.Lock()
		if info := s.workerTurns[binding.WorkerLeaseID]; info != nil {
			info.operation = workerTurnOperation(string(request.Method))
		}
		s.mu.Unlock()
		closeWindow := &authenticationReplyWindow{ConnectionContext: lifetime}
		callCtx := context.WithValue(ctx, authenticationReplyKey{}, closeWindow)
		if lifetime.Peer() == nil {
			if _, err := s.authenticateConnection(callCtx, lifetime); err != nil {
				refusal := connectionRefusal("authentication", err)
				s.journalConnection("authentication", typedError(err))
				if err := s.writeResponse(socket, api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion,
					RequestID: request.RequestID, Error: refusal}); err != nil {
					s.journalConnection("response_write", typedError(err))
				}
				return
			}
		}
		s.journalWorkerStage("authenticated")
		cost := &workerCost{}
		callCtx = context.WithValue(callCtx, workerCostKey{}, cost)
		handling := time.Now()
		transport := api.Scope{Connection: lifetime, Frame: frame}
		var result any
		switch api.WorkerOperation(request.Method) {
		case api.WorkerPrincipalRead:
			var input api.WorkerInputRequest
			err = api.DecodeObject(request.Params, &input)
			if err == nil {
				_, err = s.workerScope(callCtx, transport, api.WorkerPrincipalRead, input)
				if err == nil {
					var facts api.PeerFacts
					facts, err = lifetime.Peer().Facts(callCtx)
					if err == nil {
						store, ok := s.deps.Store.(api.WorkerIdentityStore)
						if !ok {
							err = serviceError(api.CodePrerequisite, "worker native principal store is unavailable")
						} else {
							var principal api.WorkerPrincipal
							principal, err = store.WorkerBinding(callCtx, binding, facts)
							// The principal is the caller's own native binding, so a selector mismatch exposes nothing.
							if err == nil && principal.Lease.ID != input.LeaseID {
								allowAndLog("worker_principal_lease")
							}
							result = principal
						}
					}
				}
			}
		case api.WorkerArchivePart:
			var part archivejob.PartRequest
			err = api.DecodeObject(request.Params, &part)
			if err == nil {
				var scope api.Scope
				scope, err = s.workerScope(callCtx, transport, api.WorkerArchivePart, part)
				if err == nil {
					s.journalWorkerStage("part_scoped")
					sink, ok := s.deps.Store.(archivejob.PartSink)
					if !ok {
						err = serviceError(api.CodePrerequisite, "archive part store is unavailable")
					} else {
						result, err = sink.ArchivePart(callCtx, scope, part.LeaseID, part.Index, part.Bytes)
					}
				}
			}
		case api.WorkerJudgeContext:
			var input api.WorkerInputRequest
			err = api.DecodeObject(request.Params, &input)
			if err == nil {
				result, err = s.JudgeSetup(callCtx, transport, input)
			}
		case api.WorkerJudgeRetain:
			var input job.RetainRequest
			err = api.DecodeObject(request.Params, &input)
			if err == nil {
				result, err = s.JudgeRetain(callCtx, transport, input)
			}
		case api.WorkerInputRead:
			var input api.WorkerInputRequest
			err = api.DecodeObject(request.Params, &input)
			if err == nil {
				s.journalWorkerStage("input")
				result, err = s.WorkerInput(callCtx, transport, input)
			}
		case api.WorkerChannelContext:
			var input api.WorkerInputRequest
			err = api.DecodeObject(request.Params, &input)
			if err == nil {
				var scope api.Scope
				scope, err = s.workerScope(callCtx, transport, api.WorkerChannelContext, input)
				if err == nil {
					store, ok := s.deps.Store.(api.ChannelBootstrap)
					if !ok {
						err = serviceError(api.CodePrerequisite, "channel worker context store is unavailable")
					} else {
						result, err = store.ChannelContext(callCtx, scope, input)
					}
				}
			}
		case api.WorkerChannelReceipt:
			var input api.ChannelReceiptRequest
			err = api.DecodeObject(request.Params, &input)
			if err == nil {
				var scope api.Scope
				scope, err = s.workerScope(callCtx, transport, api.WorkerChannelReceipt, input)
				if err == nil {
					store, ok := s.deps.Store.(api.ChannelBootstrap)
					if !ok {
						err = serviceError(api.CodePrerequisite, "channel worker receipt store is unavailable")
					} else {
						result, err = store.ChannelReceipt(callCtx, scope, input)
					}
				}
			}
		case api.WorkerResultAppend:
			var input api.WorkerResultSubmission
			err = api.DecodeObject(request.Params, &input)
			if err == nil {
				result, err = s.WorkerResult(callCtx, transport, input)
			}
		case api.WorkerObjectRead:
			var input api.BlobReadRequest
			err = api.DecodeObject(request.Params, &input)
			if err == nil {
				var scope api.Scope
				scope, err = s.workerScope(callCtx, transport, api.WorkerObjectRead, input)
				if err == nil {
					store, ok := s.deps.Store.(materializationStore)
					if !ok {
						err = serviceError(api.CodePrerequisite, "worker object store is unavailable")
					} else {
						result, err = store.WorkerObject(callCtx, scope, input)
					}
				}
			}
		default:
			err = serviceError(api.CodeForbidden, "worker endpoint refuses public or unknown operations")
		}
		response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID}
		handlerTime := time.Since(handling) - cost.scope - cost.authorize
		s.journalWorkerStage("handled")
		if err != nil {
			response.Error = typedError(err)
			if closeWindow.closeRequested.Load() {
				response.Error = connectionRefusal("authentication", err)
				s.journalConnection("authentication", typedError(err))
				if writeErr := s.writeResponse(socket, response); writeErr != nil {
					s.journalConnection("response_write", typedError(writeErr))
				}
				return
			}
		} else {
			response.Result, err = json.Marshal(result)
			if err != nil {
				return
			}
		}
		// Reauthenticate at delivery, including the frame and native lifetime.
		delivered := time.Now()
		_, err = s.captureScope(callCtx, transport)
		deliveryTime := time.Since(delivered)
		s.journalWorkerTiming("delivery_capture", deliveryTime)
		operation := api.WorkerOperation(request.Method)
		if total, known := costs[operation]; known {
			total.count++
			total.scope += cost.scope
			total.authorize += cost.authorize
			total.handler += handlerTime
			total.delivery += deliveryTime
			costs[operation] = total
		}
		if err != nil {
			refusal := connectionRefusal("authentication", err)
			s.journalConnection("authentication", typedError(err))
			if err := s.writeResponse(socket, api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion,
				RequestID: request.RequestID, Error: refusal}); err != nil {
				s.journalConnection("response_write", typedError(err))
			}
			return
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			return
		}
		if err := wire.WriteFrame(socket, encoded); err != nil {
			return
		}
		finish()
		finish = nil
		if operation == api.WorkerResultAppend {
			s.journalWorkerTiming("result_turn", time.Since(turnStarted))
		}
	}
}
