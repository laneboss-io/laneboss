package identityd

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/identityd/ticket"
)

const requestTimeout = 5 * time.Second
const connectionTimeout = 30 * time.Second

type Options struct {
	Config             string
	StateRoot          string
	RuntimeRoot        string
	Verifier           TicketVerifier
	UIDConnectionLimit int
	ConfigHome         string
	HumanUID           uint32
	HumanSession       *ProcessRef
	LegacyState        string
}

func (o Options) uidConnectionLimit() int {
	if o.UIDConnectionLimit == 0 || ignoreUIDSetting() {
		return MaxUIDConnections
	}
	return o.UIDConnectionLimit
}

func (o Options) roots() (string, string) {
	state, runtime := o.StateRoot, o.RuntimeRoot
	if state == "" {
		state = StateRoot
	}
	if runtime == "" {
		runtime = RuntimeRoot
	}
	return state, runtime
}

type Server struct {
	options   Options
	process   Peer
	store     *store
	listener  *net.UnixListener
	socket    string
	socketID  os.FileInfo
	runtime   *os.Root
	mu        sync.Mutex
	clientsMu sync.Mutex
	clients   map[*net.UnixConn]*socketIdentity
	byUID     map[uint32]int
	byPeer    map[Peer]int
	closing   bool
	lastSeq   atomic.Int64
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
	tickets   *ticket.Store
	ticketDB  *sql.DB
	policy    *config.Configuration
}

// Open requires provisioned roots and refuses root execution, unsafe ownership
// or permissions, a second writer, and replacement of a live/foreign socket.
func Open(options Options) (*Server, error) {
	if err := config.CheckName(options.Config); err != nil {
		return nil, refuse("the configuration name is invalid")
	}
	if options.uidConnectionLimit() < 1 || options.uidConnectionLimit() > MaxConnections {
		return nil, refuse("the UID connection limit must be from 1 to 32\nInstead: set --uid-connection-limit within the global connection limit.")
	}
	if os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return nil, refuse("the service must run as its dedicated unprivileged OS user\nInstead: install the systemd or launchd service in docs/service.md.")
	}
	current, err := nativeProcess(os.Getpid())
	if err != nil {
		return nil, err
	}
	state, runtime := options.roots()
	directoryMode, fileMode := storageModes()
	_, root, err := serviceDirectory(state, options.Config, os.FileMode(directoryMode), current.GID)
	if err != nil {
		return nil, err
	}
	store, err := openStore(root, options.Config, os.FileMode(fileMode))
	if err != nil {
		root.Close()
		return nil, err
	}
	path, runtimeDir, err := serviceDirectory(runtime, options.Config, 0750, current.GID)
	if err != nil {
		store.close()
		return nil, err
	}
	socket := filepath.Join(path, "service.sock")
	if err = staleSocket(socket, current.UID, current.GID); err != nil {
		runtimeDir.Close()
		store.close()
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		runtimeDir.Close()
		store.close()
		return nil, corrupt("the service socket cannot be opened")
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chmod(socket, 0660); err != nil {
		listener.Close()
		runtimeDir.Close()
		store.close()
		return nil, corrupt("the service socket permissions cannot be set")
	}
	info, err := os.Lstat(socket)
	if err != nil {
		listener.Close()
		runtimeDir.Close()
		store.close()
		return nil, err
	}
	uid, gid, _, err := ownership(info)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 || uid != current.UID || gid != current.GID {
		listener.Close()
		runtimeDir.Close()
		store.close()
		return nil, corrupt("the service socket's final ownership or permissions disagree with its installation")
	}
	server := &Server{options: options, process: current.Peer, store: store, listener: listener, socket: socket, socketID: info, runtime: runtimeDir, clients: map[*net.UnixConn]*socketIdentity{}, byUID: map[uint32]int{}, byPeer: map[Peer]int{}}
	server.lastSeq.Store(store.seq)
	if err := server.openTickets(); err != nil {
		server.Close()
		return nil, ticketFailure(err)
	}
	if server.options.Verifier == nil {
		server.options.Verifier = RejectTickets{}
	}
	return server, nil
}

func staleSocket(path string, owner, group uint32) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	uid, gid, _, err := ownership(info)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 || uid != owner || gid != group {
		return refuse("the service socket has unsafe type, permissions or ownership\nInstead: have the administrator inspect the existing socket; do not replace it.")
	}
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		return refuse("the service socket is already listening\nInstead: use service status or stop the existing service through its service manager.")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return refuse("the existing service socket cannot be checked\nInstead: have the administrator inspect it before restarting.")
	}
	return os.Remove(path)
}

func (s *Server) Info() ServiceInfo {
	return ServiceInfo{Config: s.options.Config, Peer: s.process, Seq: s.lastSeq.Load()}
}

func (s *Server) Socket() string { return s.socket }

func (s *Server) Serve(ctx context.Context) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			s.listener.Close()
		case <-done:
		}
	}()
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return corrupt("the service listener stopped unexpectedly")
		}
		// Capture the kernel identity at accept, before handing the connection
		// to a worker and before consuming the request's first byte.
		peer, peerError := socketPeer(conn)
		if peerError != nil {
			code, message := safeError(peerError)
			s.rejectConnection(conn, Response{Version: Version, Code: code, Error: message, Service: s.Info()})
			continue
		}
		s.clientsMu.Lock()
		if s.closing {
			s.clientsMu.Unlock()
			peer.lifetime.close()
			conn.Close()
			return nil
		}
		uidLimited := s.byUID[peer.UID] >= s.options.uidConnectionLimit()
		peerLimited := s.byPeer[peer.Peer] >= MaxPeerConnections
		limited := uidLimited || peerLimited
		if len(s.clients) >= MaxConnections || limited && !unlimitedPeer() {
			s.clientsMu.Unlock()
			peer.lifetime.close()
			message := "refused: the service global connection limit of 32 was reached\nInstead: reconnect after an existing request finishes."
			if peerLimited {
				message = "refused: the service per-peer connection limit of 2 was reached\nInstead: finish an existing request from this process before reconnecting."
			} else if uidLimited {
				message = fmt.Sprintf("refused: the service per-UID connection limit of %d was reached\nInstead: finish an existing request or have the administrator adjust --uid-connection-limit; no request bytes were read.", s.options.uidConnectionLimit())
			}
			s.rejectConnection(conn, Response{Version: Version, Code: 2, Error: message, Service: s.Info()})
			continue
		}
		s.clients[conn] = peer
		s.byUID[peer.UID]++
		s.byPeer[peer.Peer]++
		s.wg.Add(1)
		s.clientsMu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				conn.Close()
				peer.lifetime.close()
				s.clientsMu.Lock()
				delete(s.clients, conn)
				s.byUID[peer.UID]--
				s.byPeer[peer.Peer]--
				if s.byUID[peer.UID] == 0 {
					delete(s.byUID, peer.UID)
				}
				if s.byPeer[peer.Peer] == 0 {
					delete(s.byPeer, peer.Peer)
				}
				s.clientsMu.Unlock()
			}()
			s.handle(ctx, conn, peer)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn *net.UnixConn, peer *socketIdentity) {
	reader := bufio.NewReaderSize(conn, MaxRequestBytes+1)
	end := time.Now().Add(connectionTimeout)
	for count := 0; count < MaxRequests; count++ {
		if err := conn.SetReadDeadline(minDeadline(end)); err != nil {
			return
		}
		line, err := reader.ReadSlice('\n')
		if err == io.EOF && len(line) == 0 {
			return
		}
		if err != nil || len(line) > MaxRequestBytes {
			message := "refused: the service request is incomplete, oversized or timed out\nInstead: send one JSON object per line within 65536 bytes and five seconds."
			s.writeResponse(conn, Response{Version: Version, Code: 2, Error: message, Service: s.Info()})
			return
		}
		request, err := parseRequest(line)
		var response Response
		if err == nil {
			callContext, cancel := context.WithDeadline(ctx, minDeadline(end))
			response = s.dispatch(callContext, peer, request)
			cancel()
		} else {
			code, message := safeError(err)
			response = Response{Version: Version, Code: code, Error: message, Service: s.Info()}
		}
		if err := s.writeResponse(conn, response); err != nil {
			return
		}
		if ctx.Err() != nil || time.Now().After(end) {
			return
		}
	}
}

// Refusing a new connection must not wait for either the identity mutex or a
// verifier, or spend the ordinary five-second write budget in the accept loop.
func (s *Server) rejectConnection(conn *net.UnixConn, response Response) {
	defer conn.Close()
	data, err := json.Marshal(response)
	if err != nil || conn.SetWriteDeadline(time.Now().Add(100*time.Millisecond)) != nil {
		return
	}
	conn.Write(append(data, '\n'))
}

func minDeadline(end time.Time) time.Time {
	deadline := time.Now().Add(requestTimeout)
	if end.Before(deadline) {
		return end
	}
	return deadline
}

func (s *Server) writeResponse(conn *net.UnixConn, response Response) error {
	data, err := json.Marshal(response)
	if err != nil || len(data)+1 > MaxResponseBytes {
		return corrupt("the service response exceeds its size limit")
	}
	if err = conn.SetWriteDeadline(time.Now().Add(requestTimeout)); err != nil {
		return err
	}
	data = append(data, '\n')
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (s *Server) dispatch(ctx context.Context, connected *socketIdentity, request Request) Response {
	response := Response{Version: Version, Service: s.Info(), Lifetime: connected.lifetime.mode()}
	fail := func(err error) Response {
		var scoped *ticket.Refusal
		if errors.As(err, &scoped) && scoped.Reason == ticket.PolicyChanged && scoped.Policy.Valid() {
			response.PolicyChange = scoped.Policy
		}
		response.Code, response.Error = safeError(ticketFailure(err))
		response.Identified, response.Principal = false, nil
		return response
	}
	if !protocolVersion(request.Version) {
		return fail(refuse("the service protocol version is not supported\nInstead: use laneboss_service: 1."))
	}
	if request.Config != s.options.Config {
		return fail(refuse("the request conflicts with the service configuration\nInstead: connect to the socket for the bound configuration."))
	}
	if err := connected.check(); err != nil {
		return fail(err)
	}
	peer, err := claimedPeer(connected.Peer, request)
	if err != nil {
		return fail(err)
	}
	line, err := ancestry(peer)
	if err != nil {
		return fail(err)
	}
	s.mu.Lock()
	principal, err := s.store.resolve(line)
	s.mu.Unlock()
	if err != nil {
		return fail(err)
	}
	var grant Grant
	if request.Op != "register" {
		if err := s.validatePrincipal(ctx, principal); err != nil {
			return fail(err)
		}
	}
	if request.Op == "issue" {
		if err := connected.lifetime.mutationAllowed(); err != nil {
			return fail(err)
		}
		raw, err := s.issue(ctx, peer, request.Payload)
		if err != nil {
			return fail(err)
		}
		if err := connected.check(); err != nil {
			return fail(err)
		}
		if ctx.Err() != nil {
			return fail(&ticket.Refusal{Reason: ticket.Unavailable})
		}
		response.Peer, response.Ticket, response.OK = &peer, raw, true
		return response
	}
	human := false
	if request.Op == "whoami" && s.tickets != nil {
		human = (humanAuthorizer{s}).RequireHuman(context.WithValue(ctx, issuerPeerKey{}, peer)) == nil
	}
	if request.Op == "register" {
		if err := connected.lifetime.mutationAllowed(); err != nil {
			return fail(err)
		}
		if strings.HasPrefix(principal.ID, "lane:") {
			return fail(refuse("a lane cannot register a supervisor role ticket\nInstead: report up with laneboss report."))
		}
		// Only the fault build can reproduce the old global-lock stall.
		locked := verifyLocked()
		if locked {
			s.mu.Lock()
		}
		verification := ticket.WithConsumer(ctx, ticket.Consumer{PID: peer.PID, Start: peer.Start, UID: peer.UID})
		grant, err = s.options.Verifier.Verify(verification, s.options.Config, peer, request.Ticket)
		if locked {
			s.mu.Unlock()
		}
		if err != nil {
			var refused *ticket.Refusal
			if errors.As(err, &refused) {
				return fail(refused)
			}
			if _, ok := err.(*failure); ok {
				return fail(err)
			}
			return fail(refuse("the bootstrap ticket could not be verified\nInstead: obtain a fresh configuration-bound ticket through the installed bootstrap verifier."))
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := connected.check(); err != nil {
		return fail(err)
	}
	line, err = ancestry(peer)
	if err != nil {
		return fail(err)
	}
	fresh, root, detachmentRoot, err := s.store.resolveRoot(line)
	if err != nil {
		return fail(err)
	}
	if fresh != principal {
		return fail(refuse("the caller's recorded identity changed during the request\nInstead: reconnect and resolve the current session before continuing."))
	}
	if request.Op != "register" {
		if err := s.validatePrincipal(ctx, fresh); err != nil {
			return fail(err)
		}
	} else if err := s.validatePrincipal(ctx, grant.Principal); err != nil {
		return fail(err)
	}
	response.Service = s.Info()
	response.Peer, response.Identified = &peer, principal.ID != ""
	if principal.ID != "" {
		response.Principal = &principal
		response.Root = root
		response.DetachmentRoot = detachmentRoot
	}
	if request.Op == "whoami" {
		response.Human = human
		if human && s.tickets != nil {
			response.LastConsumer, err = s.tickets.LastConsumer(ctx)
			if err != nil {
				return fail(err)
			}
		}
		response.OK = true
		return response
	}
	if err := connected.lifetime.mutationAllowed(); err != nil {
		return fail(err)
	}
	var record Record
	switch request.Op {
	case "register":
		record, err = s.store.authorizeGrant(ctx, grant, principal, peer, line, s.process)
		if err != nil {
			return fail(err)
		}
		response.Principal, response.Identified = &grant.Principal, true
	case "lane-started":
		record, err = s.store.authorizeLane(ctx, request, principal, peer)
		if err != nil {
			return fail(err)
		}
	case "append":
		if principal.ID == "" {
			if !allowUnknown() {
				return fail(unidentified(false))
			}
			fresh = Principal{ID: "human"}
		}
		request.Lane, err = laneScope(request, fresh)
		if err != nil {
			return fail(err)
		}
		if err := validateAppend(request, fresh); err != nil {
			return fail(err)
		}
		record = Record{Op: "append", Actor: appendActor(fresh, request), Peer: peer, Lane: request.Lane, Type: request.Type, Kind: request.Kind, To: request.To, Payload: request.Payload}
	default:
		return fail(refuse("the service operation is not supported\nInstead: use whoami, register, lane-started or append."))
	}
	// Check the connected process again at the write boundary. PID reuse or a
	// credential change on an established connection cannot retain its authority.
	if err := connected.check(); err != nil {
		return fail(err)
	}
	line, err = ancestry(peer)
	if err != nil {
		return fail(err)
	}
	current, err := s.store.resolve(line)
	if err != nil {
		return fail(err)
	}
	if current != principal {
		return fail(refuse("the caller's recorded identity changed before the write\nInstead: reconnect from the live recorded session."))
	}
	if ctx.Err() != nil {
		return fail(refuse("the service request timed out\nInstead: reconnect and check the last recorded sequence before retrying a write."))
	}
	written, err := s.store.append(record, func(candidate Record) error {
		preview := response
		preview.Record, preview.OK, preview.Service.Seq = &candidate, true, candidate.Seq
		data, err := json.Marshal(preview)
		if err != nil || len(data)+1 > MaxResponseBytes {
			return refuse("the service response envelope exceeds its size limit\nInstead: submit a smaller observation or message.")
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	response.Record, response.OK, response.Service.Seq = written, true, s.store.seq
	s.lastSeq.Store(s.store.seq)
	return response
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.clientsMu.Lock()
		s.closing = true
		s.listener.Close()
		for conn := range s.clients {
			conn.Close()
		}
		s.clientsMu.Unlock()
		s.wg.Wait()
		info, err := os.Lstat(s.socket)
		if err == nil && os.SameFile(s.socketID, info) {
			err = s.runtime.Remove("service.sock")
		} else if err == nil {
			err = corrupt("the service socket changed before collection")
		}
		s.closeErr = errors.Join(err, s.runtime.Close(), s.store.close())
		if s.ticketDB != nil {
			s.closeErr = errors.Join(s.closeErr, s.ticketDB.Close())
		}
	})
	return s.closeErr
}
