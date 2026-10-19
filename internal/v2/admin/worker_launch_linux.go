//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
)

var _ identity.WorkerLaunchSource = (*Service)(nil)

type workerCallKey struct{}

type workerLaunchSession struct {
	mu         sync.Mutex
	service    *Service
	connection *net.UnixConn
	peer       *pinnedPeer
	snapshot   workerLaunchSnapshot
	files      []*os.File
	finish     func()
	closed     bool
}

// WithWorkerLaunch owns the enclosing native transaction. Identity borrows a
// guard from its context, closes that borrow before returning its permit, and
// OpenDataWorker uses this same authenticated conversation before the owner
// releases the helper gate/allocation locks. Every failure closes the owner.
func (s *Service) WithWorkerLaunch(ctx context.Context, prepared api.PreparedLaunch, open func(context.Context) error) (resultErr error) {
	if open == nil || ctx.Value(workerCallKey{}) != nil {
		return failure(api.CodeConflict, "worker launch requires one enclosing native handoff")
	}
	session, err := s.openWorkerLaunch(ctx, prepared.ID)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, session.close()) }()
	if session.snapshot.Native.Prepared != prepared {
		return failure(api.CodeIntegrity, "worker transaction changed its prepared native gate")
	}
	return open(context.WithValue(ctx, workerCallKey{}, session))
}

func (s *Service) workerSession(ctx context.Context) *workerLaunchSession {
	session, _ := ctx.Value(workerCallKey{}).(*workerLaunchSession)
	if session != nil && session.service == s {
		return session
	}
	return nil
}

func (s *Service) openWorkerLaunch(parent context.Context, id api.ID) (_ *workerLaunchSession, resultErr error) {
	if !validID(id) || !validConfig(s.deps.Config) || s.deps.Store == nil || s.deps.ServiceUID == 0 {
		return nil, failure(api.CodePrerequisite, "worker launch requires the installed administrator client")
	}
	ctx, cancel := context.WithTimeout(parent, helperCallTimeout)
	session := &workerLaunchSession{service: s, finish: cancel}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, session.dispose())
		}
	}()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if uint32(os.Getuid()) != s.deps.ServiceUID || uint32(os.Geteuid()) != s.deps.ServiceUID {
		return nil, failure(api.CodeForbidden, "helper calls require the installed unprivileged service identity")
	}
	current, err := loadInstallation(s.deps.Config)
	if err != nil {
		return nil, err
	}
	if current.Generation != s.binding.Generation || current.Artifact != s.binding.Artifact {
		return nil, failure(api.CodeVersion, "installed helper generation changed; restart the matched service")
	}
	if err := protectedPath(s.binding.runtimePath(), true); err != nil {
		return nil, err
	}
	dialer := helperDialer()
	connection, err := dialer.DialContext(ctx, "unix", s.binding.socketPath())
	if err != nil {
		return nil, failure(api.CodeUnavailable, "installed helper socket is unavailable")
	}
	session.connection = connection.(*net.UnixConn)
	stop, err := bindHelperCall(ctx, connection)
	if err != nil {
		return nil, err
	}
	session.finish = func() { stop(); cancel() }
	session.peer, err = pinPeer(session.connection, 0, 0)
	if err != nil {
		return nil, err
	}
	membership, err := cgroupMembership(int(session.peer.credentials.Pid))
	if err != nil {
		return nil, err
	}
	config, err := helperControlConfig(membership)
	if err != nil || config != s.deps.Config {
		return nil, failure(api.CodeUnauthenticated, "root endpoint is not the installed helper service")
	}
	request, err := session.request("worker_launch", workerLaunchQuery{PreparedID: id})
	if err != nil {
		return nil, err
	}
	if err := writeFrame(connection, request); err != nil {
		return nil, err
	}
	data, files, err := readCredentialFrame(session.connection, session.peer.credentials, session.peer.alive)
	session.files = files
	if err != nil {
		return nil, err
	}
	if err := workerResponse(data, request.Nonce, &session.snapshot); err != nil {
		return nil, err
	}
	if len(files) != 3 || session.snapshot.Native.Prepared.ID != id {
		return nil, failure(api.CodeIntegrity, "worker handoff requires exactly its input, endpoint and original pidfd")
	}
	if err := validateWorkerNative(session.snapshot.Native, session.snapshot.workerRegistration(), s.binding); err != nil {
		return nil, err
	}
	if err := session.checkFiles(); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *workerLaunchSession) request(method string, params any) (helperRequest, error) {
	body, err := EncodeWire(params)
	if err != nil {
		return helperRequest{}, failure(api.CodeInvalid, "cannot encode worker handoff input")
	}
	nonce, err := randomID("worker-")
	return helperRequest{Protocol: helperProtocol, Revision: api.ContractRevision, Config: s.service.deps.Config,
		Generation: s.service.binding.Generation, ArtifactSHA256: s.service.binding.Artifact.SHA256,
		Nonce: nonce, Method: method, Params: body}, err
}

func workerResponse(data []byte, nonce api.ID, result any) error {
	var response helperResponse
	if err := decodeReply(data, &response); err != nil {
		return err
	}
	if response.Protocol != helperProtocol || response.Revision != api.ContractRevision || response.Nonce != nonce ||
		(response.Error == nil) == (len(response.Result) == 0) || response.Reason != "" && (!api.ValidHelperReason(response.Reason) || response.Error == nil) {
		return failure(api.CodeIntegrity, "worker handoff response binding changed")
	}
	if response.Error != nil {
		return ownInvalid(response.Error, owner)
	}
	return decodeReply(response.Result, result)
}

func (s *workerLaunchSession) call(ctx context.Context, method string, params, result any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exchange(ctx, method, params, result)
}

func (s *workerLaunchSession) exchange(ctx context.Context, method string, params, result any) error {
	if s.closed || s.connection == nil || s.peer == nil {
		return failure(api.CodeContainmentUnknown, "worker handoff conversation is closed")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := s.peer.alive(); err != nil {
		return err
	}
	request, err := s.request(method, params)
	if err != nil {
		return err
	}
	if err := writeFrame(s.connection, request); err != nil {
		return err
	}
	data, err := readUnixFrame(s.connection, s.peer)
	if err != nil {
		return err
	}
	return workerResponse(data, request.Nonce, result)
}

func (s *workerLaunchSession) checkFiles() error {
	if len(s.files) != 3 {
		return failure(api.CodeContainmentUnknown, "worker handoff lost its retained descriptors")
	}
	for i, file := range s.files[:2] {
		pin, err := workerDescriptor(file)
		if err != nil {
			return err
		}
		if pin != s.snapshot.Pins[i] {
			return failure(api.CodeIntegrity, "borrowed worker descriptor identity changed")
		}
	}
	if s.snapshot.Pins[0].Device == s.snapshot.Pins[1].Device && s.snapshot.Pins[0].Inode == s.snapshot.Pins[1].Inode {
		return failure(api.CodeIntegrity, "borrowed worker descriptors alias one object")
	}
	return workerBootstrapLifetime(s.files[2], s.snapshot.Native.Peer)
}

func workerBootstrapLifetime(file *os.File, peer api.PeerFacts) error {
	// A received pidfd must name the pinned bootstrap PID in this host's
	// namespace. Poll/signal then verify that exact lifetime is still live.
	if file == nil {
		return failure(api.CodeUnauthenticated, "worker bootstrap pidfd is missing")
	}
	info, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(int(file.Fd())))
	if err != nil {
		return failure(api.CodeUnauthenticated, "worker bootstrap pidfd is unavailable")
	}
	pid := ""
	for _, line := range strings.Split(string(info), "\n") {
		if value, found := strings.CutPrefix(line, "Pid:"); found {
			pid = strings.TrimSpace(value)
		}
	}
	if pid != strconv.Itoa(peer.HostPID) {
		return failure(api.CodeUnauthenticated, "worker bootstrap pidfd changed its native process")
	}
	pin := &pinnedPeer{pidfd: int(file.Fd())}
	return pin.alive()
}

func (s *workerLaunchSession) check(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var snapshot workerLaunchSnapshot
	if err := s.exchange(ctx, "worker_check", api.Empty{}, &snapshot); err != nil {
		return err
	}
	if !reflect.DeepEqual(snapshot, s.snapshot) {
		return failure(api.CodeIntegrity, "live helper worker handoff changed")
	}
	return s.checkFiles()
}

func (s *workerLaunchSession) dispose() error {
	s.closed = true
	var result error
	if s.connection != nil {
		result = errors.Join(result, s.connection.Close())
	}
	if s.peer != nil {
		result = errors.Join(result, unix.Close(s.peer.pidfd))
	}
	result = errors.Join(result, closeCredentialFiles(s.files))
	if s.finish != nil {
		s.finish()
	}
	return result
}

func (s *workerLaunchSession) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var empty api.Empty
	err := s.exchange(context.Background(), "worker_close", api.Empty{}, &empty)
	return errors.Join(err, s.dispose())
}

type workerLaunchGuard struct {
	mu        sync.Mutex
	session   *workerLaunchSession
	authority identity.WorkerLaunchAuthority
	files     []*os.File
	owner     bool
	closed    bool
}

func (s *Service) AcquireWorkerLaunch(ctx context.Context, config string, id api.ID) (_ identity.WorkerLaunchGuard, resultErr error) {
	if config != s.deps.Config || !validConfig(config) || !validID(id) || s.deps.Store == nil {
		return nil, failure(api.CodeForbidden, "worker launch selector differs from its installed administrator")
	}
	session := s.workerSession(ctx)
	owner := session == nil
	var err error
	if owner {
		session, err = s.openWorkerLaunch(ctx, id)
		if err != nil {
			return nil, err
		}
	}
	guard := &workerLaunchGuard{session: session, owner: owner}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, guard.Close())
		}
	}()
	if session.snapshot.Native.Prepared.ID != id {
		return nil, failure(api.CodeForbidden, "worker borrow names a foreign prepared gate")
	}
	if err := session.check(ctx); err != nil {
		return nil, err
	}
	reader, ok := s.deps.Store.(api.WorkerIdentityStore)
	if !ok {
		return nil, api.NotImplemented("lb-v2-service", "retained worker identity lookup")
	}
	native := session.snapshot.Native
	registration := session.snapshot.workerRegistration()
	binding, err := s.deps.Store.LaunchBinding(ctx, registration.LaunchID)
	if err != nil {
		return nil, err
	}
	principal, err := reader.WorkerBinding(ctx, native.Endpoint, native.Peer)
	if err != nil {
		return nil, err
	}
	if binding.Prepared != native.Prepared || binding.Record.Kind != "worker" || binding.Record.Actor.Kind != "worker" || binding.Record.Revoked || binding.Recovery != nil ||
		!reflect.DeepEqual(principal.Record, binding.Record) || principal.Lease != registration.Worker || !reflect.DeepEqual(principal.Endpoint, native.Endpoint) || principal.Peer != native.Peer ||
		principal.StageID != native.Selector.StageID || principal.BootID != native.BootID || principal.AllocationGeneration != s.binding.Generation ||
		binding.Record.UIDLeaseID != native.Lease.ID || binding.Record.HostUID != native.Lease.UID || binding.Record.ContainmentID != native.Lease.ContainmentID {
		return nil, failure(api.CodeIntegrity, "worker native handoff differs from its committed principal")
	}
	guard.authority = identity.WorkerLaunchAuthority{Binding: binding, Handoff: session.snapshot.Handoff, Principal: principal}
	for _, file := range session.files {
		duplicate, err := duplicateDirectory(file)
		if err != nil {
			return nil, err
		}
		guard.files = append(guard.files, duplicate)
	}
	if err := guard.Check(ctx); err != nil {
		return nil, err
	}
	return guard, nil
}

func (g *workerLaunchGuard) Authority() identity.WorkerLaunchAuthority {
	g.mu.Lock()
	defer g.mu.Unlock()
	var authority identity.WorkerLaunchAuthority
	raw, err := json.Marshal(g.authority)
	// This is an in-process deep copy of joined typed metadata. Worker
	// bindings deliberately have nil agent Recovery; it is not a wire frame.
	if g.closed || err != nil || json.Unmarshal(raw, &authority) != nil {
		return identity.WorkerLaunchAuthority{}
	}
	return authority
}

func (g *workerLaunchGuard) Input() *os.File {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || len(g.files) != 3 {
		return nil
	}
	return g.files[0]
}

func (g *workerLaunchGuard) Endpoint() *os.File {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || len(g.files) != 3 {
		return nil
	}
	return g.files[1]
}

// The peer is this native guard, whose Facts rechecks the helper and the exact
// received pidfd. It cannot be constructed from serializable peer facts alone.
func (g *workerLaunchGuard) Peer() api.VerifiedPeer { return g }

func (g *workerLaunchGuard) Alive(ctx context.Context) error { return g.Check(ctx) }

func (g *workerLaunchGuard) Facts(ctx context.Context) (api.PeerFacts, error) {
	if err := g.Check(ctx); err != nil {
		return api.PeerFacts{}, err
	}
	return g.authority.Principal.Peer, nil
}

func (g *workerLaunchGuard) Check(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || len(g.files) != 3 {
		return failure(api.CodeContainmentUnknown, "borrowed worker launch guard is closed")
	}
	if err := g.session.check(ctx); err != nil {
		return err
	}
	for i, file := range g.files[:2] {
		pin, err := workerDescriptor(file)
		if err != nil {
			return err
		}
		if pin != g.session.snapshot.Pins[i] {
			return failure(api.CodeIntegrity, "borrowed worker descriptor identity changed")
		}
	}
	if err := workerBootstrapLifetime(g.files[2], g.authority.Principal.Peer); err != nil {
		return err
	}
	principal := g.authority.Principal
	reader, ok := g.session.service.deps.Store.(api.WorkerIdentityStore)
	if !ok {
		return api.NotImplemented("lb-v2-service", "retained worker identity lookup")
	}
	current, err := reader.WorkerBinding(ctx, principal.Endpoint, principal.Peer)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, principal) {
		return failure(api.CodeConflict, "worker claim or lease changed during its borrowed handoff")
	}
	binding, err := g.session.service.deps.Store.LaunchBinding(ctx, principal.Record.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(binding, g.authority.Binding) {
		return failure(api.CodeConflict, "worker committed binding changed during its borrowed handoff")
	}
	return nil
}

func (g *workerLaunchGuard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	err := closeCredentialFiles(g.files)
	g.files = nil
	if g.owner {
		err = errors.Join(err, g.session.close())
	}
	return err
}
