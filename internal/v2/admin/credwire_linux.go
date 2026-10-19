//go:build linux

package admin

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

const credentialProtocol = "laneboss.credential-native.v2"

type credentialPeerPin struct {
	UID           uint32
	GID           uint32
	Executable    api.Executable
	Bytes         int64
	Cgroup        string
	ContainmentID api.ID
}
type credentialPeerCatalog struct {
	Schema     string
	Config     string
	Generation api.Generation
	Broker     credentialPeerPin
	Identity   credentialPeerPin
}
type credentialChannel struct {
	mu          sync.Mutex
	operationMu *sync.Mutex
	connection  *net.UnixConn
	peer        *pinnedPeer
	pin         credentialPeerPin
	binding     installation
	boot        string
	socket      string
	generation  string
}

func (c *credentialChannel) Alive(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if c.peer == nil {
		return failure(api.CodeUnauthenticated, "credential channel has no original peer")
	}
	if err := c.transportAlive(); err != nil {
		return err
	}
	if err := c.peer.alive(); err != nil {
		return err
	}
	generation, err := processGeneration(int(c.peer.credentials.Pid), c.boot)
	if err != nil {
		return err
	}
	if generation == "" || generation != c.generation {
		return failure(api.CodeUnauthenticated, "credential peer generation is unavailable")
	}
	membership, err := cgroupMembership(int(c.peer.credentials.Pid))
	if err != nil || membership != c.pin.Cgroup {
		return failure(api.CodeUnauthenticated, "credential peer containment changed")
	}
	executable, err := os.Open("/proc/" + strconv.Itoa(int(c.peer.credentials.Pid)) + "/exe")
	if err != nil {
		return failure(api.CodeUnauthenticated, "credential peer executable is unavailable")
	}
	err = verifyExecutableFile(executable, api.ReleaseArtifact{OS: "linux", Arch: runtime.GOARCH, Bytes: c.pin.Bytes, SHA256: c.pin.Executable.SHA256})
	return errors.Join(err, executable.Close(), c.peer.alive())
}

func (c *credentialChannel) transportAlive() error {
	if c.connection == nil {
		return failure(api.CodeUnauthenticated, "credential channel is absent")
	}
	err := socketControl(c.connection, func(fd int) error {
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLRDHUP}}
		_, err := pollHelperLifetime(poll, unix.Poll)
		if err != nil || poll[0].Revents&(unix.POLLRDHUP|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return failure(api.CodeUnauthenticated, "credential channel is no longer live")
		}
		return nil
	})
	if err != nil {
		return failure(api.CodeUnauthenticated, "credential channel is no longer live")
	}
	return nil
}
func (c *credentialChannel) Facts(ctx context.Context) (api.PeerFacts, error) {
	if err := c.Alive(ctx); err != nil {
		return api.PeerFacts{}, err
	}
	generation, err := processGeneration(int(c.peer.credentials.Pid), c.boot)
	return api.PeerFacts{HostPID: int(c.peer.credentials.Pid), HostUID: c.peer.credentials.Uid, HostGID: c.peer.credentials.Gid, ProcessGeneration: generation, ContainmentID: c.pin.ContainmentID}, err
}
func (c *credentialChannel) Close() error {
	return errors.Join(c.connection.Close(), unix.Close(c.peer.pidfd))
}

func openCredentialChannel(ctx context.Context, b installation, boot, name string, pin credentialPeerPin) (*credentialChannel, error) {
	path := filepath.Join(b.credentialRuntimePath(), name)
	return openCredentialChannelAt(ctx, b, boot, path, pin, pin.GID, 0600)
}

func openCredentialChannelAt(ctx context.Context, b installation, boot, path string, pin credentialPeerPin, socketGID uint32, socketMode uint32) (*credentialChannel, error) {
	if err := protectedPath(filepath.Dir(path), true); err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != pin.UID || st.Gid != socketGID || st.Mode&07777 != socketMode {
		return nil, failure(api.CodeUnavailable, "credential owner endpoint is not installed with its private mode")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, failure(api.CodeUnavailable, "credential owner endpoint is unavailable")
	}
	conn := connection.(*net.UnixConn)
	peer, err := pinPeer(conn, pin.UID, pin.GID)
	if err != nil {
		conn.Close()
		return nil, err
	}
	channel := &credentialChannel{connection: conn, peer: peer, pin: pin, binding: b, boot: boot, socket: filepath.Base(path)}
	channel.generation, err = processGeneration(int(peer.credentials.Pid), boot)
	if err != nil || channel.generation == "" {
		channel.Close()
		return nil, failure(api.CodeUnauthenticated, "credential peer lifetime is unavailable")
	}
	membership, err := cgroupMembership(int(peer.credentials.Pid))
	if err != nil || membership != pin.Cgroup || membership == "" {
		channel.Close()
		return nil, failure(api.CodeUnauthenticated, "credential owner is outside its installed containment")
	}
	executable, err := os.Open("/proc/" + strconv.Itoa(int(peer.credentials.Pid)) + "/exe")
	if err != nil {
		channel.Close()
		return nil, failure(api.CodeUnauthenticated, "credential owner executable is unavailable")
	}
	verifyErr := verifyExecutableFile(executable, api.ReleaseArtifact{OS: "linux", Arch: runtime.GOARCH, Bytes: pin.Bytes, SHA256: pin.Executable.SHA256})
	closeErr := executable.Close()
	if verifyErr != nil || closeErr != nil {
		channel.Close()
		return nil, failure(api.CodeUnauthenticated, "credential owner executable differs from its protected pin")
	}
	return channel, nil
}

func readCredentialFrame(connection *net.UnixConn, expected unix.Ucred, alive func() error) ([]byte, []*os.File, error) {
	data, files, _, err := readCredentialStream(connection, expected, alive)
	return data, files, err
}

// Each fragment is recvmsg with atomic CLOEXEC. Every accepted duplicate is
// owned immediately and is closed even if another control/fragment is refused.
// A read that returns no bytes is the peer's end of stream, not a fragment: with
// SO_PASSCRED Linux still attaches SCM_CREDENTIALS to it from a zeroed cookie
// (pid, uid and gid 0; box 68), which names no writer. That end is refused as a
// close before any credential comparison; every fragment that carries bytes is
// still compared with the pinned connector. ended reports a close between frames
// seen by this read itself, never an error returned by alive.
func readCredentialStream(connection *net.UnixConn, expected unix.Ucred, alive func() error) (_ []byte, files []*os.File, ended bool, resultErr error) {
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, closeCredentialFiles(files))
			files = nil
		}
	}()
	started := false
	readExact := func(data []byte) error {
		for len(data) > 0 {
			oob := make([]byte, unix.CmsgSpace(64*4)+unix.CmsgSpace(unix.SizeofUcred))
			var n, control, flags int
			var receiveErr error
			raw, err := connection.SyscallConn()
			if err != nil {
				return failure(api.CodeUnavailable, "credential channel is closed")
			}
			err = raw.Read(func(fd uintptr) bool {
				n, control, flags, _, receiveErr = unix.Recvmsg(int(fd), data, oob, unix.MSG_CMSG_CLOEXEC)
				return !errors.Is(receiveErr, unix.EAGAIN) && !errors.Is(receiveErr, unix.EWOULDBLOCK)
			})
			messages, parseErr := unix.ParseSocketControlMessage(oob[:control])
			valid, unknown := false, false
			peer := "" // which peer credential fields differ (names only), for the refusal below
			for _, message := range messages {
				switch {
				case message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS:
					rights, err := unix.ParseUnixRights(&message)
					if err != nil {
						unknown = true
					}
					for _, fd := range rights {
						files = append(files, os.NewFile(uintptr(fd), "received-private-credential"))
					}
				case message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_CREDENTIALS:
					cred, err := unix.ParseUnixCredentials(&message)
					if err == nil && *cred != expected {
						for _, f := range []struct {
							name string
							same bool
						}{{"pid", cred.Pid == expected.Pid}, {"uid", cred.Uid == expected.Uid}, {"gid", cred.Gid == expected.Gid}} {
							if !f.same {
								peer += " " + f.name
							}
						}
						if credentialOwnerDetail {
							// E2E stand-in build only: the numeric peer identities (not secrets) to find the sender.
							peer += fmt.Sprintf(" got=%d/%d/%d want=%d/%d/%d", cred.Pid, cred.Uid, cred.Gid, expected.Pid, expected.Uid, expected.Gid)
						}
					}
					if err != nil || valid || *cred != expected {
						unknown = true
					} else {
						valid = true
					}
				default:
					unknown = true
				}
			}
			if err == nil && receiveErr == nil && n == 0 {
				if !started {
					ended = true
					return failure(api.CodeUnavailable, "credential frame peer closed its stream")
				}
				return failure(api.CodeUnauthenticated, "credential ancillary count, writer or framing was refused (closed)")
			}
			// Same refusal, now naming the failed condition (item 1 diagnosis, box 63).
			for _, c := range []struct {
				name string
				bad  bool
			}{
				{"recv" + recvClass(err, receiveErr), err != nil || receiveErr != nil}, {"parse", parseErr != nil}, {"peer_mismatch" + peer, peer != ""},
				{"unknown_control", unknown}, {"no_peer_credentials", !valid}, {"truncated", flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0},
				{"too_many_files", len(files) > 64}, {"short_read", n <= 0 || n > len(data)},
			} {
				if c.bad {
					return failure(api.CodeUnauthenticated, "credential ancillary count, writer or framing was refused ("+c.name+")")
				}
			}
			if alive != nil {
				if err := alive(); err != nil {
					return err
				}
			}
			data = data[n:]
			started = true
		}
		return nil
	}
	var header [4]byte
	if err := readExact(header[:]); err != nil {
		return nil, files, ended, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > api.MaxFrameBytes {
		return nil, files, false, failure(api.CodeInvalid, "credential control frame exceeds its bound")
	}
	data := make([]byte, int(size))
	if err := readExact(data); err != nil {
		return nil, files, false, err
	}
	return data, files, false, nil
}

func (c *credentialChannel) call(ctx context.Context, method string, params, result any, send []*os.File, receive bool) ([]*os.File, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.Alive(ctx); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	nonce, err := randomID("credential-call-")
	if err != nil {
		return nil, err
	}
	body, err := EncodeWire(params)
	if err != nil {
		return nil, failure(api.CodeInvalid, "cannot encode private credential metadata")
	}
	request := helperRequest{Protocol: credentialProtocol, Revision: api.ContractRevision, Config: c.binding.Config, Generation: c.binding.Generation, ArtifactSHA256: c.binding.Artifact.SHA256, Nonce: nonce, Method: method, Params: body}
	if attempt, ok := api.EffectLeaseFromContext(ctx); ok {
		request.Attempt = &attempt
	}
	return c.exchange(ctx, request, result, send, receive, deadline, func() error { return c.Alive(ctx) })
}

// The caller owns mu. Unknown stream state consumes the connection. A fully
// correlated refusal with no descriptors leaves it synchronized for reuse.
func (c *credentialChannel) exchange(ctx context.Context, request helperRequest, result any, send []*os.File, receive bool, deadline time.Time, alive func() error) (_ []*os.File, resultErr error) {
	encoded, err := EncodeWire(request)
	if err != nil {
		return nil, err
	}
	data, err := frame(encoded)
	if err != nil {
		return nil, err
	}
	resume := lendCredentialOperation(ctx, c.operationMu)
	defer resume()
	finishTrace := traceCredWait("exchange")
	defer finishTrace()
	streamKnown := false
	defer func() {
		if resultErr != nil && !streamKnown {
			resultErr = errors.Join(resultErr, c.connection.Close())
		}
	}()
	if err := c.connection.SetDeadline(deadline); err != nil {
		return nil, failure(api.CodeUnavailable, "cannot bound credential control")
	}
	interrupted := make(chan struct{})
	var interruptErr error
	stop := context.AfterFunc(ctx, func() {
		interruptErr = c.connection.SetDeadline(time.Now())
		close(interrupted)
	})
	defer func() {
		if !stop() {
			// Finish interruption before releasing the shared-channel mutex.
			// A late callback cannot poison the next exchange's deadline.
			<-interrupted
			if interruptErr != nil {
				streamKnown = false
				resultErr = errors.Join(resultErr, interruptErr)
			}
		}
	}()
	if len(send) > 0 {
		rights := make([]int, len(send))
		for i, f := range send {
			if f == nil {
				return nil, failure(api.CodeIntegrity, "credential export descriptor is absent")
			}
			rights[i] = int(f.Fd())
		}
		n, oob, err := c.connection.WriteMsgUnix(data, unix.UnixRights(rights...), nil)
		if err != nil || n != len(data) || oob != len(unix.UnixRights(rights...)) {
			return nil, failure(api.CodeContainmentUnknown, "credential export acknowledgement is uncertain")
		}
	} else if err := writeFrame(c.connection, request); err != nil {
		return nil, err
	}
	reply, files, err := readCredentialFrame(c.connection, c.peer.credentials, alive)
	if err != nil {
		return nil, err
	}
	var response credentialResponse
	if decodeStrict(reply, &response) != nil || response.Protocol != credentialProtocol || response.Revision != api.ContractRevision || response.Nonce != request.Nonce || (response.Error == nil) == (len(response.Result) == 0) || (!receive || response.Error != nil) && len(files) != 0 {
		closeErr := closeCredentialFiles(files)
		return nil, errors.Join(failure(api.CodeUnauthenticated, "credential owner reply or descriptor disposition differs"), closeErr)
	}
	if response.Error != nil {
		streamKnown = true
		refusal := &api.Error{Code: response.Error.Code, Owner: response.Error.Owner, Message: "native credential owner refused private control", Retryable: response.Error.Retryable}
		component := owner
		switch c.socket {
		case "credential-broker.sock":
			component = "lb-v2-secrets"
		case "credential-identity.sock":
			component = "lb-v2-identity"
		}
		return nil, ownInvalid(refusal, component)
	}
	if err := decodeReply(response.Result, result); err != nil {
		return nil, errors.Join(err, closeCredentialFiles(files))
	}
	return files, nil
}

type nativeCredentialBroker struct{ channel *credentialChannel }
type nativeCredentialIdentity struct{ channel *credentialChannel }

func (r *credentialRuntime) checkBinding(ctx context.Context) error {
	broker, bok := r.broker.(*nativeCredentialBroker)
	identity, iok := r.identity.(*nativeCredentialIdentity)
	if !bok || !iok || broker == nil || identity == nil || broker.channel == nil || identity.channel == nil || broker.channel == identity.channel || r.manager == nil || r.peer != broker.channel {
		return failure(api.CodeIntegrity, "credential attachment requires the original native channels")
	}
	for _, channel := range []*credentialChannel{broker.channel, identity.channel} {
		if channel.binding.Config != r.manager.binding.Config || channel.binding.Generation != r.manager.binding.Generation || channel.binding.Artifact != r.manager.binding.Artifact || channel.boot != r.manager.bootID {
			return failure(api.CodeIntegrity, "credential attachment changed its installed helper")
		}
		if err := channel.Alive(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (b *nativeCredentialBroker) TransferCredentials(ctx context.Context, peer api.VerifiedPeer, request api.CredentialProjectionRequest) (api.CredentialTransfer, error) {
	if err := peer.Alive(ctx); err != nil {
		return api.CredentialTransfer{}, err
	}
	var result api.CredentialTransfer
	files, err := b.channel.call(ctx, "transfer", request, &result, nil, true)
	result.Files = files
	return result, err
}
func (b *nativeCredentialBroker) AcknowledgeCredentials(ctx context.Context, q api.CredentialProjectionReceipt) (api.CredentialProjectionRecord, error) {
	var r api.CredentialProjectionRecord
	_, err := b.channel.call(ctx, "acknowledge", q, &r, nil, false)
	return r, err
}
func (b *nativeCredentialBroker) BeginCredentialWithdrawal(ctx context.Context, q api.CredentialWithdrawalRequest) (api.CredentialProjectionRecord, error) {
	var r api.CredentialProjectionRecord
	_, err := b.channel.call(ctx, "begin_withdrawal", q, &r, nil, false)
	return r, err
}
func (b *nativeCredentialBroker) FinishCredentialWithdrawal(ctx context.Context, q api.CredentialProjectionRecord, r api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error) {
	var result api.CredentialProjectionRecord
	_, err := b.channel.call(ctx, "finish_withdrawal", struct {
		Record  api.CredentialProjectionRecord
		Receipt api.CredentialWithdrawalReceipt
		Scan    *rscan.NativeReleaseScan `json:",omitempty"`
	}{q, r, rscan.NativeReleaseScanFromContext(ctx)}, &result, nil, false)
	return result, err
}
func (b *nativeCredentialBroker) AcceptCredentialRefresh(ctx context.Context, peer api.VerifiedPeer, q api.CredentialRefresh) (api.CredentialSourceVersion, error) {
	var r api.CredentialSourceVersion
	if err := peer.Alive(ctx); err != nil {
		return r, err
	}
	_, err := b.channel.call(ctx, "refresh", q, &r, []*os.File{q.File}, false)
	return r, err
}
func (i *nativeCredentialIdentity) AuthorizeCredentialProjection(ctx context.Context, peer api.VerifiedPeer, q api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	var r api.CredentialProjectionAuthority
	facts, err := peer.Facts(ctx)
	if err != nil {
		return r, err
	}
	_, err = i.channel.call(ctx, "authorize", struct {
		Peer    api.PeerFacts
		Request api.CredentialProjectionRequest
	}{facts, q}, &r, nil, false)
	return r, err
}
func (i *nativeCredentialIdentity) CheckLaunchCredentials(ctx context.Context, q api.LaunchBindingRequest) (api.CredentialProjectionRecord, error) {
	var r api.CredentialProjectionRecord
	_, err := i.channel.call(ctx, "check_launch", q, &r, nil, false)
	return r, err
}

type nativeCredentialGuard struct {
	channel  *credentialChannel
	record   api.CredentialProjectionRecord
	context  context.Context
	mu       sync.Mutex
	closed   bool
	closeErr error
}

func (g *nativeCredentialGuard) Projection() api.CredentialProjectionRecord { return g.record }
func (g *nativeCredentialGuard) Check(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return failure(api.CodeForbidden, "native credential guard is already closed")
	}
	var r api.CredentialProjectionRecord
	_, err := g.channel.call(ctx, "guard_check", api.Empty{}, &r, nil, false)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(g.record, r) {
		return failure(api.CodeForbidden, "live credential guard changed its projection")
	}
	return nil
}
func (g *nativeCredentialGuard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return g.closeErr
	}
	g.closed = true
	parent := g.context
	if parent == nil {
		parent = context.Background()
	}
	// Retain the helper lock-lending context, even if the open's caller has
	// ended. EOF alone does not establish that the broker stopped its checks.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer cancel()
	var result api.Empty
	_, err := g.channel.call(ctx, "guard_close", api.Empty{}, &result, nil, false)
	g.closeErr = errors.Join(err, g.channel.Close())
	return g.closeErr
}
func (b *nativeCredentialBroker) LockCredentialProjection(ctx context.Context, q api.CredentialGateRequest) (api.CredentialGateGuard, error) {
	c, err := openCredentialChannel(ctx, b.channel.binding, b.channel.boot, b.channel.socket, b.channel.pin)
	if err != nil {
		return nil, err
	}
	c.operationMu = b.channel.operationMu
	var r api.CredentialProjectionRecord
	_, err = c.call(ctx, "guard_lock", q, &r, nil, false)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &nativeCredentialGuard{channel: c, record: r, context: ctx}, nil
}

func (m *leaseManager) bindCredentials(ctx context.Context) credentialBindingResult {
	if m.credentialBindAttempted {
		return credentialBindingResult{Failure: failure(api.CodeConflict, "native credential binding is one-use")}
	}
	if os.Geteuid() != 0 {
		m.credentialBindAttempted = true
		return credentialBindingResult{Failure: failure(api.CodeForbidden, "native credential receiver must be the root helper")}
	}
	path := filepath.Join("/etc/laneboss-v2/credential-peers", m.binding.Config+".json")
	_, absentErr := os.Lstat(path)
	if errors.Is(absentErr, os.ErrNotExist) {
		e := failure(api.CodeUnavailable, "protected native credential peers are not installed")
		e.Retryable = true
		return credentialBindingResult{Unbound: m.credentials == nil, Failure: e}
	}
	m.credentialBindAttempted = true
	data, err := readProtected(path, api.MaxFrameBytes)
	if err != nil {
		return credentialBindingResult{Failure: failure(api.CodeIntegrity, "protected native credential peers are invalid or unreadable")}
	}
	var pins credentialPeerCatalog
	if decodeStrict(data, &pins) != nil || pins.Schema != "laneboss.credential-peers.v2" || pins.Config != m.binding.Config || pins.Generation != m.binding.Generation || pins.Broker.UID == 0 || pins.Broker.UID == m.binding.Service.UID || pins.Identity.UID != m.binding.Service.UID || pins.Identity.GID != m.binding.Service.GID || !validID(pins.Broker.ContainmentID) {
		return credentialBindingResult{Failure: failure(api.CodeIntegrity, "native credential peer pins differ from this installation")}
	}
	for _, pin := range []credentialPeerPin{pins.Broker, pins.Identity} {
		if !validID(pin.Executable.ID) || !validDigest(pin.Executable.SHA256) || pin.Executable.Version == "" || pin.Bytes <= 0 || pin.Bytes > 1<<30 || !validID(pin.ContainmentID) || pin.Cgroup == "" || pin.Cgroup == "/" || filepath.Clean(pin.Cgroup) != pin.Cgroup || !filepath.IsAbs(pin.Cgroup) {
			return credentialBindingResult{Failure: failure(api.CodeIntegrity, "credential owner pin is incomplete")}
		}
	}
	for _, account := range m.binding.Lanes {
		if account.UID == pins.Broker.UID {
			return credentialBindingResult{Failure: failure(api.CodeIntegrity, "credential broker must be outside the lane UID pool")}
		}
	}
	for _, owner := range []struct {
		source, name string
		pin          credentialPeerPin
	}{
		{filepath.Join(m.binding.credentialRuntimePath(), "owners", "broker", "credential-broker.sock"), "credential-broker.sock", pins.Broker},
		{filepath.Join(m.binding.credentialRuntimePath(), "owners", "identity", "credential-identity.sock"), "credential-identity.sock", pins.Identity},
	} {
		target := filepath.Join(m.binding.credentialRuntimePath(), owner.name)
		if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
			if err := publishCredentialOwner(m.binding, owner.source, target, owner.pin); err != nil {
				return credentialBindingResult{Failure: failure(api.CodeUnavailable, "native credential listener is not ready for protected publication")}
			}
		}
	}
	component := filepath.Join(m.binding.credentialRuntimePath(), "component.sock")
	if _, err := os.Lstat(component); errors.Is(err, os.ErrNotExist) {
		if err := publishCredentialOwner(m.binding, filepath.Join(m.binding.credentialRuntimePath(), "owners", "identity", "credential-component.sock"), component, pins.Identity); err != nil {
			return credentialBindingResult{Failure: failure(api.CodeUnavailable, "credential metadata listener is not ready for protected publication")}
		}
		if err := errors.Join(os.Chown(component, int(pins.Identity.UID), int(pins.Broker.GID)), os.Chmod(component, 0660)); err != nil {
			return credentialBindingResult{Failure: failure(api.CodeIntegrity, "credential metadata publication mode failed")}
		}
	}
	broker, err := openCredentialChannel(ctx, m.binding, m.bootID, "credential-broker.sock", pins.Broker)
	if err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) {
			typed = failure(api.CodeIntegrity, "credential broker binding failed")
		}
		return credentialBindingResult{Failure: typed}
	}
	identity, err := openCredentialChannel(ctx, m.binding, m.bootID, "credential-identity.sock", pins.Identity)
	if err != nil {
		broker.Close()
		var typed *api.Error
		if !errors.As(err, &typed) {
			typed = failure(api.CodeIntegrity, "credential identity binding failed")
		}
		return credentialBindingResult{Failure: typed}
	}
	broker.operationMu, identity.operationMu = &m.operationMu, &m.operationMu
	m.credentials = &credentialRuntime{manager: m, broker: &nativeCredentialBroker{broker}, identity: &nativeCredentialIdentity{identity}, peer: broker, held: map[api.ID]*heldCredentials{}}
	return credentialBindingResult{Bound: true}
}

// recvClass names a receive failure's class (errno or timeout), never its text.
func recvClass(errs ...error) string {
	for _, err := range errs {
		switch {
		case err == nil:
		case errors.Is(err, os.ErrDeadlineExceeded):
			return " deadline"
		case errors.Is(err, net.ErrClosed):
			return " closed"
		case errors.Is(err, unix.ECONNRESET):
			return " reset"
		case errors.Is(err, unix.EPIPE):
			return " pipe"
		case errors.Is(err, unix.EBADF):
			return " badf"
		default:
			var errno unix.Errno
			if errors.As(err, &errno) {
				return " errno_" + unix.ErrnoName(errno)
			}
			return " other"
		}
	}
	return ""
}
