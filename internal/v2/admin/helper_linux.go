//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func closePeer(peer *pinnedPeer) { unix.Close(peer.pidfd) }

func runPlatformHelper(parent context.Context, config string) (resultErr error) {
	if err := verifyHelperIDs(os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid()); err != nil {
		return err
	}
	b, err := loadInstallation(config)
	if err != nil {
		return err
	}
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return failure(api.CodeIntegrity, "cannot pin the running helper artifact")
	}
	verifyErr := sameInstalledExecutable(self, b)
	closeErr := self.Close()
	if verifyErr != nil {
		return verifyErr
	}
	if closeErr != nil {
		return failure(api.CodeIntegrity, "cannot close running helper artifact verification")
	}
	membership, err := cgroupMembership(os.Getpid())
	if err != nil {
		return err
	}
	if membership != "/system.slice/laneboss-helper@"+config+".service" {
		return failure(api.CodeForbidden, "helper must be started by its fixed administrator-installed systemd unit")
	}
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || nnp != 1 {
		return failure(api.CodePrerequisite, "helper unit must set NoNewPrivileges before starting")
	}
	if err := helperBeforeAccounts(os.Stderr, readProcessSetUID, readHelperUIDs); err != nil {
		return err
	}
	if err := checkAccount(b.Service); err != nil {
		return err
	}
	for _, a := range b.Lanes {
		if err := checkAccount(a); err != nil {
			return err
		}
	}
	if err := json.NewEncoder(os.Stderr).Encode(map[string]string{"stage": "helper.after_accounts", "observation": nativeMainCapabilityFacts()}); err != nil {
		return failure(api.CodeUnavailable, "cannot retain helper account capability observation")
	}
	if err := privateDirectory(b.statePath(), 0, 0700); err != nil {
		return err
	}
	if err := privateDirectory(b.runtimePath(), b.Service.GID, 0750); err != nil {
		return err
	}
	stateRoot, err := os.OpenRoot(b.statePath())
	if err != nil {
		return failure(api.CodePrerequisite, "cannot pin the administrator lease store")
	}
	defer stateRoot.Close()
	lock, err := stateRoot.OpenFile("lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return failure(api.CodeIntegrity, "cannot open helper process lock")
	}
	defer lock.Close()
	var lockStat unix.Stat_t
	if err := unix.Fstat(int(lock.Fd()), &lockStat); err != nil || lockStat.Uid != 0 ||
		lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Mode&0777 != 0600 || lockStat.Nlink != 1 {
		return failure(api.CodeIntegrity, "unsafe helper process lock")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return failure(api.CodeConflict, "another helper owns the installed lease store")
	}
	closeProc, err := mountHelperProc(b.runtimePath())
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closeProc()) }()
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(strings.TrimSpace(string(boot))) != 36 {
		return failure(api.CodePrerequisite, "cannot bind helper leases to the actual kernel boot")
	}
	manager := newLeaseManager(b, strings.TrimSpace(string(boot)),
		&fileLeaseStore{root: stateRoot}, &linuxResources{binding: b})
	manager.storeLock = lock
	manager.resources.(*linuxResources).manager = manager
	if _, err := manager.records(); err != nil {
		return err
	}
	if err := manager.recoverNetworks(parent); err != nil {
		return err
	}
	if err := setupCgroups(b); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(parent, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := recoverHelperSocket(ctx, b); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: b.socketPath(), Net: "unix"})
	if err != nil {
		return failure(api.CodeConflict, "helper endpoint already exists or cannot bind; preserve it for administrator inspection")
	}
	defer listener.Close()
	listener.SetUnlinkOnClose(true)
	listenerRaw, err := listener.SyscallConn()
	if err != nil {
		return failure(api.CodeIntegrity, "cannot protect helper listener")
	}
	var optionErr error
	if err := listenerRaw.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
	}); err != nil || optionErr != nil {
		return failure(api.CodePrerequisite, "cannot enable native helper message credentials")
	}
	if err := os.Chown(b.socketPath(), 0, int(b.Service.GID)); err != nil {
		return failure(api.CodeIntegrity, "cannot bind helper endpoint group")
	}
	if err := os.Chmod(b.socketPath(), 0660); err != nil {
		return failure(api.CodeIntegrity, "cannot protect helper endpoint mode")
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	closeMetadata, err := startCredentialMetadata(ctx, b, manager)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closeMetadata()) }()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return failure(api.CodeUnavailable, "helper listener failed")
		}
		// Serialize helper operations under the process/store lock. A bounded
		// request cannot race another allocation or UID release.
		if err := serveHelperConnection(ctx, connection, b, manager); errors.Is(err, errHelperJournal) {
			return failure(api.CodeUnavailable, "cannot retain helper request journal")
		}
	}
}

func verifyHelperIDs(uid, euid, gid, egid int) error {
	if uid != euid || gid != egid {
		return failure(api.CodeForbidden, "setuid or setgid helper invocation is refused")
	}
	if uid != 0 || euid != 0 || gid != 0 || egid != 0 {
		return failure(api.CodeForbidden, "helper mode requires the administrator-started root unit")
	}
	return nil
}

func privateDirectory(path string, gid uint32, mode uint32) error {
	if err := protectedPath(path, true); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil || st.Uid != 0 || st.Gid != gid || st.Mode&0777 != mode {
		return failure(api.CodeIntegrity, "installed helper directory ownership or mode differs")
	}
	return nil
}

func serveHelperConnection(parent context.Context, connection *net.UnixConn, b installation, manager *leaseManager, metadataOnly ...bool) error {
	return serveHelperConnectionWithJournal(parent, connection, b, manager, os.Stderr, metadataOnly...)
}

func serveHelperConnectionWithJournal(parent context.Context, connection *net.UnixConn, b installation, manager *leaseManager, journal io.Writer, metadataOnly ...bool) (resultErr error) {
	trace := &helperRequestTrace{method: "unknown", check: "transport_window", timing: journal}
	trace.stage("transport_window")
	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, api.WithHelperReason(closeErr, "connection_close"))
		}
		resultErr = api.WithHelperReason(resultErr, trace.check)
		trace.finishTiming()
		if err := trace.write(journal, resultErr); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	return serveHelperRequest(parent, connection, b, manager, trace, metadataOnly...)
}

func serveHelperRequest(parent context.Context, connection *net.UnixConn, b installation, manager *leaseManager, trace *helperRequestTrace, metadataOnly ...bool) error {
	window, err := openHelperWindow(parent, connection, helperWorkTimeout, helperReplyTimeout)
	if err != nil {
		return err
	}
	defer window.finish()
	ctx := window.work
	nonce := api.ID("")
	replyError := func(err error) error {
		return window.refuse(helperProtocol, nonce, api.WithHelperReason(err, trace.check))
	}
	trace.stage("caller_identity")
	rootCaller, err := helperRootCaller(connection)
	if err != nil {
		return replyError(err)
	}
	uid, gid := b.Service.UID, b.Service.GID
	if rootCaller {
		uid, gid = 0, 0
	}
	peer, err := pinPeer(connection, uid, gid)
	if err != nil {
		return replyError(err)
	}
	defer closePeer(peer)
	verifyCaller := func() error {
		if rootCaller {
			return peer.verifyEnrollmentHelper(b)
		}
		return peer.verifyService(b)
	}
	trace.stage("caller_containment")
	if err := verifyCaller(); err != nil {
		return replyError(err)
	}
	trace.stage("request_frame")
	data, err := readUnixFrame(connection, peer)
	if err != nil {
		return replyError(err)
	}
	var request helperRequest
	trace.stage("request_decode")
	if err := decodeStrict(data, &request); err != nil {
		return replyError(err)
	}
	nonce = request.Nonce
	trace.method = helperMethod(request.Method)
	ctx = context.WithValue(ctx, helperTimingKey{}, trace)
	trace.stage("request_binding")
	if !validID(nonce) || len(nonce) < 32 || request.Protocol != helperProtocol || request.Revision != api.ContractRevision || request.Config != b.Config ||
		request.Generation != b.Generation || request.ArtifactSHA256 != b.Artifact.SHA256 {
		return replyError(failure(api.CodeVersion, "helper request does not match its installed binding"))
	}
	trace.nonce, trace.caller = nonce, int(peer.credentials.Pid)
	trace.stage("caller_role")
	if err := enrollmentCaller(rootCaller, request.Method); err != nil {
		return replyError(err)
	}
	trace.stage("installation")
	current, err := loadInstallation(b.Config)
	if err != nil {
		return replyError(err)
	}
	if current.Artifact != b.Artifact || current.Generation != b.Generation {
		return replyError(failure(api.CodeVersion, "helper installation changed; restart the coherent deployment"))
	}
	trace.stage("caller_containment")
	if err := verifyCaller(); err != nil {
		return replyError(err)
	}
	trace.stage("cancellation")
	if err := contextError(ctx); err != nil {
		return replyError(err)
	}
	metadata := len(metadataOnly) == 1 && metadataOnly[0]
	if metadata && !credentialMetadataMethod(request.Method) {
		return replyError(failure(api.CodeForbidden, "credential metadata endpoint refuses state-changing operations"))
	}
	trace.stage("operation_wait")
	ctx, finishTurn, err := manager.beginHelperTurn(ctx, metadata, request.Method, request.Params, trace.timing)
	if err != nil {
		return replyError(err)
	}
	defer finishTurn()
	if request.Attempt != nil {
		attempt := *request.Attempt
		if !api.EffectLeaseClaimed(attempt) || attempt.ClaimID != attempt.Record.ClaimID || attempt.ExpiresAt != attempt.Record.ClaimExpiresAt || attempt.Record.Effect.Context == nil || attempt.Record.Effect.Context.Config != b.Config {
			return replyError(failure(api.CodeForbidden, "native helper received an invalid explicit effect attempt"))
		}
		ctx = api.WithEffectLease(ctx, attempt)
	}
	if request.Method == "worker_launch" {
		trace.stage("operation")
		return manager.serveWorkerLaunch(ctx, connection, peer, request, window, verifyCaller, trace)
	}
	var result any
	trace.stage("operation_input")
	if rootCaller {
		result, err = forwardEnrollment(ctx, b, request.Params)
		if err != nil {
			return replyError(err)
		}
	} else if request.Method == "runner_prompt" {
		var input runnerPromptRequest
		if err := decodeStrict(request.Params, &input); err != nil {
			return replyError(err)
		}
		result, err = manager.receiveRunnerPrompt(ctx, input, func() ([]byte, error) { return readUnixFrame(connection, peer) })
		if err != nil {
			return replyError(err)
		}
	} else if request.Method == "isolation_evidence" {
		var runtime api.BlobRef
		if err := decodeStrict(request.Params, &runtime); err != nil {
			return replyError(err)
		}
		result, err = manager.measureIsolation(ctx, runtime)
		if err != nil {
			return replyError(err)
		}
	} else if request.Method == "probe" {
		var empty api.Empty
		if err := decodeStrict(request.Params, &empty); err != nil {
			return replyError(err)
		}
		result = probeResult{Capabilities: probeAdmin(ctx, b, manager)}
	} else {
		result, err = manager.dispatch(ctx, request.Method, request.Params)
		if err != nil {
			return replyError(err)
		}
	}
	trace.stage("peer_lifetime")
	if err := peer.alive(); err != nil {
		return replyError(err)
	}
	if rootCaller {
		trace.stage("caller_containment")
		if err := verifyCaller(); err != nil {
			return replyError(err)
		}
	}
	trace.stage("cancellation")
	if err := contextError(ctx); err != nil {
		return replyError(err)
	}
	trace.stage("response_encode")
	encoded, err := EncodeWire(result)
	if err != nil {
		return replyError(failure(api.CodeIntegrity, "cannot encode helper operation result"))
	}
	response := helperResponse{Protocol: helperProtocol, Revision: api.ContractRevision, Nonce: nonce, Result: encoded}
	if request.Method == "containment_live" {
		// The operation lock still protects the validated state. Queue wait
		// precedes this observation and cannot consume its sharing lifetime.
		response.Observed, err = containmentNow()
		if err != nil {
			return replyError(err)
		}
	}
	// Validate the complete envelope before writing any transport bytes, so
	// a malformed/oversize RawMessage becomes a correlated typed refusal.
	if _, err := encodeHelperFrame(response); err != nil {
		return replyError(err)
	}
	trace.stage("reply_transport")
	return window.write(response)
}
