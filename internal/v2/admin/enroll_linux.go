//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// The service owns this lifecycle and must propagate its returned error. The
// optional installation field alone never starts or advertises a ceremony.
func (s *Service) ServeEnrollment(ctx context.Context, endpoint api.AdminEnrollmentEndpoint) error {
	if err := validateEnrollmentEndpoint(endpoint, s.binding); err != nil {
		return err
	}
	human, err := readEnrollmentHumanBinding(s.deps.BindingFile, endpoint, s.binding)
	if err != nil {
		return err
	}
	if err := verifyEnrollmentServiceIDs(s.binding); err != nil {
		return err
	}
	if nilEnrollmentPort(s.deps.Store) {
		return api.NotImplemented("lb-v2-service", "protected human credential inventory")
	}
	if err := api.CheckHumanEnrollmentPolicy(ctx, s.deps.Store, endpoint.Config); err != nil {
		return err
	}
	if err := enrollmentDirectory(filepath.Dir(endpoint.Socket), s.binding.Service); err != nil {
		return err
	}
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return failure(api.CodeIntegrity, "cannot pin enrollment service executable")
	}
	verifyErr := sameInstalledExecutable(self, s.binding)
	closeErr := self.Close()
	if verifyErr != nil {
		return verifyErr
	}
	if closeErr != nil {
		return failure(api.CodeIntegrity, "cannot close enrollment service artifact check")
	}
	s.enrollmentMu.Lock()
	if s.enrollment == nil || s.enrollmentServing {
		s.enrollmentMu.Unlock()
		return failure(api.CodeConflict, "enrollment must be bound once and have one listener")
	}
	target := s.enrollment
	s.enrollmentServing = true
	s.enrollmentMu.Unlock()
	defer func() { s.enrollmentMu.Lock(); s.enrollmentServing = false; s.enrollmentMu.Unlock() }()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint.Socket, Net: "unix"})
	if err != nil {
		return failure(api.CodeConflict, "administrator enrollment socket exists or cannot bind; preserve it for inspection")
	}
	defer listener.Close()
	listener.SetUnlinkOnClose(true)
	raw, err := listener.SyscallConn()
	if err != nil {
		return failure(api.CodeIntegrity, "cannot pin administrator enrollment listener")
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || optionErr != nil {
		return failure(api.CodePrerequisite, "administrator enrollment requires per-message native credentials")
	}
	if err := os.Chmod(endpoint.Socket, 0600); err != nil {
		return failure(api.CodeIntegrity, "cannot protect administrator enrollment socket")
	}
	if err := checkEnrollmentSocket(endpoint.Socket, s.binding.Service); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return contextError(ctx)
			}
			return failure(api.CodeUnavailable, "administrator enrollment listener ended unexpectedly")
		}
		// One bounded message per native connection. Requests are serialized;
		// the configuration-wide baseline still belongs to the store lock.
		requestErr := s.serveEnrollmentConnection(ctx, connection, endpoint, human, target)
		closeErr := connection.Close()
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return failure(api.CodeUnavailable, "cannot close administrator enrollment connection")
		}
		if requestErr != nil {
			var typed *api.Error
			if !errors.As(requestErr, &typed) {
				return failure(api.CodeIntegrity, "administrator enrollment failed without a typed refusal")
			}
			// Refusals are sent to that administrator; no registration bytes,
			// native paths, process arguments or credential material are logged.
		}
	}
}

func verifyEnrollmentServiceIDs(binding installation) error {
	if uint32(os.Getuid()) != binding.Service.UID || uint32(os.Geteuid()) != binding.Service.UID ||
		uint32(os.Getgid()) != binding.Service.GID || uint32(os.Getegid()) != binding.Service.GID || binding.Service.UID == 0 {
		return failure(api.CodeForbidden, "administrator enrollment listener requires the dedicated unprivileged service")
	}
	return nil
}

// The final directory belongs exclusively to the installed service, outside
// the lane pool's reach. No lane-writable ancestor or symlink is accepted.
func enrollmentDirectory(path string, service account) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return failure(api.CodeIntegrity, "invalid administrator enrollment directory")
	}
	for current := path; ; current = filepath.Dir(current) {
		var st unix.Stat_t
		if unix.Lstat(current, &st) != nil {
			return failure(api.CodeIntegrity, "administrator enrollment directory cannot be observed")
		}
		if err := checkEnrollmentDirectoryStat(st, service, current == path); err != nil {
			return failure(api.CodeIntegrity, "administrator enrollment directory has an untrusted owner, link or shared access")
		}
		if current == "/" {
			return nil
		}
	}
}

func checkEnrollmentDirectoryStat(st unix.Stat_t, service account, final bool) error {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != service.UID) || st.Mode&0022 != 0 ||
		final && (st.Uid != service.UID || st.Gid != service.GID || st.Mode&07777 != 0700) {
		return failure(api.CodeIntegrity, "administrator enrollment directory ownership or ACL differs")
	}
	return nil
}

func checkEnrollmentSocket(path string, service account) error {
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		st.Uid != service.UID || st.Gid != service.GID || st.Mode&07777 != 0600 {
		return failure(api.CodeIntegrity, "administrator enrollment socket ownership or ACL differs")
	}
	return nil
}

func (p *pinnedPeer) verifyEnrollmentHelper(binding installation) error {
	if err := p.alive(); err != nil {
		return err
	}
	if p.credentials.Uid != 0 || p.credentials.Gid != 0 {
		return failure(api.CodeForbidden, "administrator enrollment refuses a nonadministrator helper")
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", p.credentials.Pid))
	if err != nil {
		return failure(api.CodeUnauthenticated, "cannot recheck administrator helper identity")
	}
	if err := checkEnrollmentHelperStatus(data); err != nil {
		return err
	}
	file, err := os.Open(fmt.Sprintf("/proc/%d/exe", p.credentials.Pid))
	if err != nil {
		return failure(api.CodeUnauthenticated, "cannot pin administrator helper artifact")
	}
	defer file.Close()
	if err := sameInstalledExecutable(file, binding); err != nil {
		return err
	}
	return p.alive()
}

func checkEnrollmentHelperStatus(data []byte) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key != "Uid" && key != "Gid" {
			continue
		}
		fields := strings.Fields(value)
		if seen[key] || len(fields) != 4 {
			return failure(api.CodeUnauthenticated, "administrator helper identity observation is incomplete")
		}
		for _, field := range fields {
			id, err := strconv.ParseUint(field, 10, 32)
			if err != nil || id != 0 {
				return failure(api.CodeForbidden, "administrator helper has nonroot or setid credentials")
			}
		}
		seen[key] = true
	}
	if !seen["Uid"] || !seen["Gid"] {
		return failure(api.CodeUnauthenticated, "administrator helper identity observation is incomplete")
	}
	return nil
}

func (s *Service) serveEnrollmentConnection(parent context.Context, connection *net.UnixConn, endpoint api.AdminEnrollmentEndpoint, human api.InstalledBinding, target api.AdminEnrollment) error {
	window, err := openHelperWindow(parent, connection, enrollmentWorkTimeout, helperReplyTimeout)
	if err != nil {
		return err
	}
	defer window.finish()
	ctx := window.work
	nonce := api.ID("")
	replyError := func(err error) error { return window.refuse(enrollmentProtocol, nonce, err) }
	peer, err := pinPeer(connection, 0, 0)
	if err != nil {
		return replyError(err)
	}
	defer closePeer(peer)
	native, err := newEnrollmentConnection(ctx, connection, human, endpoint)
	if err != nil {
		return replyError(err)
	}
	defer native.Peer().Close()
	var received api.FrameContext
	verify := func() error {
		if err := peer.alive(); err != nil {
			return err
		}
		if err := native.verify(ctx, endpoint, received); err != nil {
			return err
		}
		current, err := loadInstallation(endpoint.Config)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, s.binding) {
			return failure(api.CodeVersion, "administrator enrollment installation changed")
		}
		if err := validateEnrollmentEndpoint(endpoint, current); err != nil {
			return err
		}
		currentHuman, err := readEnrollmentHumanBinding(s.deps.BindingFile, endpoint, current)
		if err != nil {
			return err
		}
		if currentHuman != human {
			return failure(api.CodeVersion, "installed human endpoint changed during administrator enrollment")
		}
		return checkEnrollmentSocket(endpoint.Socket, current.Service)
	}
	received, err = wire.ReadPinnedFrame(connection, wire.SocketPeer{UID: peer.credentials.Uid, GID: peer.credentials.Gid, PID: int(peer.credentials.Pid)})
	if err != nil {
		return replyError(err)
	}
	var request helperRequest
	if err := decodeStrict(received.Bytes(), &request); err != nil {
		return replyError(err)
	}
	nonce = request.Nonce
	if err := validateEnrollmentEnvelope(request, endpoint); err != nil {
		return replyError(err)
	}
	if err := verify(); err != nil {
		return replyError(err)
	}
	ctx = context.WithValue(ctx, enrollmentChannelKey{}, &enrollmentChannel{endpoint: endpoint, human: human, verify: verify})
	result, err := dispatchEnrollment(ctx, endpoint, request, target, s.deps.Store)
	if err != nil {
		return replyError(err)
	}
	if err := CheckEnrollmentChannel(ctx, endpoint); err != nil {
		return replyError(err)
	}
	encoded, err := EncodeWire(result)
	if err != nil {
		return replyError(failure(api.CodeIntegrity, "cannot encode administrator enrollment response"))
	}
	return window.write(helperResponse{Protocol: enrollmentProtocol, Revision: api.ContractRevision, Nonce: nonce, Result: encoded})
}

func validateEnrollmentEnvelope(request helperRequest, endpoint api.AdminEnrollmentEndpoint) error {
	if request.Protocol != enrollmentProtocol || request.Revision != api.ContractRevision || request.Config != endpoint.Config ||
		request.Generation != endpoint.InstallationGeneration || request.ArtifactSHA256 != endpoint.Helper.SHA256 ||
		!validID(request.Nonce) || len(request.Nonce) < 32 || (request.Method != "enroll_begin" && request.Method != "enroll_complete" && request.Method != "initial_publish" && request.Method != "spend_reconcile") {
		return failure(api.CodeForbidden, "administrator enrollment frame differs from its fixed installed entry")
	}
	return nil
}

func dispatchEnrollment(ctx context.Context, endpoint api.AdminEnrollmentEndpoint, request helperRequest, target api.AdminEnrollment, store api.StateStore) (any, error) {
	if err := CheckEnrollmentChannel(ctx, endpoint); err != nil {
		return nil, err
	}
	channel := ctx.Value(enrollmentChannelKey{}).(*enrollmentChannel)
	if target == nil {
		return nil, failure(api.CodePrerequisite, "administrator enrollment handler is missing")
	}
	switch request.Method {
	case "spend_reconcile":
		var reading api.SpendReading
		if err := decodeStrict(request.Params, &reading); err != nil {
			return nil, err
		}
		bound, err := bindSpendReading(ctx, endpoint, reading)
		if err != nil {
			return nil, err
		}
		reconciler, ok := target.(api.SpendReconciler)
		if !ok {
			return nil, api.NotImplemented("lb-v2-service", "protected spend reconciliation")
		}
		return reconciler.ReconcileSpend(bound, reading)
	case "initial_publish":
		var input InitialRequest
		if err := decodeStrict(request.Params, &input); err != nil {
			return nil, err
		}
		channel.initialRequest = &input
		publisher, ok := target.(InitialPublisher)
		if !ok {
			return nil, api.NotImplemented("lb-v2-service", "protected initial publication entry")
		}
		receipt, err := publisher.PublishInitial(ctx, input)
		if err != nil {
			return nil, err
		}
		if channel.initialReceipt == nil || *channel.initialReceipt != receipt {
			return nil, failure(api.CodeIntegrity, "initial publication lacks a durable read-back receipt")
		}
		return receipt, nil
	case "enroll_begin":
		var input api.EnrollmentCeremonyRequest
		if err := decodeStrict(request.Params, &input); err != nil {
			return nil, err
		}
		if err := validateInitialCeremony(input, endpoint.Config); err != nil {
			return nil, err
		}
		if err := requireEmptyEnrollment(ctx, store, endpoint.Config); err != nil {
			return nil, err
		}
		challenge, err := target.BeginHumanEnrollment(ctx, input)
		if err != nil {
			return nil, err
		}
		if err := api.ValidateEnrollmentChallenge(challenge, input, time.Now()); err != nil {
			return nil, err
		}
		if challenge.Origin != endpoint.Origin || challenge.RPID != endpoint.RPID ||
			challenge.InstallationGeneration != endpoint.InstallationGeneration || challenge.EndpointGeneration != channel.human.EndpointGeneration {
			return nil, failure(api.CodeIntegrity, "administrator create reply differs from the installed endpoint")
		}
		return challenge, nil
	case "enroll_complete":
		var input api.EnrollmentValidationRequest
		if err := decodeStrict(request.Params, &input); err != nil {
			return nil, err
		}
		if err := validateInitialCeremony(input.Ceremony, endpoint.Config); err != nil {
			return nil, err
		}
		if !validID(input.ChallengeID) || len(input.ClientDataJSON) == 0 || len(input.AttestationObject) == 0 {
			return nil, failure(api.CodeInvalid, "administrator complete requires actual registration bytes")
		}
		// The service replays a completed ceremony before revalidating its
		// consumed challenge. A transport inventory precheck here would break
		// lost-reply replay. The commit adapter enforces absence atomically.
		receipt, err := target.CompleteHumanEnrollment(ctx, input)
		if err != nil {
			return nil, err
		}
		if channel.receipt == nil || *channel.receipt != receipt {
			return nil, failure(api.CodeIntegrity, "administrator complete lacks its independently read-back commit")
		}
		return receipt, nil
	}
	return nil, failure(api.CodeForbidden, "administrator endpoint refuses a nonceremony method")
}

func runEnrollment(parent context.Context, config string, options enrollmentOptions) (any, error) {
	if err := verifyHelperIDs(os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid()); err != nil {
		return nil, err
	}
	binding, err := loadInstallation(config)
	if err != nil {
		return nil, err
	}
	installed, err := readEnrollmentInstallation(options.installation, binding)
	if err != nil {
		return nil, err
	}
	endpoint := installed.Endpoint
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, failure(api.CodeIntegrity, "cannot pin administrator enrollment helper")
	}
	verifyErr := sameInstalledExecutable(self, binding)
	closeErr := self.Close()
	if verifyErr != nil {
		return nil, verifyErr
	}
	if closeErr != nil {
		return nil, failure(api.CodeIntegrity, "cannot close administrator helper artifact check")
	}
	method, path := "enroll_begin", options.begin
	if options.complete != "" {
		method, path = "enroll_complete", options.complete
	}
	if options.publish != "" {
		method, path = "initial_publish", options.publish
	}
	if options.spend != "" {
		method, path = "spend_reconcile", options.spend
	}
	input, err := readProtected(path, api.MaxFrameBytes/2)
	if err != nil {
		return nil, err
	}
	var ceremony api.EnrollmentCeremonyRequest
	var initial initialBundle
	if method == "enroll_begin" {
		if err := decodeStrict(input, &ceremony); err != nil {
			return nil, err
		}
	} else if method == "enroll_complete" {
		var request api.EnrollmentValidationRequest
		if err := decodeStrict(input, &request); err != nil {
			return nil, err
		}
		ceremony = request.Ceremony
	} else if method == "initial_publish" {
		var request InitialRequest
		if err := decodeStrict(input, &request); err != nil {
			return nil, err
		}
		initial, err = loadInitialBound(binding, request)
		if err != nil {
			return nil, err
		}
	} else {
		var tool BalanceTool
		if err := decodeStrict(input, &tool); err != nil {
			return nil, err
		}
		reading, err := tool.Reading(parent)
		if err != nil {
			return nil, err
		}
		input, err = json.Marshal(reading)
		if err != nil {
			return nil, failure(api.CodeIntegrity, "cannot encode operator tool reading")
		}
	}
	if method == "enroll_begin" || method == "enroll_complete" {
		if err := validateInitialCeremony(ceremony, config); err != nil {
			return nil, err
		}
	}
	if err := enrollmentDirectory(filepath.Dir(endpoint.Socket), binding.Service); err != nil {
		return nil, err
	}
	if err := checkEnrollmentSocket(endpoint.Socket, binding.Service); err != nil {
		return nil, err
	}
	request, err := newEnrollmentFrame(binding, endpoint, method, input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, enrollmentCallTimeout)
	defer cancel()
	result, err := relayEnrollment(ctx, binding, endpoint, request)
	if err != nil {
		return nil, err
	}
	current, err := loadInstallation(config)
	if err != nil {
		return nil, err
	}
	latest, err := readEnrollmentInstallation(options.installation, current)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(current, binding) || latest != installed {
		return nil, failure(api.CodeVersion, "administrator installation changed during enrollment")
	}
	if method == "spend_reconcile" {
		var balance api.SpendBalance
		if err := decodeStrict(result, &balance); err != nil {
			return nil, err
		}
		var reading api.SpendReading
		if err := decodeStrict(input, &reading); err != nil {
			return nil, err
		}
		if balance.CredentialID != reading.CredentialID || balance.ObservedAt != reading.ObservedAt || balance.FloorMicros != reading.FloorMicros || balance.Generation == 0 {
			return nil, failure(api.CodeIntegrity, "spend reply differs from its operator tool reading")
		}
		return balance, nil
	}
	if method == "initial_publish" {
		var receipt InitialReceipt
		if err := decodeStrict(result, &receipt); err != nil {
			return nil, err
		}
		var request InitialRequest
		if err := decodeStrict(input, &request); err != nil {
			return nil, err
		}
		if receipt.Schema != "laneboss.initial-receipt.v2" || receipt.Config != config || receipt.Manifest != request.Manifest || receipt.Generation != 1 ||
			receipt.ID != initial.manifest.ID || receipt.OperationID != api.ID("initial-op-"+string(initial.manifest.ID)) ||
			receipt.EventID != api.ID("initial-event-"+string(initial.manifest.ID)) || receipt.CommittedSeq == 0 ||
			receipt.Receipt.ID != initialReceiptID(config) || receipt.Receipt.Class != "manifest" || !initialRef(receipt.Receipt) {
			return nil, failure(api.CodeIntegrity, "initial helper reply lacks its committed publication")
		}
		return receipt, nil
	}
	if method == "enroll_begin" {
		var challenge api.EnrollmentChallenge
		if err := decodeStrict(result, &challenge); err != nil {
			return nil, err
		}
		if err := api.ValidateEnrollmentChallenge(challenge, ceremony, time.Now()); err != nil {
			return nil, err
		}
		if challenge.Origin != endpoint.Origin || challenge.RPID != endpoint.RPID || challenge.InstallationGeneration != endpoint.InstallationGeneration || challenge.EndpointGeneration != installed.Human.EndpointGeneration {
			return nil, failure(api.CodeIntegrity, "administrator create challenge changed endpoint")
		}
		return challenge, nil
	}
	var receipt api.EnrollmentReceipt
	if err := decodeStrict(result, &receipt); err != nil {
		return nil, err
	}
	var completed api.EnrollmentValidationRequest
	if err := decodeStrict(input, &completed); err != nil {
		return nil, err
	}
	if err := validateCompleteReceipt(config, completed, receipt); err != nil {
		return nil, err
	}
	return receipt, nil
}

// The external administrator CLI never borrows the unit's cgroup. It proves
// its mapped artifact to the privileged daemon, which forwards only enrollment.
func relayEnrollment(ctx context.Context, binding installation, endpoint api.AdminEnrollmentEndpoint, request api.AdminEnrollmentFrame) (json.RawMessage, error) {
	if err := privateDirectory(binding.runtimePath(), binding.Service.GID, 0750); err != nil {
		return nil, err
	}
	dialer := helperDialer()
	connection, err := dialer.DialContext(ctx, "unix", binding.socketPath())
	if err != nil {
		return nil, failure(api.CodeUnavailable, "installed administrator relay is unavailable")
	}
	defer connection.Close()
	un, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, failure(api.CodeIntegrity, "administrator enrollment requires a Unix endpoint")
	}
	stop, err := bindHelperCall(ctx, connection)
	if err != nil {
		return nil, err
	}
	defer stop()
	peer, err := pinPeer(un, 0, 0)
	if err != nil {
		return nil, err
	}
	defer closePeer(peer)
	verify := func() error {
		membership, err := cgroupMembership(int(peer.credentials.Pid))
		if err != nil {
			return err
		}
		if membership != "/system.slice/laneboss-helper@"+binding.Config+".service/control" {
			return failure(api.CodeForbidden, "administrator relay is outside the installed helper control unit")
		}
		return peer.verifyEnrollmentHelper(binding)
	}
	if err := verify(); err != nil {
		return nil, err
	}
	params, err := EncodeWire(enrollmentForward{Endpoint: endpoint, Frame: request})
	if err != nil {
		return nil, failure(api.CodeInvalid, "cannot encode fixed administrator forwarding input")
	}
	outer := helperRequest{Protocol: helperProtocol, Revision: api.ContractRevision, Config: binding.Config,
		Generation: binding.Generation, ArtifactSHA256: binding.Artifact.SHA256, Nonce: request.Nonce,
		Method: enrollmentRelayMethod, Params: params}
	if err := writeFrame(connection, outer); err != nil {
		return nil, err
	}
	data, err := readHelperFrame(ctx, un, peer)
	if err != nil {
		return nil, err
	}
	var response helperResponse
	if err := decodeStrict(data, &response); err != nil {
		return nil, err
	}
	if response.Protocol != helperProtocol || response.Revision != api.ContractRevision || response.Nonce != request.Nonce ||
		(response.Error == nil) == (len(response.Result) == 0) || response.Reason != "" && (!api.ValidHelperReason(response.Reason) || response.Error == nil) {
		return nil, failure(api.CodeIntegrity, "administrator relay response differs from its fixed request")
	}
	if err := verify(); err != nil {
		return nil, err
	}
	if response.Error != nil {
		api.ObserveHelperReason(ctx, response.Error, response.Reason)
		return nil, response.Error
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return response.Result, nil
}

// Only the daemon invokes the service channel. It reloads the canonical
// protected installation; neither a caller path nor a claimed scope is used.
func forwardEnrollment(parent context.Context, binding installation, params json.RawMessage) (json.RawMessage, error) {
	ctx, cancel := helperForwardContext(parent)
	defer cancel()
	var input enrollmentForward
	if err := decodeStrict(params, &input); err != nil {
		return nil, err
	}
	path := filepath.Join("/etc/laneboss-v2/service", binding.Config+".json")
	installed, err := readEnrollmentInstallation(path, binding)
	if err != nil {
		return nil, err
	}
	if err := validateEnrollmentForward(input, installed.Endpoint); err != nil {
		return nil, err
	}
	if err := enrollmentDirectory(filepath.Dir(installed.Endpoint.Socket), binding.Service); err != nil {
		return nil, err
	}
	if err := checkEnrollmentSocket(installed.Endpoint.Socket, binding.Service); err != nil {
		return nil, err
	}
	if err := helperServiceBudget(ctx); err != nil {
		return nil, err
	}
	dialer := helperDialer()
	connection, err := dialer.DialContext(ctx, "unix", installed.Endpoint.Socket)
	if err != nil {
		return nil, failure(api.CodeUnavailable, "protected administrator service endpoint is unavailable")
	}
	defer connection.Close()
	un, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, failure(api.CodeIntegrity, "administrator relay requires its Unix service endpoint")
	}
	stop, err := bindHelperCall(ctx, connection)
	if err != nil {
		return nil, err
	}
	defer stop()
	peer, err := pinPeer(un, binding.Service.UID, binding.Service.GID)
	if err != nil {
		return nil, err
	}
	defer closePeer(peer)
	if err := peer.verifyService(binding); err != nil {
		return nil, err
	}
	if err := writeFrame(connection, input.Frame); err != nil {
		return nil, err
	}
	data, err := readHelperFrame(ctx, un, peer)
	if err != nil {
		return nil, err
	}
	var response api.AdminEnrollmentReply
	if err := decodeStrict(data, &response); err != nil {
		return nil, err
	}
	if err := api.ValidateAdminEnrollmentReply(response, input.Frame); err != nil {
		return nil, err
	}
	if err := peer.verifyService(binding); err != nil {
		return nil, err
	}
	current, err := loadInstallation(binding.Config)
	if err != nil {
		return nil, err
	}
	latest, err := readEnrollmentInstallation(path, current)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(current, binding) || latest != installed {
		return nil, failure(api.CodeVersion, "administrator relay installation changed during enrollment")
	}
	if response.Error != nil {
		return nil, response.Error
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return response.Result, nil
}

// The helper and service read the same protected human binding. Its endpoint
// revision is independent of the helper/administrator installation generation.
type enrollmentInstallation struct {
	Endpoint api.AdminEnrollmentEndpoint
	Human    api.InstalledBinding
}

func readEnrollmentHumanBinding(path string, endpoint api.AdminEnrollmentEndpoint, binding installation) (api.InstalledBinding, error) {
	var human api.InstalledBinding
	data, err := readProtected(path, api.MaxFrameBytes)
	if err != nil {
		return human, err
	}
	if err := api.DecodeObject(data, &human); err != nil {
		return human, err
	}
	if err := validateEnrollmentHumanBinding(endpoint, human); err != nil {
		return human, err
	}
	if human.ServiceGID != binding.Service.GID || human.InstallationGeneration != binding.Generation {
		return human, failure(api.CodeIntegrity, "human endpoint differs from the protected helper account or installation")
	}
	return human, nil
}

// CanonicalJSON rejects duplicates/invalid JSON before extracting this fixed
// capability from the administrator-owned service installation's other fields.
func readEnrollmentInstallation(path string, binding installation) (enrollmentInstallation, error) {
	var result enrollmentInstallation
	data, err := readProtected(path, api.MaxFrameBytes)
	if err != nil {
		return result, err
	}
	canonical, err := api.CanonicalJSON(data)
	if err != nil {
		return result, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(canonical, &fields) != nil {
		return result, failure(api.CodeInvalid, "invalid service enrollment installation")
	}
	var schema, config, socket, bindingFile string
	var uid uint32
	var digest api.Digest
	for _, field := range []struct {
		name string
		into any
	}{{"schema", &schema}, {"config", &config}, {"socket", &socket},
		{"service_uid", &uid}, {"artifact_sha256", &digest}, {"binding_file", &bindingFile}} {
		if json.Unmarshal(fields[field.name], field.into) != nil {
			return result, failure(api.CodeInvalid, "service enrollment installation is incomplete")
		}
	}
	if schema != "laneboss.service-install.v2" || config != binding.Config || uid != binding.Service.UID || digest != binding.Artifact.SHA256 {
		return result, failure(api.CodeIntegrity, "service enrollment installation differs from the helper")
	}
	if len(fields["admin_enrollment"]) == 0 || string(fields["admin_enrollment"]) == "null" {
		return result, failure(api.CodePrerequisite, "administrator enrollment is not installed")
	}
	if err := api.DecodeObject(fields["admin_enrollment"], &result.Endpoint); err != nil {
		return result, err
	}
	if err := validateEnrollmentEndpoint(result.Endpoint, binding); err != nil {
		return result, err
	}
	human, err := readEnrollmentHumanBinding(bindingFile, result.Endpoint, binding)
	if err != nil {
		return result, err
	}
	if human.Socket != socket {
		return result, failure(api.CodeIntegrity, "human endpoint differs from the service installation")
	}
	result.Human = human
	return result, nil
}
