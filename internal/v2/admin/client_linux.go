//go:build linux

package admin

import (
	"context"
	"errors"
	"net"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) call(parent context.Context, method string, params any, result any, observed ...*int64) (resultErr error) {
	if method == "open_gate" {
		registration, ok := params.(gateOpenRegistration)
		if !ok {
			return failure(api.CodeInvalid, "agent release requires its committed gate registration")
		}
		// validateOpenCommit also admits worker records; their containment is bound on their own path.
		if registration.Binding.Record.Kind == "agent" {
			if err := s.bindAgentContainment(parent, registration); err != nil {
				return err
			}
			finish := s.beginContainment(registration.Binding.Record.ContainmentID)
			defer finish()
		}
	}
	if session := s.workerSession(parent); session != nil && !credentialMetadataMethod(method) {
		return session.call(parent, method, params, result)
	}
	check := "call_context"
	refusalReason := ""
	defer func() {
		if resultErr != nil {
			reason := api.HelperReason(resultErr)
			if reason == "" {
				reason = refusalReason
			}
			if reason == "" {
				reason = check
			}
			api.ObserveHelperReason(parent, resultErr, reason)
		}
		resultErr = api.WithoutHelperReason(resultErr)
	}()
	ctx, cancel := context.WithTimeout(parent, helperCallTimeout)
	defer cancel()
	if err := contextError(ctx); err != nil {
		return err
	}
	check = "call_identity"
	if uint32(os.Getuid()) != s.deps.ServiceUID || uint32(os.Geteuid()) != s.deps.ServiceUID {
		return failure(api.CodeForbidden, "helper calls require the installed unprivileged service identity")
	}
	check = "call_binding"
	current, err := loadInstallation(s.deps.Config)
	if err != nil {
		return err
	}
	if current.Generation != s.binding.Generation || current.Artifact != s.binding.Artifact {
		return failure(api.CodeVersion, "installed helper generation changed; restart the matched service")
	}
	check = "call_socket"
	if err := protectedPath(s.binding.runtimePath(), true); err != nil {
		return err
	}
	dialer := helperDialer()
	socketPath := s.binding.socketPath()
	if credentialMetadataMethod(method) {
		socketPath = s.binding.credentialMetadataPath()
	}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return failure(api.CodeUnavailable, "installed helper socket is unavailable")
	}
	defer connection.Close()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return failure(api.CodeIntegrity, "helper endpoint is not a Unix connection")
	}
	stop, err := bindHelperCall(ctx, connection)
	if err != nil {
		return err
	}
	defer stop()
	check = "call_peer"
	peer, err := pinPeer(unixConnection, 0, 0)
	if err != nil {
		return err
	}
	defer closePeer(peer)
	membership, err := cgroupMembership(int(peer.credentials.Pid))
	if err != nil {
		return err
	}
	instance, unitErr := helperControlConfig(membership)
	if unitErr != nil || instance != s.deps.Config {
		return failure(api.CodeUnauthenticated, "root endpoint is not the installed helper service")
	}
	check = "call_encode"
	body, err := EncodeWire(helperInput(params))
	if err != nil {
		return failure(api.CodeInvalid, "cannot encode helper input")
	}
	nonce, err := randomID("call-")
	if err != nil {
		return err
	}
	request := helperRequest{Protocol: helperProtocol, Revision: api.ContractRevision, Config: s.deps.Config,
		Generation: s.binding.Generation, ArtifactSHA256: s.binding.Artifact.SHA256,
		Nonce: nonce, Method: method, Params: body}
	finishJournal := journalHelperCall(ctx, method, nonce)
	defer func() { finishJournal(resultErr, check) }()
	if attempt, ok := api.EffectLeaseFromContext(ctx); ok {
		request.Attempt = &attempt
	}
	check = "call_write"
	if err := writeFrame(connection, request); err != nil {
		return err
	}
	streamErr := writeHelperInput(connection, params)
	check = "reply_transport"
	data, err := readHelperFrame(ctx, unixConnection, peer)
	if err != nil {
		if streamErr != nil {
			return errors.Join(streamErr, err)
		}
		return err
	}
	var response helperResponse
	check = "reply_decode"
	if err := decodeReply(data, &response); err != nil {
		return err
	}
	check = "reply_binding"
	if response.Protocol != helperProtocol || response.Revision != api.ContractRevision || response.Nonce != nonce ||
		(response.Error == nil) == (len(response.Result) == 0) || response.Reason != "" && (!api.ValidHelperReason(response.Reason) || response.Error == nil) {
		return failure(api.CodeIntegrity, "invalid or mismatched helper response")
	}
	check = "peer_lifetime"
	if err := peer.alive(); err != nil {
		return err
	}
	if response.Error != nil {
		refusalReason = response.Reason
		refusal := ownInvalid(response.Error, owner)
		if streamErr != nil {
			return errors.Join(refusal, streamErr)
		}
		return refusal
	}
	if streamErr != nil {
		return streamErr
	}
	check = "cancellation"
	if err := contextError(ctx); err != nil {
		return err
	}
	check = "reply_result"
	if len(observed) == 1 && observed[0] != nil {
		*observed[0] = response.Observed
	}
	return decodeReply(response.Result, result)
}
