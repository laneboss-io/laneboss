package identityd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/identityd/ticket"
)

// Call is the small integration client. It authenticates the socket's service
// peer using the kernel, rather than trusting a PID/UID in a response object.
func Call(ctx context.Context, options Options, request Request) (Response, error) {
	var response Response
	if err := config.CheckName(options.Config); err != nil {
		return response, refuse("the configuration name is invalid")
	}
	_, runtime := options.roots()
	base, err := filepath.EvalSymlinks(runtime)
	if err != nil {
		return response, refuse("the service socket root is unavailable\nInstead: install or start the dedicated service in docs/service.md.")
	}
	path := filepath.Join(base, options.Config, "service.sock")
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 {
		return response, refuse("the service socket is unavailable or has unsafe permissions\nInstead: install or start the dedicated service in docs/service.md.")
	}
	uid, gid, _, err := ownership(info)
	if err != nil || uid == 0 || uid == uint32(os.Geteuid()) {
		return response, refuse("the service socket must belong to another dedicated unprivileged OS user\nInstead: install the service under its own OS account.")
	}
	if err := protectedAncestors(filepath.Dir(path), uid); err != nil {
		return response, err
	}
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil || directory.Mode().Perm() != 0750 {
		return response, refuse("the service socket directory must be 0750")
	}
	dirUID, dirGID, _, err := ownership(directory)
	if err != nil || dirUID != uid || dirGID != gid {
		return response, refuse("the service socket directory and socket ownership disagree")
	}
	dialer := net.Dialer{Timeout: requestTimeout}
	connection, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return response, refuse("the service is not reachable\nInstead: inspect the installed service manager's status before retrying.")
	}
	defer connection.Close()
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		return response, corrupt("the service connection is not a Unix socket")
	}
	peer, err := socketPeer(conn)
	if peer != nil {
		defer peer.lifetime.close()
	}
	if err != nil {
		return response, err
	}
	if peer.UID != uid || peer.GID != gid {
		return response, refuse("the connected service peer disagrees with the installed socket owner\nInstead: have the administrator inspect the service socket.")
	}
	if request.Op != "whoami" {
		if err := peer.lifetime.mutationAllowed(); err != nil {
			return response, err
		}
	}
	deadline := time.Now().Add(requestTimeout)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return response, err
	}
	request.Version, request.Config = Version, options.Config
	data, err := json.Marshal(request)
	if err != nil || len(data)+1 > MaxRequestBytes {
		return response, refuse("the service request exceeds 65536 bytes")
	}
	data = append(data, '\n')
	return exchangeResponse(conn, options.Config, peer, data)
}

// Call has authenticated peer and set the request deadline before entering
// this helper. A refuse-and-close may beat the write while its reply remains
// queued. Read that bounded reply without extending the deadline or retrying.
func exchangeResponse(conn *net.UnixConn, config string, peer *socketIdentity, data []byte) (Response, error) {
	var response Response
	closedIncomplete := false
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			if !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET) || dropRefusal() {
				return response, err
			}
			// The terminal newline is still unsent in this case, so the
			// service cannot have processed the incomplete JSON request.
			closedIncomplete = n < len(data)
			break
		}
		if n == 0 {
			return response, io.ErrShortWrite
		}
		data = data[n:]
	}
	line, err := bufio.NewReaderSize(conn, MaxResponseBytes+1).ReadSlice('\n')
	if err != nil || len(line) > MaxResponseBytes {
		if closedIncomplete && len(line) == 0 {
			return response, refuse("the service closed the connection before reading the request\nInstead: retry within your deadline; the request was not processed.")
		}
		return response, corrupt("the service response is incomplete, oversized or timed out")
	}
	if _, err := eventstore.Parse(line, "the service response"); err != nil || json.Unmarshal(line, &response) != nil {
		return Response{}, corrupt("the service response is malformed")
	}
	if err := peer.check(); err != nil {
		return Response{}, err
	}
	if response.Version != Version || response.Service.Config != config || !samePeer(response.Service.Peer, peer.Peer) {
		return Response{}, corrupt("the service response disagrees with its kernel peer identity")
	}
	if !response.OK {
		if response.Code != 2 && response.Code != 3 {
			return Response{}, corrupt("the service response has an invalid refusal code")
		}
		if response.PolicyChange != nil {
			problem := &ticket.Refusal{Reason: ticket.PolicyChanged, Policy: response.PolicyChange}
			if response.Code != 2 || !response.PolicyChange.Valid() || response.Error != "refused: "+problem.Error() {
				return Response{}, corrupt("the service policy refusal has invalid scope")
			}
			return response, problem
		}
		return response, &failure{response.Code, response.Error}
	}
	if response.Code != 0 {
		return Response{}, corrupt("the service success response has a nonzero code")
	}
	if response.PolicyChange != nil {
		return Response{}, corrupt("the service success response carries a policy refusal")
	}
	if closedIncomplete {
		return Response{}, corrupt("the service returned success for an incomplete request")
	}
	return response, nil
}
