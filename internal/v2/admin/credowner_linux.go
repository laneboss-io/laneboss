//go:build linux

package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// CredentialOwnerSession owns all state retained by one private native stream.
// The transport closes every received duplicate, including refused frames.
// Returned files remain owned by the broker until its durable acknowledgement.
type CredentialOwnerSession interface {
	Call(context.Context, api.VerifiedPeer, string, json.RawMessage, []*os.File) (any, []*os.File, error)
	Close() error
}

type CredentialOwnerOptions struct {
	Config            string
	Path              string
	OwnerUID          uint32
	OwnerGID          uint32
	CallerUID         uint32
	CallerGID         uint32
	CallerCgroup      string
	CallerContainment api.ID
	VerifyCaller      func(context.Context, api.VerifiedPeer) error
	NewSession        func() CredentialOwnerSession
}

// CredentialRuntimeDirectory gives each configuration a fixed-length socket
// root, shared with the installer, within the native Unix pathname limit.
func CredentialRuntimeDirectory(config string) string {
	sum := sha256.Sum256([]byte(config))
	return filepath.Join("/run/lb-v2-cred", hex.EncodeToString(sum[:16]))
}

// The publisher has one configuration-scoped writable mount. Both private
// owner-created source directories and protected destinations live beneath
// it, so publication does not cross the unit's separate bind mounts.
func (b installation) credentialRuntimePath() string {
	return CredentialRuntimeDirectory(b.Config)
}

// ListenCredentialOwner creates the listener as its real unprivileged owner.
// Publication is a separate root-helper rename; chown of a root-created
// listener cannot supply the owner's native SO_PEERCRED identity.
func ListenCredentialOwner(ctx context.Context, options CredentialOwnerOptions) (func() error, error) {
	b, err := loadInstallation(options.Config)
	if err != nil {
		return nil, err
	}
	if options.OwnerUID == 0 || uint32(os.Geteuid()) != options.OwnerUID || uint32(os.Getegid()) != options.OwnerGID || options.NewSession == nil || options.VerifyCaller == nil || options.CallerCgroup == "" {
		return nil, failure(api.CodeForbidden, "credential listener requires its installed unprivileged owner and native caller")
	}
	if err := enrollmentDirectory(filepath.Dir(options.Path), account{UID: options.OwnerUID, GID: options.OwnerGID}); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(options.Path); !errors.Is(err, os.ErrNotExist) {
		return nil, failure(api.CodeConflict, "retain an existing credential listener for administrator recovery")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: options.Path, Net: "unix"})
	if err != nil {
		return nil, failure(api.CodeUnavailable, "credential owner cannot create its private listener")
	}
	listener.SetUnlinkOnClose(false)
	control, err := listener.SyscallConn()
	if err != nil {
		listener.Close()
		return nil, err
	}
	var credentialErr error
	if err := control.Control(func(fd uintptr) { credentialErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || credentialErr != nil {
		listener.Close()
		return nil, errors.Join(err, credentialErr)
	}
	if err := os.Chmod(options.Path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		listener.Close()
		return nil, err
	}
	var workers sync.WaitGroup
	ownerCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ownerCtx, func() { listener.Close() })
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			connection, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				stopConnection := context.AfterFunc(ownerCtx, func() { connection.Close() })
				defer stopConnection()
				serveCredentialOwner(ownerCtx, connection, b, strings.TrimSpace(string(boot)), options)
			}()
		}
	}()
	return func() error {
		cancel()
		stop()
		err := listener.Close()
		workers.Wait()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}, nil
}

func serveCredentialOwner(ctx context.Context, connection *net.UnixConn, b installation, boot string, options CredentialOwnerOptions) {
	peer, err := pinPeer(connection, options.CallerUID, options.CallerGID)
	if err != nil {
		credentialOwnerDropped("pin_peer", err)
		return
	}
	generation, err := processGeneration(int(peer.credentials.Pid), boot)
	if err != nil {
		credentialOwnerDropped("process_generation", err)
		closePeer(peer)
		return
	}
	verified := &credentialOwnerPeer{peer: peer, boot: boot, generation: generation, cgroup: options.CallerCgroup, containment: options.CallerContainment}
	defer verified.Close()
	session := options.NewSession()
	if session == nil {
		credentialOwnerDropped("no_session", nil)
		return
	}
	defer session.Close()
	for served := 0; ; served++ {
		if connection.SetReadDeadline(time.Now().Add(5*time.Minute)) != nil {
			credentialOwnerDropped("read_deadline", nil)
			return
		}
		data, files, ended, err := readCredentialStream(connection, peer.credentials, func() error {
			finishTrace := traceCredWait("owner_verify")
			defer finishTrace()
			if err := verified.Alive(ctx); err != nil {
				return err
			}
			return options.VerifyCaller(ctx, verified)
		})
		if err != nil {
			// A caller that closes after its calls (credentialRemoteCall's one-shot client) ends the session; the
			// owner drops nothing. A close before any frame is journaled as the caller's, never as a peer mismatch.
			reason := "read_frame "
			if ended {
				if served > 0 {
					return
				}
				reason = "caller_closed "
			}
			credentialOwnerDropped(reason+filepath.Base(options.Path), err)
			return
		}
		var request helperRequest
		err = decodeStrict(data, &request)
		if err != nil || request.Protocol != credentialProtocol || request.Revision != api.ContractRevision || request.Config != b.Config || request.Generation != b.Generation || request.ArtifactSHA256 != b.Artifact.SHA256 || !validID(request.Nonce) || request.Method == "" {
			reason := "request_binding"
			if err != nil {
				reason = "request_decode"
			}
			credentialOwnerDropped(reason, err)
			closeCredentialFiles(files)
			return
		}
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if request.Attempt != nil {
			callCtx = api.WithEffectLease(callCtx, *request.Attempt)
		}
		finishTrace := traceCredWait("owner_call")
		result, exports, callErr := session.Call(callCtx, verified, request.Method, request.Params, files)
		finishTrace()
		cancel()
		closeErr := closeCredentialFiles(files)
		if callErr == nil {
			callErr = closeErr
		}
		response := credentialResponse{Protocol: credentialProtocol, Revision: api.ContractRevision, Nonce: request.Nonce}
		if callErr == nil {
			response.Result, callErr = EncodeWire(result)
		}
		if callErr != nil {
			response.Result = nil
			response.Error = failure(api.CodeIntegrity, "native credential owner refused private control")
			var typed *api.Error
			if errors.As(callErr, &typed) {
				response.Error = &api.Error{Code: typed.Code, Owner: typed.Owner, Retryable: typed.Retryable, Message: "native credential owner refused private control"}
			}
			// The reply stays masked; the owner's own journal names the refused method with the typed code and
			// owner only, never free text from the credential path (item 1 diagnosis; saved item 27).
			// Production journals the method, code and owner only; the E2E stand-in build adds the fixed message
			// (credentialOwnerDetail), never free text in production (saved items 27 and 28).
			method, code, owner, detail := "other", "", "", ""
			if credentialOwnerMethod.MatchString(request.Method) {
				method = request.Method
			}
			if typed != nil {
				code, owner = string(typed.Code), typed.Owner
				if credentialOwnerDetail {
					detail = typed.Message
				}
			}
			if line, err := json.Marshal(struct {
				Event  string `json:"event"`
				Method string `json:"method"`
				Code   string `json:"code"`
				Owner  string `json:"owner"`
				Detail string `json:"detail,omitempty"`
			}{"credential_owner_refused", method, code, owner, detail}); err == nil && !credentialStorageReadAbsent(request.Method, callErr) {
				_, _ = os.Stderr.Write(append(line, '\n'))
			}
			exports = nil
		}
		if connection.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			return
		}
		if err := writeCredentialOwnerReply(connection, response, exports); err != nil {
			return
		}
	}
}

// Storage reads also serve first-use key checks and journal generation probes.
// Keep NotFound in the reply so the broker can decide whether a record is
// required. Only direct secret-store absence is routine at this private port;
// compound failures and higher-level broker refusals still reach the journal.
func credentialStorageReadAbsent(method string, err error) bool {
	typed, ok := err.(*api.Error)
	return method == "storage.read" && ok && typed != nil && typed.Code == api.CodeNotFound && typed.Owner == "lb-v2-secrets"
}

func writeCredentialOwnerReply(connection *net.UnixConn, response credentialResponse, files []*os.File) error {
	data, err := EncodeWire(response)
	if err != nil {
		return err
	}
	packet, err := frame(data)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return writeFrame(connection, response)
	}
	if len(files) > 64 {
		return failure(api.CodeInvalid, "credential owner export count exceeds its native bound")
	}
	fds := make([]int, len(files))
	for index, file := range files {
		if file == nil {
			return failure(api.CodeIntegrity, "credential owner export is absent")
		}
		fds[index] = int(file.Fd())
	}
	rights := unix.UnixRights(fds...)
	n, control, err := connection.WriteMsgUnix(packet, rights, nil)
	if err != nil || n != len(packet) || control != len(rights) {
		return failure(api.CodeUnavailable, "credential owner export transport is incomplete")
	}
	return nil
}

type credentialOwnerPeer struct {
	peer                     *pinnedPeer
	boot, generation, cgroup string
	containment              api.ID
	closeOnce                sync.Once
	closeErr                 error
}

func (p *credentialOwnerPeer) Alive(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := p.peer.alive(); err != nil {
		return err
	}
	generation, err := processGeneration(int(p.peer.credentials.Pid), p.boot)
	if err != nil || generation != p.generation {
		return failure(api.CodeUnauthenticated, "credential caller lifetime changed")
	}
	group, err := cgroupMembership(int(p.peer.credentials.Pid))
	if err != nil || group != p.cgroup {
		return failure(api.CodeUnauthenticated, "credential caller left its installed containment")
	}
	return nil
}
func (p *credentialOwnerPeer) Facts(ctx context.Context) (api.PeerFacts, error) {
	if err := p.Alive(ctx); err != nil {
		return api.PeerFacts{}, err
	}
	return api.PeerFacts{HostPID: int(p.peer.credentials.Pid), HostUID: p.peer.credentials.Uid, HostGID: p.peer.credentials.Gid, ProcessGeneration: p.generation, ContainmentID: p.containment}, nil
}
func (p *credentialOwnerPeer) Close() error {
	p.closeOnce.Do(func() { p.closeErr = unix.Close(p.peer.pidfd) })
	return p.closeErr
}

// PublishCredentialOwner moves only the owner's measured private listener.
// Neither the caller nor a lane supplies either pathname or a catalog pin.
func publishCredentialOwner(b installation, source, target string, pin credentialPeerPin) (resultErr error) {
	check := "source_directory"
	peer := "unknown"
	switch filepath.Base(target) {
	case "credential-broker.sock":
		peer = "broker"
	case "credential-identity.sock":
		peer = "identity"
	case "component.sock":
		peer = "metadata"
	}
	defer func() {
		result := "ok"
		if resultErr != nil {
			result = "refused"
		}
		// Fixed words only: no path, numeric account, configuration, request,
		// native error string or credential value is written to the journal.
		if err := json.NewEncoder(os.Stderr).Encode(struct {
			Stage  string `json:"stage"`
			Peer   string `json:"peer"`
			Check  string `json:"check"`
			Result string `json:"result"`
		}{"credential_publication", peer, check, result}); err != nil {
			resultErr = errors.Join(resultErr, failure(api.CodeUnavailable, "cannot retain credential publication diagnostic"))
		}
	}()
	if err := enrollmentDirectory(filepath.Dir(source), account{UID: pin.UID, GID: pin.GID}); err != nil {
		return err
	}
	check = "protected_parent"
	if err := protectedPath(filepath.Dir(target), true); err != nil {
		return err
	}
	check = "socket_identity"
	if err := checkEnrollmentSocket(source, account{UID: pin.UID, GID: pin.GID}); err != nil {
		return err
	}
	check = "publication_rename"
	if err := unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE); err != nil {
		switch {
		case errors.Is(err, unix.EXDEV):
			check = "publication_cross_mount"
		case errors.Is(err, unix.EROFS):
			check = "publication_read_only"
		case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
			check = "publication_permission"
		case errors.Is(err, unix.EEXIST):
			check = "publication_occupied"
		}
		return failure(api.CodeConflict, "credential listener publication requires absent protected destination")
	}
	check = "published"
	return nil
}

// credentialOwnerMethod matches a plain method name; any other method is journaled as "other".
var credentialOwnerMethod = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]{0,63}$`)

// credentialOwnerDropped journals why the owner closed a caller's connection without a reply: a fixed reason and the
// typed code only, never text (item 1 diagnosis; box 65 saw only the caller's receive failure).
func credentialOwnerDropped(reason string, err error) {
	code := ""
	var typed *api.Error
	if errors.As(err, &typed) {
		code = string(typed.Code)
	} else if err != nil {
		code = "untyped"
	}
	detail := ""
	if credentialOwnerDetail && typed != nil {
		detail = typed.Message // the E2E stand-in build only (credential_owner_diag_partial_linux.go)
	}
	if line, marshalErr := json.Marshal(struct {
		Event  string `json:"event"`
		Reason string `json:"reason"`
		Code   string `json:"code,omitempty"`
		Detail string `json:"detail,omitempty"`
	}{"credential_owner_dropped", reason, code, detail}); marshalErr == nil {
		_, _ = os.Stderr.Write(append(line, '\n'))
	}
}
