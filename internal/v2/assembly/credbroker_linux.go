//go:build linux

package assembly

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
	"laneboss.io/laneboss/internal/v2/runner/codex"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

type credentialBrokerHost struct {
	mu        sync.Mutex
	installed Installation
	key       []byte
	backend   *native.Service
	broker    *secrets.Service
	initErr   error
	attempted bool
}

// RunCredentialBroker is the fixed system-unit owner. It listens before any
// material operation, breaking the helper/identity/reservation construction
// cycle. Its first authenticated operation unlocks the real encrypted backend.
func RunCredentialBroker(ctx context.Context, config, installationFile, keyFile string) (resultErr error) {
	var installed Installation
	data, err := readProtected(installationFile, api.MaxFrameBytes)
	if err != nil {
		return err
	}
	if err := api.DecodeObject(data, &installed); err != nil {
		return err
	}
	if err := validateInstallation(installed, Options{Config: config, InstallationFile: installationFile}); err != nil {
		return err
	}
	pins, err := admin.LoadNativeCredentialPeers(config)
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 || uint32(os.Geteuid()) != pins.Broker.UID || uint32(os.Getegid()) != pins.Broker.GID {
		return installError("credential owner requires its separately installed broker UID")
	}
	if keyFile != filepath.Join("/run/credentials", "laneboss-credential@"+config+".service", "native.key") {
		return installError("credential key must come from its fixed systemd credential mount")
	}
	file, err := os.OpenFile(keyFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return installError("outside broker key credential is unavailable")
	}
	info, err := file.Stat()
	var mount unix.Statfs_t
	var stat unix.Stat_t
	// systemd owns the credential file and grants this unit read access through
	// its private read-only credential mount. Require that exact native form.
	if err != nil || unix.Fstat(int(file.Fd()), &stat) != nil || unix.Fstatfs(int(file.Fd()), &mount) != nil || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != 0440 || info.Size() != 32 || mount.Flags&unix.ST_RDONLY == 0 {
		file.Close()
		return installError("outside broker key credential has unsafe ownership, mode or size")
	}
	key, readErr := io.ReadAll(io.LimitReader(file, 33))
	if err := errors.Join(readErr, file.Close()); err != nil || len(key) != 32 {
		clear(key)
		return installError("outside broker key credential is incomplete")
	}
	defer clear(key)
	host := &credentialBrokerHost{installed: installed, key: key}
	closeOwner, err := admin.ListenCredentialOwner(ctx, admin.CredentialOwnerOptions{Config: config, Path: filepath.Join(admin.CredentialRuntimeDirectory(config), "owners", "broker", "credential-broker.sock"), OwnerUID: pins.Broker.UID, OwnerGID: pins.Broker.GID,
		CallerUID: 0, CallerGID: 0, CallerCgroup: "/system.slice/laneboss-helper@" + config + ".service/control",
		VerifyCaller: func(ctx context.Context, peer api.VerifiedPeer) error {
			facts, err := peer.Facts(ctx)
			if err != nil {
				return err
			}
			_, err = credentialRemoteCall[api.Empty](ctx, credentialRemote{config}, "peer.VerifyHelper", facts)
			return err
		}, NewSession: func() admin.CredentialOwnerSession { return &credentialBrokerSession{host: host} }})
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, closeOwner())
		if host.backend != nil {
			resultErr = errors.Join(resultErr, host.backend.Close())
		}
	}()
	<-ctx.Done()
	return nil
}

func (h *credentialBrokerHost) service(ctx context.Context) (*secrets.Service, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.attempted {
		return h.broker, h.initErr
	}
	h.attempted = true
	r := credentialRemote{h.installed.Config}
	storage := &credentialRemoteStorage{config: r.config}
	backend, err := native.NewWithStorage(native.Dependencies{Config: r.config, KeyHandle: h.installed.SecretKeyHandle, Clock: wallClock{}}, storage)
	if err != nil {
		h.initErr = err
		return nil, err
	}
	h.backend = backend
	if err := backend.Unlock(ctx, h.installed.SecretKeyHandle, bytes.NewReader(h.key)); err != nil {
		h.initErr = err
		return nil, err
	}
	identity := &credentialRemoteIdentity{remote: r}
	helper := &credentialRemoteHelper{remote: r}
	h.broker, h.initErr = secrets.New(secrets.Dependencies{Config: r.config, Clock: wallClock{}, Backend: backend, Store: &credentialRemoteStore{remote: r}, Human: identity,
		ProjectionIdentity: identity, Grants: &credentialRemoteGrants{remote: r}, Helper: helper, WithdrawalNative: helper, Control: &credentialRemoteControl{remote: r}, CodexValidator: codex.CredentialValidator{}, HeadlessValidator: claudock.CredentialValidator{}, APIKeyValidator: claudock.APIKeyValidator{}})
	if h.initErr == nil {
		h.initErr = h.broker.EnableAPIKeyReuseGate(nil)
	}
	return h.broker, h.initErr
}

type credentialBrokerSession struct {
	host        *credentialBrokerHost
	guard       api.CredentialGateGuard
	cancelGuard context.CancelFunc
}

func (s *credentialBrokerSession) Close() error {
	if s.guard != nil {
		guard := s.guard
		s.guard = nil
		err := guard.Close()
		if s.cancelGuard != nil {
			s.cancelGuard()
			s.cancelGuard = nil
		}
		return err
	}
	return nil
}
func (s *credentialBrokerSession) Call(ctx context.Context, peer api.VerifiedPeer, method string, raw json.RawMessage, files []*os.File) (any, []*os.File, error) {
	if method != "refresh" && len(files) != 0 {
		return nil, nil, installError("credential operation carried unexpected descriptors")
	}
	b, err := s.host.service(ctx)
	if err != nil {
		return nil, nil, err
	}
	switch method {
	case "source_versions":
		var q struct {
			Request      api.CredentialProjectionRequest
			ProjectionID api.ID
		}
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		value, err := b.CredentialSourceVersions(ctx, peer, q.Request, q.ProjectionID)
		// The existing receiver requires an object envelope for strict JSON.
		return struct{ Sources []api.CredentialSourceVersion }{value}, nil, err
	case "reserve", "transfer":
		var q api.CredentialProjectionRequest
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		if method == "reserve" {
			value, err := b.ReserveCredentials(ctx, peer, q)
			return value, nil, err
		}
		value, err := b.TransferCredentials(ctx, peer, q)
		return value, value.Files, err
	case "acknowledge":
		var q api.CredentialProjectionReceipt
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		value, err := b.AcknowledgeCredentials(ctx, q)
		return value, nil, err
	case "begin_withdrawal":
		var q api.CredentialWithdrawalRequest
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		value, err := b.BeginCredentialWithdrawal(ctx, q)
		return value, nil, err
	case "finish_withdrawal":
		var q struct {
			Record  api.CredentialProjectionRecord
			Receipt api.CredentialWithdrawalReceipt
			Scan    *rscan.NativeReleaseScan `json:",omitempty"`
		}
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		if q.Scan != nil && (q.Record.Fence == nil || q.Scan.Cause != q.Record.Fence.Cause || !reflect.DeepEqual(q.Scan.Authority, q.Record.Authority)) {
			return nil, nil, installError("native release scan differs from its exact credential fence")
		}
		value, err := b.FinishCredentialWithdrawal(rscan.WithNativeReleaseScan(ctx, q.Scan), q.Record, q.Receipt)
		return value, nil, err
	case "refresh":
		var q api.CredentialRefresh
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		if len(files) != 1 {
			return nil, nil, installError("credential refresh requires exactly one anonymous descriptor")
		}
		// AcceptCredentialRefresh owns and closes its input. Duplicate here so
		// that the transport retains independent ownership of the received FD.
		fd, err := unix.FcntlInt(files[0].Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return nil, nil, err
		}
		q.File = os.NewFile(uintptr(fd), "native-refresh")
		value, err := b.AcceptCredentialRefresh(ctx, peer, q)
		return value, nil, err
	case "guard_lock":
		if s.guard != nil {
			return nil, nil, installError("credential stream already owns a guard")
		}
		var q api.CredentialGateRequest
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		guardContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		guard, err := b.LockCredentialProjection(guardContext, q)
		if err != nil {
			cancel()
			return nil, nil, err
		}
		s.guard = guard
		s.cancelGuard = cancel
		return guard.Projection(), nil, nil
	case "guard_check":
		var q api.Empty
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		if s.guard == nil {
			return nil, nil, installError("credential stream has no retained native guard")
		}
		if err := s.guard.Check(ctx); err != nil {
			return nil, nil, err
		}
		return s.guard.Projection(), nil, nil
	case "guard_close":
		var q api.Empty
		if err := api.DecodeObject(raw, &q); err != nil {
			return nil, nil, err
		}
		if s.guard == nil {
			return nil, nil, installError("credential stream has no retained native guard")
		}
		if err := s.Close(); err != nil {
			return nil, nil, err
		}
		return api.Empty{}, nil, nil
	}
	return nil, nil, installError("unknown fixed native credential operation")
}
