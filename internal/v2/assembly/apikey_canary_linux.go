//go:build linux && laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

// Only the explicit E2E build has this source. It seeds the real encrypted
// backend and InstallProfile path; it supplies no provider or runner proof.
func (s *initialFixtureProfiles) authenticateAPIKeyCanary(ctx context.Context, p bstate.Profile) (available bool, resultErr error) {
	if s.real == nil || p.Runtime != s.real.Wrapper || p.Config != s.installed.Config || p.Mode != "claude-api-key" ||
		p.Paid || p.Provider != "serve-fixture" || p.Source != standInProfileSource(p.Config, p.ID, p.ExpiresAt) {
		return false, installError("API key canary differs from protected real-vendor enrollment")
	}
	path := filepath.Join("/run/laneboss-v2", p.Config, "api-key-canary.sock")
	if err := protectedParents(filepath.Dir(path), 0); err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return false, installError("API key canary source is unavailable")
	}
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return false, installError("API key canary source could not connect")
	}
	defer connection.Close()
	raw, err := connection.(*net.UnixConn).SyscallConn()
	if err != nil {
		return false, installError("API key canary source has no native peer")
	}
	var peer *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || peerErr != nil || peer == nil || peer.Uid != 0 {
		return false, installError("API key canary source is not the root harness")
	}
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return false, installError("API key canary source deadline failed")
	}
	material, err := io.ReadAll(io.LimitReader(connection, claudock.MaxAPIKeyBytes+1))
	defer clear(material)
	if err != nil || (claudock.APIKeyValidator{}).ValidateAPIKeyCredential(string(p.ID), string(p.LoginID), material) != nil {
		return false, installError("API key canary source shape differs")
	}
	backend, err := installedSecrets(ctx, s.installed, wallClock{})
	if err != nil {
		return false, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, backend.Close())
		if resultErr != nil {
			available = false
		}
	}()
	want := api.SecretInfo{Name: p.Source.Name, Version: p.Source.Version, SourceHandle: p.Source.SourceHandle, KeyID: s.installed.SecretKeyHandle}
	stored, err := backend.Store(ctx, want, api.SecretMaterial{Bytes: material})
	if err != nil || stored != want {
		return false, installError("API key canary encrypted enrollment failed")
	}
	actual, err := backend.Fetch(ctx, p.Source)
	defer clear(actual.Bytes)
	if err != nil || !bytes.Equal(actual.Bytes, material) {
		return false, installError("API key canary encrypted readback differs")
	}
	return true, nil
}
