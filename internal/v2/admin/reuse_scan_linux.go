//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

// NativeAPIKeyReleaseScanner belongs in the root helper. EvidenceDirectory is
// an installed administrator input, never a projection/lane request field.
// The outside credential broker must use a private material transport to this
// owner; a service-UID filesystem read is deliberately not a fallback.
type NativeAPIKeyReleaseScanner struct {
	Config            string
	EvidenceDirectory string
}

var _ rscan.APIKeyReleaseScanner = NativeAPIKeyReleaseScanner{}

func (s NativeAPIKeyReleaseScanner) ScanAPIKeyRelease(ctx context.Context, a api.CredentialProjectionAuthority, material api.SecretMaterial) (rscan.APIKeyScanResult, error) {
	if os.Geteuid() != 0 || !validConfig(s.Config) || a.Request.Handoff.Config != s.Config ||
		!validID(a.Request.Lease.ID) || !filepath.IsAbs(s.EvidenceDirectory) || filepath.Clean(s.EvidenceDirectory) != s.EvidenceDirectory {
		return rscan.APIKeyScanResult{}, failure(api.CodeForbidden, "API key release scan requires its installed root helper")
	}
	binding, err := loadInstallation(s.Config)
	if err != nil {
		return rscan.APIKeyScanResult{}, failure(api.CodeIntegrity, "API key release scan cannot read its installed binding")
	}
	path := filepath.Join(binding.statePath(), string(a.Request.Lease.ID)+".json")
	raw, err := readProtectedMode(path, api.MaxFrameBytes, 0600)
	defer clear(raw)
	var record leaseRecord
	if err != nil || decodeStrict(raw, &record) != nil {
		return rscan.APIKeyScanResult{}, failure(api.CodeIntegrity, "API key release scan cannot read helper-state")
	}
	boot, bootErr := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if bootErr != nil || record.Schema != "laneboss.helper-lease.v2" || record.BootID != strings.TrimSpace(string(boot)) ||
		record.BootID != a.BootID || validateLease(record.Lease, binding) != nil || validateGateJournal(record) != nil || validateCredentialJournal(record) != nil {
		return rscan.APIKeyScanResult{}, failure(api.CodeIntegrity, "API key release scan lost its native release binding")
	}
	inputs, err := apiKeyReleaseInputs(binding, record, a, s.EvidenceDirectory)
	if err != nil {
		return rscan.APIKeyScanResult{}, err
	}
	return rscan.ScanAPIKeyReleaseInputs(ctx, material, inputs), nil
}

func apiKeyReleaseInputs(binding installation, record leaseRecord, a api.CredentialProjectionAuthority, evidence string) (rscan.APIKeyScanInputs, error) {
	q := a.Request
	if record.Lease != q.Lease || record.Storage == nil || !record.Storage.Ready || record.Storage.Collected ||
		record.Storage.Binding.Home != q.Home || record.Storage.Binding.Target != q.Prepared.Target ||
		record.Spec == nil || !reflect.DeepEqual(record.Spec.Handoff, q.Handoff) ||
		record.Gate == nil || record.Gate.Prepared != q.Prepared || record.Credentials == nil || record.Credentials.Record == nil ||
		!reflect.DeepEqual(record.Credentials.Record.Authority, a) || record.Credentials.Record.Fence == nil ||
		record.Credentials.State != "withdrawing" && record.Credentials.State != "withdrawn" ||
		q.Handoff.Config != binding.Config || !validID(q.Home.RootID) || !validID(q.Lease.ID) {
		return rscan.APIKeyScanInputs{}, failure(api.CodeIntegrity, "API key release scan lost its retained native home")
	}
	home := filepath.Join(storageBase(binding, record), string(q.Home.RootID))
	info, err := os.Lstat(home)
	var native unix.Stat_t
	if err != nil || !info.IsDir() || unix.Lstat(home, &native) != nil {
		return rscan.APIKeyScanInputs{}, failure(api.CodeIntegrity, "API key release scan cannot pin lane-home")
	}
	matches := 0
	for _, identity := range record.Storage.Directories {
		if identity.ID == q.Home.RootID {
			if identity.Device != strconv.FormatUint(uint64(native.Dev), 10) || identity.Inode != strconv.FormatUint(native.Ino, 10) {
				return rscan.APIKeyScanInputs{}, failure(api.CodeIntegrity, "API key release scan lane-home identity changed")
			}
			matches++
		}
	}
	if matches != 1 {
		return rscan.APIKeyScanInputs{}, failure(api.CodeIntegrity, "API key release scan lacks one lane-home identity")
	}
	return rscan.APIKeyScanInputs{Home: home, HomeIdentity: info,
		HelperState: binding.statePath(), Evidence: evidence,
		Journal: func(ctx context.Context, role string) (io.ReadCloser, error) {
			return openAPIKeyJournal(ctx, binding.Config, role)
		}}, nil
}

type apiKeyJournalStream struct {
	io.ReadCloser
	command *exec.Cmd
}

func (s *apiKeyJournalStream) Close() error {
	return errors.Join(s.ReadCloser.Close(), s.command.Wait())
}

func openAPIKeyJournal(ctx context.Context, config, role string) (io.ReadCloser, error) {
	if !validConfig(config) || role != "service" && role != "helper" && role != "credential" {
		return nil, failure(api.CodeInvalid, "API key journal selection is not installed")
	}
	unit := "laneboss-" + role + "@" + config + ".service"
	command := exec.CommandContext(ctx, "/usr/bin/journalctl", "--quiet", "--no-pager", "--output=cat", "_SYSTEMD_UNIT="+unit, "+", "UNIT="+unit)
	command.Env, command.Stderr = []string{}, io.Discard
	stream, err := command.StdoutPipe()
	if err != nil {
		return nil, failure(api.CodeUnavailable, "API key journal reader is unavailable")
	}
	if err := command.Start(); err != nil {
		stream.Close()
		return nil, failure(api.CodeUnavailable, "API key journal query did not start")
	}
	return &apiKeyJournalStream{ReadCloser: stream, command: command}, nil
}
