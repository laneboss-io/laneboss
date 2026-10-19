//go:build linux

package admin

import (
	"context"
	"path/filepath"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

const keyScanLimit = 4096

func releaseAPIKeyMaterial(held *heldCredentials, p api.CredentialProjectionRecord) ([]byte, error) {
	runner := p.Authority.Request.Handoff.Spec.Runner
	if runner == nil || runner.Slot.Mode != "claude-api-key" {
		return nil, nil
	}
	for i, target := range p.Authority.Targets {
		if !keyStoreTarget(p.Authority, target) {
			continue
		}
		if i >= len(held.files) || held.files[i] == nil {
			return nil, failure(api.CodeContainmentUnknown, "API key scan lost its original store holding")
		}
		file := held.files[i]
		_, fact, err := credentialObject(file)
		flags, flagErr := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		if err != nil || flagErr != nil || fact.Nlink != 1 || fact.Uid != p.Authority.Request.Lease.UID || fact.Mode&07777 != 0600 || flags&unix.O_ACCMODE != unix.O_RDONLY || fact.Size < 8 || fact.Size > 6*keyScanLimit+256 {
			return nil, failure(api.CodeContainmentUnknown, "API key scan requires its private held store")
		}
		key := make([]byte, int(fact.Size))
		if n, err := file.ReadAt(key, 0); err != nil || n != len(key) {
			clear(key)
			return nil, failure(api.CodeContainmentUnknown, "API key scan could not read its original bounded holding")
		}
		material, err := claudock.DecodeKeyStore(key)
		clear(key)
		if len(material) > keyScanLimit {
			clear(material)
			return nil, failure(api.CodeContainmentUnknown, "API key scan material exceeds its original bound")
		}
		return material, err
	}
	return nil, failure(api.CodeContainmentUnknown, "API key scan has no exact store target")
}

func (m *leaseManager) scanReleaseAPIKey(ctx context.Context, record leaseRecord, p api.CredentialProjectionRecord, key []byte) (rscan.APIKeyScanResult, error) {
	// The helper owns both paths and the retained home inode. The service
	// receives only redacted diagnostics through the private owner channel.
	// Keep this scope aligned with the administrator installer's state_directory.
	inputs, err := apiKeyReleaseInputs(m.binding, record, p.Authority, filepath.Join("/var/lib/laneboss-v2/service", m.binding.Config))
	if err != nil {
		return rscan.APIKeyScanResult{}, err
	}
	return rscan.ScanAPIKeyReleaseInputs(ctx, api.SecretMaterial{Bytes: key}, inputs), nil
}
