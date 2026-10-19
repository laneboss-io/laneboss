//go:build linux

package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) credentialSource(ctx context.Context, query credentialSourceQuery) (result api.CredentialProjectionAuthority, resultErr error) {
	q := query.Request
	if os.Geteuid() != 0 || query.Actor.Kind != "service" || !validID(query.Actor.ID) || m.credentials == nil {
		return result, failure(api.CodeForbidden, "credential metadata requires its bound root helper owner")
	}
	if err := m.credentials.checkBinding(ctx); err != nil {
		return result, err
	}
	if err := api.ValidateCredentialProjectionRequest(q, time.Now()); err != nil {
		return result, err
	}
	record, err := m.findActive(q.Lease.ID, storageReady)
	if err != nil {
		return result, err
	}
	if record.Spec == nil || record.Gate == nil || record.Storage == nil || record.Gate.Prepared != q.Prepared || record.Lease != q.Lease ||
		record.Storage.Binding.Home != q.Home || !reflect.DeepEqual(record.Spec.Handoff, q.Handoff) || !retainedPrepare(q.Claim.Record.Effect.HelperPrepare, record.Gate.Request, q.Claim.Record.ClaimantID) {
		return result, failure(api.CodeForbidden, "credential metadata differs from its actual native gate allocation and home")
	}
	data, err := readProtected(filepath.Join("/etc/laneboss-v2/boot", m.binding.Config+".json"), api.MaxFrameBytes)
	if err != nil {
		return result, err
	}
	var catalog bootCatalog
	if err := decodeStrict(data, &catalog); err != nil {
		return result, err
	}
	if catalog.Config != m.binding.Config || catalog.RuntimeManifest != q.Handoff.Spec.RuntimeManifest {
		return result, failure(api.CodeIntegrity, "credential helper runtime differs from its protected boot catalog")
	}
	data, err = readProtected(catalog.RuntimeFile, catalog.RuntimeManifest.Bytes)
	if err != nil {
		return result, err
	}
	var runtime api.RuntimeManifest
	if digestBytes(data) != catalog.RuntimeManifest.SHA256 || api.DecodeObject(data, &runtime) != nil || runtime.Artifact.SHA256 != m.binding.Artifact.SHA256 || runtime.Artifact.Version != m.binding.Release.Version {
		return result, failure(api.CodeIntegrity, "credential helper executable lost its installed runtime pin")
	}
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		return result, failure(api.CodeUnauthenticated, "credential helper executable is unavailable")
	}
	if err := errors.Join(verifyExecutableFile(executable, m.binding.Artifact), executable.Close()); err != nil {
		return result, err
	}
	generation, err := processGeneration(os.Getpid(), m.bootID)
	if err != nil {
		return result, err
	}
	broker := m.credentials.broker.(*nativeCredentialBroker)
	brokerPeer, err := broker.channel.Facts(ctx)
	if err != nil {
		return result, err
	}
	// Prepare/acknowledge is waiting on the original broker stream. Metadata
	// rechecks use a distinct authenticated connection to that same pinned owner.
	inventory, err := openCredentialChannel(ctx, broker.channel.binding, broker.channel.boot, broker.channel.socket, broker.channel.pin)
	if err != nil {
		return result, err
	}
	inventory.operationMu = broker.channel.operationMu
	defer func() { resultErr = errors.Join(resultErr, inventory.Close()) }()
	var projection api.ID
	if record.Credentials != nil && record.Credentials.Record != nil {
		projection = record.Credentials.Record.Authority.ID
	}
	var inventoryReply struct{ Sources []api.CredentialSourceVersion }
	if _, err := inventory.call(ctx, "source_versions", struct {
		Request      api.CredentialProjectionRequest
		ProjectionID api.ID
	}{q, projection}, &inventoryReply, nil, false); err != nil {
		return result, err
	}
	// Targets is derived by the store (api.CredentialTargets); empty lists, not null, cross the strict wire.
	if inventoryReply.Sources == nil {
		inventoryReply.Sources = []api.CredentialSourceVersion{}
	}
	result = api.CredentialProjectionAuthority{Request: q, Targets: []api.CredentialTarget{}, Helper: runtime.Artifact, Broker: broker.channel.pin.Executable,
		HelperPeer: api.PeerFacts{HostUID: uint32(os.Geteuid()), HostGID: uint32(os.Getegid()), HostPID: os.Getpid(), ProcessGeneration: generation},
		BrokerPeer: brokerPeer, ServiceUID: m.binding.Service.UID, InstallationGeneration: m.binding.Generation, BootID: m.bootID, Sources: inventoryReply.Sources}
	return result, nil
}

func (m *leaseManager) credentialObservation(ctx context.Context, authority api.CredentialProjectionAuthority) (api.CredentialProjectionReceipt, error) {
	if m.credentials == nil {
		return api.CredentialProjectionReceipt{}, failure(api.CodePrerequisite, "credential native receiver is not bound")
	}
	if err := m.credentials.checkBinding(ctx); err != nil {
		return api.CredentialProjectionReceipt{}, err
	}
	held := m.credentials.held[authority.ID]
	if held == nil || !reflect.DeepEqual(held.record.Authority, authority) {
		return api.CredentialProjectionReceipt{}, failure(api.CodeForbidden, "credential native observation selected another held authority")
	}
	return m.credentials.observe(ctx, authority.ID)
}
