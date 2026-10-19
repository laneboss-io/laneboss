package admin

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
)

type networkJournal struct {
	Phase           string           `json:"phase"`
	SpecID          api.ID           `json:"spec_id"`
	SpecSHA256      api.Digest       `json:"spec_sha256"`
	ClaimID         api.ID           `json:"claim_id,omitempty"`
	ClaimGeneration api.Generation   `json:"claim_generation,omitempty"`
	Lease           api.NetworkLease `json:"lease"`
	Device          string           `json:"device,omitempty"`
	Inode           string           `json:"inode,omitempty"`
}

func validateNetworkJournal(record leaseRecord) error {
	network := record.Network
	if network == nil {
		return nil
	}
	if record.Spec == nil || network.SpecID != record.Spec.Handoff.Spec.ID || network.SpecSHA256 != record.Spec.Handoff.SpecSHA256 ||
		!validID(network.Lease.ID) || !validID(network.Lease.NamespaceID) || network.Lease.GrantSetID != record.Spec.Handoff.Spec.Grants.ID ||
		network.Lease.Generation != record.Spec.Handoff.Spec.PolicyGeneration ||
		(network.Phase != "creating" && network.Phase != "ready" && network.Phase != "collecting" && network.Phase != "collected") ||
		network.Phase != "creating" && network.Phase != "collected" && (network.Device == "" || network.Inode == "") {
		return failure(api.CodeIntegrity, "invalid retained private network namespace")
	}
	grants := record.Spec.Handoff.Spec.Grants.Network
	if len(network.Lease.EndpointIDs) != len(grants) {
		return failure(api.CodeIntegrity, "retained network endpoints differ from the current grant set")
	}
	seen := map[api.ID]bool{}
	for index, grant := range grants {
		if !validID(grant.ID) || !validID(grant.EndpointID) || grant.Mode != "internet" && grant.Mode != "service" && grant.Mode != "publish" ||
			network.Lease.EndpointIDs[index] != grant.EndpointID || seen[grant.EndpointID] {
			return failure(api.CodeIntegrity, "retained network endpoint identity is foreign or duplicated")
		}
		seen[grant.EndpointID] = true
	}
	if len(grants) != 0 {
		if !validID(network.ClaimID) || network.ClaimGeneration == 0 || network.ClaimID != record.Spec.Handoff.Cause.EffectID {
			return failure(api.CodeIntegrity, "retained network claim is foreign or incomplete")
		}
		raw, err := json.Marshal(grants)
		if err != nil || network.Lease.PolicySHA256 != digestBytes(raw) || network.Lease.PolicySHA256 == "" {
			return failure(api.CodeIntegrity, "retained network policy pin differs from its grants")
		}
	}
	return nil
}

// Keep the type common so Darwin can decode retained journals without gaining
// a Linux operation. The descriptor never crosses a public or helper frame.
type namespaceOwner struct {
	file     *os.File
	resolv   *os.File
	check    func() error
	collect  func() error
	released bool
}

func (m *leaseManager) resolvePreparedRuntime(ctx context.Context, handoff api.PreparedSpecHandoff) (_ api.ResolvedRuntime, resultErr error) {
	defer helperCheck(&resultErr, "runtime_enrollment")
	record, err := m.findActive(handoff.Spec.UIDLeaseID, storageReady)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	return m.resolveNativeRuntime(ctx, record, handoff)
}

func (m *leaseManager) collectNetwork(ctx context.Context, record *leaseRecord) error {
	if record.Network == nil || record.Network.Phase == "collected" {
		return errors.Join(m.collectGateExports(record.Lease.ID), m.closeRunnerPrompt(record.Lease.ID))
	}
	if err := m.collectNativeNetwork(ctx, record); err != nil {
		return err
	}
	return errors.Join(m.collectGateExports(record.Lease.ID), m.closeRunnerPrompt(record.Lease.ID))
}
