package store

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// CredentialProjectionSource is installed private metadata authority. The
// native owner authenticates both peers and current source inventory; a public
// request or a copied peer label cannot implement this boundary. Calls occur
// outside the store writer lock and must return no credential bytes or files.
// Holding commit runs under the broker's existing canonical journal/refresh
// lock: implementations must use their independent native metadata/control
// channel and must never recursively acquire that broker journal.
// ID, Generation, Request and Targets are assigned by the store.
type CredentialProjectionSource interface {
	ResolveCredentialProjection(context.Context, api.Scope, api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error)
	ObserveCredentialProjection(context.Context, api.CredentialProjectionAuthority) (api.CredentialProjectionReceipt, error)
}

func (s *Service) credentialSource(ctx context.Context, scope api.Scope, request api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	if s.deps.CredentialProjection == nil || reflect.ValueOf(s.deps.CredentialProjection).Kind() == reflect.Pointer && reflect.ValueOf(s.deps.CredentialProjection).IsNil() {
		return api.CredentialProjectionAuthority{}, fault(api.CodePrerequisite, "credential projection requires its installed native metadata source")
	}
	a, err := s.deps.CredentialProjection.ResolveCredentialProjection(ctx, scope, request)
	if err != nil {
		return api.CredentialProjectionAuthority{}, err
	}
	if a.ID != "" || a.Generation != 0 || a.Revoked {
		return api.CredentialProjectionAuthority{}, fault(api.CodeForbidden, "credential metadata source cannot assign projection identity or revision")
	}
	a.Request = request
	a.Targets, err = api.CredentialTargets(request, s.deps.Clock.Now())
	if err != nil {
		return api.CredentialProjectionAuthority{}, err
	}
	if err := validateCredentialMetadata(a); err != nil {
		return api.CredentialProjectionAuthority{}, err
	}
	return a, nil
}

func validateCredentialMetadata(a api.CredentialProjectionAuthority) error {
	request := a.Request
	if !wire.ValidID(string(a.Helper.ID)) || !wire.ValidDigest(string(a.Helper.SHA256)) || a.Helper.Version == "" || !wire.ValidID(string(a.Broker.ID)) || !wire.ValidDigest(string(a.Broker.SHA256)) || a.Broker.Version == "" ||
		a.Revoked || a.Helper == a.Broker || a.InstallationGeneration == 0 || a.InstallationGeneration >= 1<<53 || a.BootID == "" || a.ServiceUID == 0 || a.ServiceUID == request.Lease.UID ||
		a.HelperPeer.HostUID != 0 || a.HelperPeer.HostPID <= 1 || a.HelperPeer.ProcessGeneration == "" ||
		a.BrokerPeer.HostUID == 0 || a.BrokerPeer.HostUID == a.ServiceUID || a.BrokerPeer.HostUID == request.Lease.UID ||
		a.BrokerPeer.HostPID <= 1 || a.BrokerPeer.HostPID == a.HelperPeer.HostPID || a.BrokerPeer.HostGID == 0 ||
		a.BrokerPeer.ProcessGeneration == "" || !wire.ValidID(string(a.BrokerPeer.ContainmentID)) || a.BrokerPeer.ContainmentID == request.Lease.ContainmentID || len(a.Sources) != len(a.Targets) {
		return fault(api.CodeForbidden, "credential metadata lacks distinct authenticated helper and broker inventory")
	}
	for i, source := range a.Sources {
		if source.Key != a.Targets[i].Key || source.Generation == 0 || source.Generation >= 1<<53 || source.Revoked || source.Version == "" ||
			a.Targets[i].SlotID == "" && source.Version != a.Targets[i].Version {
			return fault(api.CodeForbidden, "credential source inventory differs from the selected targets")
		}
	}
	return nil
}

func sameCredentialPins(first, next api.CredentialProjectionRequest) bool {
	// Claim identity and deadline authenticate this attempt, not a new home,
	// source selection or gate. The immutable effect remains an exact pin.
	left, right := first.Claim.Record.Effect, next.Claim.Record.Effect
	first.Claim, next.Claim = api.EffectLease{}, api.EffectLease{}
	return reflect.DeepEqual(first, next) && reflect.DeepEqual(left, right)
}

func credentialTimestamp(value api.Timestamp, now time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, string(value))
	return err == nil && !t.IsZero() && t.UTC().Format(time.RFC3339Nano) == string(value) && !t.After(now.Add(time.Second))
}
