package lifecycle

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Transact constructs this view while holding the actual fixture writer mutex.
// It reads the protected head, never Scope.PolicyGeneration or cached history.
type lockedLaunchPolicy struct{ store *launchFixtureStore }

func (store *launchFixtureStore) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return (lockedLaunchPolicy{store: store}).CurrentApprovedPolicy(ctx, scope)
}

func (source lockedLaunchPolicy) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	if err := ctx.Err(); err != nil {
		return api.EffectivePolicy{}, err
	}
	if scope.Config != "example" || source.store == nil {
		return api.EffectivePolicy{}, launchMissing()
	}
	return source.store.policy, nil
}

func (store *launchFixtureStore) CredentialProjection(ctx context.Context, config string, id api.ID) (api.CredentialProjectionRecord, error) {
	if err := ctx.Err(); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.projections[id]
	if !ok || record.Authority.Request.Prepared.ID != id || record.Authority.Request.Handoff.Config != config {
		return api.CredentialProjectionRecord{}, launchMissing()
	}
	return record, nil
}

func (p *launchFixturePorts) AuthorizeCredentialProjection(context.Context, api.VerifiedPeer, api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	return api.CredentialProjectionAuthority{}, api.NotImplemented("lb-v2-identity", "fixture has no native peer authorization")
}

func (p *launchFixturePorts) CheckLaunchCredentials(ctx context.Context, binding api.LaunchBindingRequest) (api.CredentialProjectionRecord, error) {
	if err := p.stage("credential-check"); err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	for id, candidate := range p.store.projections {
		if candidate.Authority.Request.Prepared != binding.Prepared {
			continue
		}
		record, err := p.store.CredentialProjection(ctx, binding.Record.Config, id)
		if err != nil {
			return api.CredentialProjectionRecord{}, err
		}
		// The fixture identity selects a real retained record. Lifecycle still
		// independently validates it; no constant "valid" verdict is returned.
		return record, nil
	}
	return api.CredentialProjectionRecord{}, launchMissing()
}

// This is an explicit correlation model of the protected producer/held record.
// No credential bytes, descriptors or native ownership observations are supplied
// or claimed. The native identity/helper/broker implementations remain owners.
func (f *launchFixture) retainProjection(t *testing.T, plan api.LaunchPlan, binding api.LaunchBindingRequest, claim api.EffectLease) {
	t.Helper()
	if binding.Recovery == nil || claim.Record.Effect.Context == nil {
		t.Fatal("projection fixture lost the actual prepared job")
	}
	request := api.CredentialProjectionRequest{Cause: *claim.Record.Effect.Context, Claim: claim,
		Handoff: binding.Recovery.Handoff, Prepared: binding.Prepared, Lease: plan.Lease, Home: plan.Data.Home}
	if err := api.ValidateCredentialProjectionRequest(request, f.service.deps.Clock.Now()); err != nil {
		t.Fatal(err)
	}
	targets, err := api.CredentialTargets(request, f.service.deps.Clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := launchIDForTest()
	authority := api.CredentialProjectionAuthority{ID: id, Generation: 1, Request: request, Targets: targets}
	held, inherited := uint64(len(targets)), uint64(0)
	receipt := api.CredentialProjectionReceipt{ProjectionID: id, Generation: authority.Generation + 1,
		Prepared: binding.Prepared, HelperLeaseID: plan.Lease.ID, SpecSHA256: binding.Prepared.SpecSHA256,
		Home: plan.Data.Home, CancellationEpoch: plan.Reservation.CancellationEpoch, HeldDescriptors: &held,
		InheritedSources: &inherited, GateClosed: true, ObservedAt: api.Timestamp(f.service.deps.Clock.Now().UTC().Format("2006-01-02T15:04:05.999999999Z07:00"))}
	for _, target := range targets {
		version := target.Version
		if target.SlotID != "" {
			version = string(target.SlotID)
		}
		authority.Sources = append(authority.Sources, api.CredentialSourceVersion{Key: target.Key, Generation: 1, Version: version})
		item := api.CredentialHeldTarget{Target: target, SourceObjectID: string(launchIDForTest()), ObjectID: string(launchIDForTest()),
			RootID: plan.Data.Home.RootID, HomeGeneration: plan.Data.Home.Generation, OwnerUID: plan.Lease.UID,
			Mode: target.FileMode, ParentMode: 0700, Links: 1}
		if target.Delivery == "env" {
			item.OwnerUID, item.Mode = 0, 0600
			if target.SlotID != "" {
				item.Links = 0
			}
		}
		if target.FileMode == 0400 && target.Delivery == "file" {
			item.ParentMode, item.ReadOnlyView = 0500, true
		}
		if target.SlotID != "" && target.EnvironmentName != "" {
			item.ReadOnlyView = true
		}
		receipt.Targets = append(receipt.Targets, item)
	}
	record := api.CredentialProjectionRecord{Authority: authority, Generation: receipt.Generation, State: "held", Receipt: &receipt}
	if err := api.ValidateCredentialProjectionGate(record, binding, f.service.deps.Clock.Now()); err != nil {
		t.Fatal(err)
	}
	f.store.mu.Lock()
	f.store.projections[binding.Prepared.ID] = record
	f.store.mu.Unlock()
	actual, err := f.store.CredentialProjection(context.Background(), binding.Record.Config, binding.Prepared.ID)
	if err != nil || !reflect.DeepEqual(actual, record) {
		t.Fatalf("projection fixture did not retain its exact selected inputs: %v", err)
	}
}
