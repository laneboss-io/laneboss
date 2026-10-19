//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This component owner kills and reaps a real canary. It does not claim that
// its single-process observations establish native cgroup/UID quiescence.
type stopCanaryOwner struct {
	*observedResources
	gate    *nativeGate
	finish  *os.File
	handle  api.ProcessHandle
	kills   int
	waits   int
	waited  bool
	waitErr error
	killErr error
}

func (o *stopCanaryOwner) KillContainment(_ context.Context, _ leaseRecord) error {
	o.kills++
	return errors.Join(o.gate.Close(), o.killErr)
}
func (o *stopCanaryOwner) WaitContainmentEmpty(ctx context.Context, _ leaseRecord) error {
	o.waits++
	observation, err := o.gate.Stop(ctx, o.handle)
	if err != nil {
		return err
	}
	if observation.State != "exited" {
		return failure(api.CodeContainmentUnknown, "canary wait did not reap its process")
	}
	o.waited = true
	return o.waitErr
}
func (o *stopCanaryOwner) Quiescent(ctx context.Context, record leaseRecord) error {
	if !o.waited {
		return failure(api.CodeContainmentUnknown, "canary has not been waited on")
	}
	return o.observedResources.Quiescent(ctx, record)
}

type stopBroker struct {
	api.CredentialProjectionBroker
	owner   *stopCanaryOwner
	store   leaseStorage
	failure error
	calls   int
	ordered bool
	fenced  bool
	request api.CredentialWithdrawalRequest
}

func (b *stopBroker) BeginCredentialWithdrawal(_ context.Context, q api.CredentialWithdrawalRequest) (api.CredentialProjectionRecord, error) {
	b.calls++
	b.request = q
	b.ordered = b.owner.kills > 0 && b.owner.waits > 0 && b.owner.waited
	records, err := b.store.Records()
	if err != nil {
		return api.CredentialProjectionRecord{}, err
	}
	if len(records) == 1 {
		r := records[0]
		b.fenced = r.Revoked && r.Credentials != nil && r.Credentials.Stop != nil
	}
	return api.CredentialProjectionRecord{}, b.failure
}

// The receipt/authority is comparison metadata for an existing holding, not a
// simulated successful broker authentication, projection or withdrawal. The
// held destination is real and must remain open after the broker refusal.
func stopCredentialFixture(t *testing.T, opened bool, identities ...[2]uint32) (*leaseManager, gateOpenRegistration, *nativeGate, *fileLeaseStore, *stopCanaryOwner, *stopBroker, *os.File) {
	t.Helper()
	m, registration, g, store, owner, broker, held, _ := stopCredentialFixtureControl(t, opened, identities...)
	return m, registration, g, store, owner, broker, held
}

func stopCredentialFixtureControl(t *testing.T, opened bool, identities ...[2]uint32) (*leaseManager, gateOpenRegistration, *nativeGate, *fileLeaseStore, *stopCanaryOwner, *stopBroker, *os.File, *os.File) {
	t.Helper()
	m, registration, g, reader, store, hold := retainedGateFixtureControl(t, identities...)
	m, registration, g, store, owner, broker, held := stopCredentialsForGate(t, opened, m, registration, g, reader, store)
	owner.finish = hold
	return m, registration, g, store, owner, broker, held, hold
}

func stopCredentialsForGate(t *testing.T, opened bool, m *leaseManager, registration gateOpenRegistration, g *nativeGate, reader *os.File, store *fileLeaseStore) (*leaseManager, gateOpenRegistration, *nativeGate, *fileLeaseStore, *stopCanaryOwner, *stopBroker, *os.File) {
	t.Helper()
	records, err := store.Records()
	if err != nil || len(records) != 1 {
		t.Fatal("stop fixture journal unavailable")
	}
	r := records[0]
	prepare := r.Gate.Request
	expires := api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	claim := api.EffectLease{ClaimID: "stop-claim", ExpiresAt: expires, Record: api.EffectRecord{State: api.EffectClaimed, Generation: 1, ClaimID: "stop-claim", ClaimantID: "stop-service", ClaimExpiresAt: expires, Effect: api.Effect{ID: prepare.Cause.EffectID, OperationID: prepare.Cause.CauseOperationID, Context: &prepare.Cause, HelperPrepare: &prepare}}}
	q := api.CredentialProjectionRequest{Cause: prepare.Cause, Claim: claim, Handoff: r.Spec.Handoff, Prepared: r.Gate.Prepared, Lease: r.Lease, Home: r.Storage.Binding.Home}
	if err := api.ValidateCredentialProjectionRequest(q, time.Now()); err != nil {
		t.Fatal(err)
	}
	targets, err := api.CredentialTargets(q, time.Now())
	if err != nil || len(targets) != 1 {
		t.Fatal("stop fixture selected unexpected credential targets")
	}
	home, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(home.Name(), targets[0].RelativePath)
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	id, err := randomID("ordinary-stop-canary-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(id), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(name, int(r.Lease.UID), int(r.Lease.GID)); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := credentialDescriptor(held, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := held.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
		if err := home.Close(); err != nil {
			t.Error(err)
		}
	})
	a := api.CredentialProjectionAuthority{ID: "stop-projection", Generation: 1, Request: q, Targets: targets, Sources: []api.CredentialSourceVersion{{Key: targets[0].Key, Generation: 1, Version: "ordinary-source-version"}}}
	count, zero := uint64(len(targets)), uint64(0)
	receipt := api.CredentialProjectionReceipt{ProjectionID: a.ID, Generation: 2, Prepared: q.Prepared, HelperLeaseID: r.Lease.ID, SpecSHA256: q.Handoff.SpecSHA256, Home: q.Home, CancellationEpoch: q.Cause.CancellationEpoch, GateClosed: true, ObservedAt: gateTimestamp(), HeldDescriptors: &count, InheritedSources: &zero, Targets: []api.CredentialHeldTarget{{Target: targets[0], SourceObjectID: "outside-source-object", ObjectID: fact.ObjectID, RootID: q.Home.RootID, HomeGeneration: q.Home.Generation, OwnerUID: fact.OwnerUID, Mode: fact.Mode, ParentMode: 0700, Links: fact.Links}}}
	projection := api.CredentialProjectionRecord{Authority: a, State: "held", Generation: 2, Receipt: &receipt}
	if opened {
		if _, err := m.openGate(context.Background(), registration); err != nil {
			t.Fatal(err)
		}
		if err := reader.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, len(g.token))
		if _, err := io.ReadFull(reader, data); err != nil || string(data) != g.token {
			t.Fatal("stop canary did not reach its running control")
		}
		records, err = store.Records()
		if err != nil || len(records) != 1 {
			t.Fatal("opened stop fixture unavailable")
		}
		r = records[0]
	}
	r.Credentials = &credentialJournal{State: "held", Record: &projection, Request: &q}
	if err := m.save(r); err != nil {
		t.Fatal(err)
	}
	// Exercise the same persisted decoder and manager validation that stop
	// and recovery will use. A typed save alone cannot prove those bytes are
	// readable, and this check does not replace the real process kill/wait.
	roundtrip, err := m.records()
	if err != nil || len(roundtrip) != 1 || !reflect.DeepEqual(roundtrip[0].Credentials, r.Credentials) {
		t.Fatal("acceptance: credential journal did not survive persisted readback")
	}
	owner := &stopCanaryOwner{observedResources: &observedResources{}, gate: g, handle: gateHandle(r)}
	broker := &stopBroker{owner: owner, store: store, failure: errors.New("ordinary broker unavailable")}
	m.resources = owner
	m.credentials = &credentialRuntime{manager: m, broker: broker, held: map[api.ID]*heldCredentials{a.ID: {record: projection, home: home, files: []*os.File{held}}}}
	return m, registration, g, store, owner, broker, held
}

func assertStoppedOwned(t *testing.T, m *leaseManager, g *nativeGate, store *fileLeaseStore, owner *stopCanaryOwner, broker *stopBroker, held *os.File, err error) {
	t.Helper()
	if broker.calls != 1 || !broker.ordered || !owner.waited || owner.kills == 0 || owner.waits == 0 {
		t.Fatal("acceptance: credential error prevented kill and wait")
	}
	select {
	case <-g.done:
	default:
		t.Fatal("acceptance: credential stop returned before native wait")
	}
	if !errors.Is(err, broker.failure) {
		t.Fatal("acceptance: broker withdrawal failure was swallowed")
	}
	records, readErr := store.Records()
	if readErr != nil || len(records) != 1 {
		t.Fatal("stopped credential journal unavailable")
	}
	r := records[0]
	if !broker.fenced || !r.Revoked || r.Credentials == nil || r.Credentials.Stop == nil || r.Credentials.State != "held" || r.Credentials.Record.State != "held" || r.Credentials.Record.Generation != 2 {
		t.Fatal("acceptance: broker error lost the local fence or invented withdrawal")
	}
	if _, err := held.Stat(); err != nil {
		t.Fatal("acceptance: failed withdrawal discarded its held descriptor")
	}
	if err := m.ensureCredentialsWithdrawn(r); err == nil {
		t.Fatal("acceptance: owned credentials allowed lease collection")
	}
	if err := m.collectPrivateStorage(context.Background(), &r); err == nil || r.Storage.Collected || len(owner.removed) != 0 {
		t.Fatal("acceptance: owned credentials allowed lease collection")
	}
	if err := m.requireActive(r, storageReady); err == nil {
		t.Fatal("acceptance: locally stopped credentials regained launch authority")
	}
}

func TestCredRevokeFailure(t *testing.T) {
	m, registration, g, store, owner, broker, held := stopCredentialFixture(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	matched, err := m.revokeNativeContainment(ctx, registration.Binding.Record.ID)
	if !matched {
		t.Fatal("credential revocation missed the retained lane")
	}
	assertStoppedOwned(t, m, g, store, owner, broker, held, err)
	if broker.request.Reason != "revoked" || broker.request.Cause.Kind != api.InternalHelperStop || broker.request.Cause.ID == registration.Request.Cause.ID {
		t.Fatal("acceptance: native revocation did not retain its synthesized stop cause")
	}
	records, err := store.Records()
	if err != nil || len(records) != 1 {
		t.Fatal("revoked retry journal unavailable")
	}
	cause := registration.Request.Cause
	cause.Kind = api.InternalHelperRelease
	err = m.withdrawProjection(ctx, &records[0], cause, "release")
	if !errors.Is(err, broker.failure) || broker.request.Reason != "revoked" {
		t.Fatal("acceptance: retry weakened locally revoked credential cleanup")
	}
	cause.Kind = api.InternalHelperStop
	err = m.withdrawProjection(ctx, &records[0], cause, "cancelled")
	if !errors.Is(err, broker.failure) || broker.request.Reason != "revoked" {
		t.Fatal("acceptance: later stop replaced the retained revocation reason")
	}
}

func TestCredStopFailure(t *testing.T) {
	m, registration, g, store, owner, broker, held := stopCredentialFixture(t, true)
	cause := registration.Request.Cause
	cause.Kind = api.InternalHelperStop
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := m.stopGate(ctx, api.HelperStopRequest{Cause: cause, Target: api.HelperObserveRequest{LeaseID: registration.Binding.Record.UIDLeaseID, Handle: gateHandleFrom(registration)}, Reason: "component stop", OperationID: cause.CauseOperationID, EffectID: cause.EffectID})
	assertStoppedOwned(t, m, g, store, owner, broker, held, err)
	if broker.request.Reason != "cancelled" {
		t.Fatalf("ordinary stop must retain its distinct withdrawal reason: reason=%s", broker.request.Reason)
	}
}

func TestCredStopThenRevoke(t *testing.T) {
	m, registration, _, store, _, broker, held := stopCredentialFixture(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cause := registration.Request.Cause
	cause.Kind = api.InternalHelperStop
	_, err := m.stopGate(ctx, api.HelperStopRequest{Cause: cause,
		Target: api.HelperObserveRequest{LeaseID: registration.Binding.Record.UIDLeaseID, Handle: gateHandleFrom(registration)},
		Reason: "component stop", OperationID: cause.CauseOperationID, EffectID: cause.EffectID})
	if !errors.Is(err, broker.failure) || broker.request.Reason != api.CredentialStopReason {
		t.Fatal("stop control did not retain its unfinished cancelled fence", err)
	}
	matched, err := m.revokeNativeContainment(ctx, registration.Binding.Record.ID)
	if !matched || !errors.Is(err, broker.failure) || broker.request.Reason != "revoked" {
		t.Fatal("LB-304 a later revoke did not escalate the pending stop", err)
	}
	records, err := store.Records()
	if err != nil || len(records) != 1 || records[0].Credentials.Stop == nil || records[0].Credentials.Stop.Reason != "revoked" {
		t.Fatal("LB-304 escalated stop did not survive journal readback", err)
	}
	if _, err := held.Stat(); err != nil || m.ensureCredentialsWithdrawn(records[0]) == nil {
		t.Fatal("LB-304 revocation discarded its quarantined holding", err)
	}
	if err := m.fenceStopped(&records[0], cause, api.CredentialStopReason); err != nil {
		t.Fatal(err)
	}
	records, err = store.Records()
	if err != nil || len(records) != 1 || records[0].Credentials.Stop.Reason != "revoked" {
		t.Fatal("LB-304 a later stop downgraded the persisted revocation", err)
	}
}

func gateHandleFrom(registration gateOpenRegistration) api.ProcessHandle {
	return api.ProcessHandle{ID: registration.Binding.Record.ID, Target: registration.Request.Prepared.Target, ContainmentID: registration.Request.Prepared.ContainmentID, Generation: registration.Request.Prepared.ProcessGeneration}
}

func TestCredAbortFailure(t *testing.T) {
	m, registration, g, store, owner, broker, held := stopCredentialFixture(t, false)
	cause := registration.Request.Cause
	cause.Kind = api.InternalHelperAbort
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := m.abort(ctx, api.HelperAbortRequest{Cause: cause, LeaseID: registration.Binding.Record.UIDLeaseID, PreparedID: registration.Request.Prepared.ID, SpecSHA256: registration.Request.Prepared.SpecSHA256, OperationID: cause.CauseOperationID, EffectID: cause.EffectID})
	assertStoppedOwned(t, m, g, store, owner, broker, held, err)
	records, err := store.Records()
	if err != nil || records[0].Gate.State != "aborted" || records[0].AbortReceipt != nil {
		t.Fatal("acceptance: failed credential abort invented collection or execution")
	}
}

func TestCredWaitFailure(t *testing.T) {
	for repeat := range 3 {
		t.Run(strconv.Itoa(repeat), testCredWaitFailure)
	}
}

func testCredWaitFailure(t *testing.T) {
	m, registration, _, store, owner, broker, _ := stopCredentialFixture(t, true)
	waitErr := errors.New("ordinary population wait failure")
	owner.waitErr = waitErr
	cause := registration.Request.Cause
	cause.Kind = api.InternalHelperStop
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := m.stopGate(ctx, api.HelperStopRequest{Cause: cause, Target: api.HelperObserveRequest{LeaseID: registration.Binding.Record.UIDLeaseID, Handle: gateHandleFrom(registration)}, Reason: "component stop", OperationID: cause.CauseOperationID, EffectID: cause.EffectID})
	records, readErr := store.Records()
	if !errors.Is(err, waitErr) || broker.calls != 0 || !owner.waited || readErr != nil || len(records) != 1 || !records[0].Revoked || records[0].Credentials.Stop == nil {
		t.Fatal("acceptance: unknown containment wait permitted credential cleanup")
	}
}

func TestCredFenceRecovery(t *testing.T) {
	before := &credentialJournal{State: "receiving"}
	after := *before
	after.Stop = &credentialStop{Cause: testCause(api.InternalHelperStop, "life-a"), Reason: "revoked"}
	if err := credentialRecoveryTransition(before, &after); err != nil {
		t.Fatal(err)
	}
	if err := credentialRecoveryTransition(&after, before); err == nil {
		t.Fatal("acceptance: recovery removed the local credential stop fence")
	}
	changed := after
	fence := *after.Stop
	changed.Stop = &fence
	changed.Stop.Reason = "release"
	if reflect.DeepEqual(after.Stop, changed.Stop) || credentialRecoveryTransition(&after, &changed) == nil {
		t.Fatal("acceptance: recovery weakened the retained credential stop fence")
	}
}

func TestCredKillFailure(t *testing.T) {
	m, registration, g, store, owner, broker, held := stopCredentialFixture(t, true)
	killErr := errors.New("ordinary containment kill failure")
	owner.killErr = killErr
	cause := registration.Request.Cause
	cause.Kind = api.InternalHelperStop
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := m.stopGate(ctx, api.HelperStopRequest{Cause: cause, Target: api.HelperObserveRequest{LeaseID: registration.Binding.Record.UIDLeaseID, Handle: gateHandleFrom(registration)}, Reason: "component stop", OperationID: cause.CauseOperationID, EffectID: cause.EffectID})
	if !errors.Is(err, killErr) || !owner.waited || owner.waits == 0 || broker.calls != 0 {
		t.Fatal("acceptance: failed containment kill bypassed native wait")
	}
	select {
	case <-g.done:
	default:
		t.Fatal("acceptance: failed containment kill bypassed native wait")
	}
	records, readErr := store.Records()
	if readErr != nil || len(records) != 1 || !records[0].Revoked || records[0].Credentials.Stop == nil || m.ensureCredentialsWithdrawn(records[0]) == nil {
		t.Fatal("acceptance: failed containment kill lost credential ownership")
	}
	if _, err := held.Stat(); err != nil {
		t.Fatal("acceptance: failed containment kill lost credential ownership")
	}
}
