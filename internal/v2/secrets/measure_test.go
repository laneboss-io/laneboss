//go:build linux

package secrets

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

func retainedWithdrawalSlots(t *testing.T, m *projectionModel) {
	t.Helper()
	for _, id := range m.a.Request.Handoff.Spec.Injection.SlotIDs {
		slot := readCaseSlot(t, m.c, id)
		live := !slot.Released && len(slot.Material) > 0
		clear(slot.Material)
		clear(slot.Returned)
		if !live {
			t.Fatal("resource refusal released retained slots")
		}
	}
}

// Duplicate the real owning file description, so closing the broker's original
// leaves a kernel lock alive. The product's independent probe must observe it.
func duplicateRefreshLease(t *testing.T, c *launchCase) *os.File {
	t.Helper()
	path := filepath.Join(c.directory, ".refresh-"+string(c.profile.LoginID)+".lock")
	identity, err := os.Stat(path)
	if err != nil {
		t.Fatal("cannot inspect owned refresh lock")
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("cannot inspect owned refresh descriptor scope")
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal("owned descriptor selector is invalid")
		}
		info, err := os.Stat("/proc/self/fd/" + entry.Name())
		if err != nil || !os.SameFile(identity, info) {
			continue
		}
		dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			t.Fatal("cannot retain actual refresh lock duplicate")
		}
		file := os.NewFile(uintptr(dup), "refresh-lock-control")
		t.Cleanup(func() {
			if _, err := file.Stat(); err == nil {
				if err := file.Close(); err != nil {
					t.Error("cannot close retained refresh duplicate")
				}
			}
		})
		return file
	}
	t.Fatal("actual refresh lease descriptor was not retained")
	return nil
}

func TestLiveWithdrawal(t *testing.T) {
	for _, fault := range []string{"original", "lease", "missing", "helper"} {
		t.Run(fault, func(t *testing.T) {
			m, _ := projectionCase(t)
			record, transfer := reviewWithdrawal(t, m, "release", fault != "original")
			f := m.c.service.flight(m.a.ID)
			ctx := context.Background()
			switch fault {
			case "original":
				for _, file := range transfer.Files[1:] {
					if err := file.Close(); err != nil {
						t.Fatal("cannot close descriptor control siblings")
					}
				}
				f.closed = true // Simulate precisely the stale flag from the review.
				t.Cleanup(func() {
					if _, err := transfer.Files[0].Stat(); err == nil {
						if err := transfer.Files[0].Close(); err != nil {
							t.Error("cannot close surviving original control")
						}
					}
				})
				count, err := f.brokerDescriptorCount()
				if err != nil || count != 1 {
					t.Fatal("open broker descriptor was reported absent")
				}
				_, err = m.c.service.FinishCredentialWithdrawal(ctx, record, m.withdrawal)
				if !hasCode(err, api.CodeContainmentUnknown) {
					t.Fatal("live broker descriptor completed withdrawal")
				}
			case "lease":
				count, err := f.refreshLeaseCount()
				if err != nil || count != 1 {
					t.Fatal("live refresh lease was not measured before withdrawal")
				}
				duplicate := duplicateRefreshLease(t, m.c)
				_, err = m.c.service.FinishCredentialWithdrawal(ctx, record, m.withdrawal)
				if !hasCode(err, api.CodeInvalid) {
					t.Fatal("live refresh lock completed withdrawal")
				}
				retainedWithdrawalSlots(t, m)
				count, err = f.refreshLeaseCount()
				if err != nil || count != 1 {
					t.Fatal("closed original hid a surviving kernel refresh lock")
				}
				if err := duplicate.Close(); err != nil {
					t.Fatal("cannot release actual refresh duplicate")
				}
				done, err := m.c.service.FinishCredentialWithdrawal(ctx, record, m.withdrawal)
				if err != nil || done.Withdrawal == nil || done.Withdrawal.RefreshLeases == nil || *done.Withdrawal.RefreshLeases != 0 {
					t.Fatal("measured refresh collection did not complete")
				}
				if err := f.checkRefreshLease(m.a.Targets[0].SlotID); !hasCode(err, api.CodeConflict) {
					t.Fatal("retired refresh lease remained usable")
				}
				return
			case "missing":
				leases := f.refresh
				f.refresh = nil
				t.Cleanup(func() { f.refresh = leases })
				_, err := m.c.service.FinishCredentialWithdrawal(ctx, record, m.withdrawal)
				if !hasCode(err, api.CodePrerequisite) {
					t.Fatal("missing live refresh inventory completed withdrawal")
				}
			case "helper":
				one := uint64(1)
				m.withdrawal.ProjectedFiles = &one
				_, err := m.c.service.FinishCredentialWithdrawal(ctx, record, m.withdrawal)
				if !hasCode(err, api.CodeInvalid) {
					t.Fatal("bad helper shape completed withdrawal")
				}
				count, err := f.refreshLeaseCount()
				if err != nil || count != 1 {
					t.Fatal("bad helper shape retired the live refresh lease")
				}
			}
			retainedWithdrawalSlots(t, m)
		})
	}
}

func TestWritableAliases(t *testing.T) {
	file, err := exportCredential(syntheticBytes(t, 47))
	if err != nil {
		t.Fatal("cannot export alias measurement control")
	}
	defer file.Close()
	before, err := credentialFact(file)
	if err != nil || before.WritableHandles == nil || *before.WritableHandles != 0 {
		t.Fatal("unaliased credential measurement failed")
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.FormatUint(uint64(file.Fd()), 10), unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("cannot open owned write-access alias")
	}
	alias := os.NewFile(uintptr(fd), "credential-alias-control")
	defer alias.Close()
	if _, err := alias.WriteAt([]byte{'x'}, 0); err == nil {
		t.Fatal("immutable seal allowed a control write")
	}
	withAlias, err := credentialFact(file)
	if err != nil || withAlias.WritableHandles == nil || *withAlias.WritableHandles != 1 {
		t.Fatal("write-access alias was reported absent")
	}
	if err := alias.Close(); err != nil {
		t.Fatal("cannot close write-access alias")
	}
	after, err := credentialFact(file)
	if err != nil || after.WritableHandles == nil || *after.WritableHandles != 0 {
		t.Fatal("closed write-access alias remained in measurement")
	}
}

type withdrawalLockBackend struct {
	*measuredBackend
	calls int
}

func (b *withdrawalLockBackend) WithBroker(ctx context.Context, fn func(bstate.Journal) error) error {
	b.calls++
	return b.measuredBackend.WithBroker(ctx, fn)
}
func (b *withdrawalLockBackend) WithBrokerDurable(ctx context.Context, fn func(bstate.Journal) error) error {
	b.calls++
	return b.measuredBackend.WithBrokerDurable(ctx, fn)
}

func TestWithdrawalLock(t *testing.T) {
	for _, phase := range []string{"begin", "finish"} {
		t.Run(phase, func(t *testing.T) {
			m, peer := projectionCase(t)
			ctx := context.Background()
			var record api.CredentialProjectionRecord
			if phase == "finish" {
				record, _ = reviewWithdrawal(t, m, "release", true)
			} else {
				transfer, err := m.c.service.TransferCredentials(ctx, peer, m.a.Request)
				if err != nil {
					t.Fatal("cannot export locked withdrawal control")
				}
				var errAck error
				record, errAck = m.c.service.AcknowledgeCredentials(ctx, m.hold(t, transfer))
				if errAck != nil {
					t.Fatal("cannot hold locked withdrawal control")
				}
			}
			version := api.CredentialSourceVersion{Key: m.a.Targets[0].SlotID, Generation: 2, Version: "two"}
			if err := m.c.backend.WithBroker(ctx, func(j bstate.Journal) error {
				var projection bstate.Projection
				if err := j.Read("projection", m.a.ID, &projection); err != nil {
					return err
				}
				projection.Refresh, projection.RefreshObject = &version, "retained-refresh-object"
				return j.Write("projection", m.a.ID, projection)
			}); err != nil {
				t.Fatal("cannot retain concurrent refresh metadata")
			}
			backend := &withdrawalLockBackend{measuredBackend: m.c.backend}
			m.c.service.deps.Backend = backend
			var err error
			if phase == "begin" {
				cause := m.a.Request.Cause
				cause.ID, cause.Kind, cause.EffectID = "locked-release", api.InternalHelperRelease, "locked-release-effect"
				_, err = m.c.service.BeginCredentialWithdrawal(ctx, api.CredentialWithdrawalRequest{ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Cause: cause, Reason: "release"})
			} else {
				_, err = m.c.service.FinishCredentialWithdrawal(ctx, record, m.withdrawal)
			}
			if err != nil {
				t.Fatal("locked withdrawal control did not complete its step")
			}
			if backend.calls != 1 {
				t.Fatal("withdrawal decision crossed journal locks")
			}
			var projection bstate.Projection
			if err := m.c.backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("projection", m.a.ID, &projection) }); err != nil {
				t.Fatal("cannot read locked withdrawal result")
			}
			if !reflect.DeepEqual(projection.Refresh, &version) || projection.RefreshObject != "retained-refresh-object" || !projection.Fenced {
				t.Fatal("withdrawal erased current refresh metadata")
			}
		})
	}
}

type clearingJournal struct {
	bstate.Journal
	id      api.ID
	fault   string
	buffers [][]byte
}

func (j *clearingJournal) Read(kind string, id api.ID, out any) error {
	err := j.Journal.Read(kind, id, out)
	if err != nil {
		return err
	}
	if slot, ok := out.(*bstate.Slot); ok && kind == "slot" && id == j.id {
		j.buffers = append(j.buffers, slot.Material, slot.Returned)
	}
	if kind == "profile" && j.fault == "profile" || kind == "login" && j.fault == "login" {
		return wire.Error(api.CodeUnavailable, "synthetic protected read interruption")
	}
	if login, ok := out.(*bstate.Login); ok && kind == "login" && j.fault == "owner" {
		login.Quarantined = true
	}
	return nil
}

func TestSlotClearing(t *testing.T) {
	for _, fault := range []string{"profile", "validator", "login", "owner"} {
		t.Run(fault, func(t *testing.T) {
			m, _ := projectionCase(t)
			id := m.a.Targets[0].SlotID
			ctx := context.Background()
			returned := syntheticBytes(t, 23)
			defer clear(returned)
			if err := m.c.backend.WithBroker(ctx, func(j bstate.Journal) error {
				var slot bstate.Slot
				if err := j.Read("slot", id, &slot); err != nil {
					return err
				}
				defer clear(slot.Material)
				slot.Returned = append([]byte(nil), returned...)
				defer clear(slot.Returned)
				return j.Write("slot", id, slot)
			}); err != nil {
				t.Fatal("cannot retain zeroization control buffers")
			}
			if err := m.c.backend.WithBroker(ctx, func(j bstate.Journal) error {
				slots, _, err := m.c.service.projectionSlots(ctx, j, m.a)
				defer clearProjectionSlots(slots)
				if err != nil || len(slots) == 0 || !bytes.Equal(slots[0].Material, m.c.material) || !bytes.Equal(slots[0].Returned, returned) {
					t.Fatal("successful projection cleared or changed selected buffers")
				}
				return err
			}); err != nil {
				t.Fatal("cannot select positive zeroization control")
			}
			if fault == "validator" {
				m.c.service.deps.CodexValidator = nil
			}
			var capture *clearingJournal
			err := m.c.backend.WithBroker(ctx, func(j bstate.Journal) error {
				capture = &clearingJournal{Journal: j, id: id, fault: fault}
				slots, _, err := m.c.service.projectionSlots(ctx, capture, m.a)
				clearProjectionSlots(slots)
				return err
			})
			if err == nil || capture == nil || len(capture.buffers) != 2 || len(capture.buffers[0]) == 0 || len(capture.buffers[1]) == 0 {
				t.Fatal("zeroization control did not reach selected buffers")
			}
			for _, buffer := range capture.buffers {
				if !bytes.Equal(buffer, make([]byte, len(buffer))) {
					t.Fatal("refused projection retained a selected secret buffer")
				}
			}
		})
	}
}

type historicalPolicyStore struct {
	api.StateStore
	historical api.EffectivePolicy
}

func (s historicalPolicyStore) Policy(context.Context, api.Scope) (api.EffectivePolicy, error) {
	return s.historical, nil
}

func TestCurrentPolicy(t *testing.T) {
	for _, port := range []string{"agent", "worker", "delivery"} {
		t.Run(port, func(t *testing.T) {
			ctx := context.Background()
			if port == "worker" {
				c, lease, _, _ := newWorkerCase(t)
				prior, err := c.store.CurrentApprovedPolicy(ctx, c.service.deps.ServiceScope)
				if err != nil {
					t.Fatal("cannot read prior worker policy")
				}
				c.store.policy.Generation++
				c.service.deps.Store = historicalPolicyStore{c.store, prior}
				_, err = c.service.currentWorkerGrants(ctx, lease)
				if !hasCode(err, api.CodeConflict) {
					t.Fatal("worker credentials used historical policy")
				}
				return
			}
			c := newLaunchCase(t, "headless_token")
			var slot bstate.Slot
			if port == "delivery" {
				issued, err := c.acquire(ctx, c.target, c.grant)
				if err != nil {
					t.Fatal("cannot prepare policy source control")
				}
				slot = readCaseSlot(t, c, issued.ID)
				defer clear(slot.Material)
			}
			prior, err := c.store.CurrentApprovedPolicy(ctx, c.service.deps.ServiceScope)
			if err != nil {
				t.Fatal("cannot read prior agent policy")
			}
			c.store.policy.Generation++
			c.service.deps.Store = historicalPolicyStore{c.store, prior}
			if port == "agent" {
				selector, selectErr := c.selection(ctx)
				if selectErr != nil {
					t.Fatal(selectErr)
				}
				_, err = c.service.currentGrants(ctx, c.target, selector)
			} else {
				err = c.backend.WithBroker(ctx, func(j bstate.Journal) error { return c.service.deliveryPolicy(ctx, j, slot) })
			}
			if !hasCode(err, api.CodeConflict) {
				t.Fatal("agent credentials used historical policy")
			}
		})
	}
}

type tickerStore struct {
	api.StateStore
	fault   string
	changed atomic.Bool
	openID  api.ID
}

func (s *tickerStore) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	policy, err := s.StateStore.CurrentApprovedPolicy(ctx, scope)
	if s.changed.Load() && s.fault == "policy" {
		policy.Generation++
	}
	return policy, err
}
func (s *tickerStore) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	record, err := s.StateStore.Effect(ctx, scope, id)
	if s.changed.Load() && s.fault == "claim" && id == s.openID {
		record.State = api.EffectCompleted
	}
	return record, err
}
func (s *tickerStore) Grants(ctx context.Context, id api.ID) (api.GrantSet, error) {
	grants, err := s.StateStore.Grants(ctx, id)
	if s.changed.Load() && s.fault == "grants" {
		grants.Revoked = true
	}
	return grants, err
}
func (s *tickerStore) Lane(ctx context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	lane, err := s.StateStore.Lane(ctx, scope, target)
	if s.changed.Load() && s.fault == "epoch" {
		lane.CancellationEpoch++
	}
	return lane, err
}

func TestGateTicker(t *testing.T) {
	for _, fault := range []string{"policy", "claim", "grants", "epoch"} {
		t.Run(fault, func(t *testing.T) {
			m, peer := projectionCase(t)
			s := m.c.service
			ctx := context.Background()
			transfer, err := s.TransferCredentials(ctx, peer, m.a.Request)
			if err != nil {
				t.Fatal("cannot export ticker control")
			}
			held, err := s.AcknowledgeCredentials(ctx, m.hold(t, transfer))
			if err != nil {
				t.Fatal("cannot hold ticker control")
			}
			store := &tickerStore{StateStore: s.deps.Store, fault: fault, openID: m.open.EffectID}
			s.deps.Store = store
			guard, err := s.lockCredentialProjection(ctx, api.CredentialGateRequest{ProjectionID: m.a.ID, ExpectedGeneration: held.Generation, Open: m.open}, nil)
			if err != nil {
				t.Fatal("cannot acquire ticker control guard")
			}
			t.Cleanup(func() { guard.Close() })
			store.changed.Store(true)
			select {
			case <-guard.done:
			case <-time.After(2 * time.Second):
				guard.Close()
				t.Fatal("gate ticker retained stale authority")
			}
			if err := guard.Close(); err == nil {
				t.Fatal("gate ticker lost its authority refusal")
			}
			var projection bstate.Projection
			if err := m.c.backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("projection", m.a.ID, &projection) }); err != nil {
				t.Fatal("cannot read ticker failure fence")
			}
			if !projection.Fenced {
				t.Fatal("gate ticker authority refusal was not durable")
			}
		})
	}
}
