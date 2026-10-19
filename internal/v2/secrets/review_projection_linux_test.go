//go:build linux

package secrets

import (
	"bytes"
	"context"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
	"reflect"
	"testing"
	"time"
)

type reviewBackend struct {
	*measuredBackend
	failAt, writes int
	before         func()
}
type reviewJournal struct {
	bstate.Journal
	owner *reviewBackend
}

func (j reviewJournal) Write(kind string, id api.ID, value any) error {
	j.owner.writes++
	if j.owner.failAt > 0 && j.owner.writes == j.owner.failAt {
		return wire.Error(api.CodeUnavailable, "synthetic journal write interruption")
	}
	return j.Journal.Write(kind, id, value)
}
func (b *reviewBackend) wrap(j bstate.Journal, fn func(bstate.Journal) error) error {
	if b.before != nil {
		f := b.before
		b.before = nil
		f()
	}
	return fn(reviewJournal{j, b})
}
func (b *reviewBackend) WithBroker(ctx context.Context, fn func(bstate.Journal) error) error {
	return b.measuredBackend.WithBroker(ctx, func(j bstate.Journal) error { return b.wrap(j, fn) })
}
func (b *reviewBackend) WithBrokerDurable(ctx context.Context, fn func(bstate.Journal) error) error {
	return b.measuredBackend.WithBrokerDurable(ctx, func(j bstate.Journal) error { return b.wrap(j, fn) })
}

func reviewWithdrawal(t *testing.T, m *projectionModel, reason string, ack bool) (api.CredentialProjectionRecord, api.CredentialTransfer) {
	t.Helper()
	s := m.c.service
	ctx := context.Background()
	peer := &usagePeerFixture{facts: m.a.HelperPeer}
	transfer, err := s.TransferCredentials(ctx, peer, m.a.Request)
	if err != nil {
		t.Fatal("cannot export review withdrawal")
	}
	generation := m.a.Generation
	if ack {
		held, err := s.AcknowledgeCredentials(ctx, m.hold(t, transfer))
		if err != nil {
			t.Fatal("cannot hold review withdrawal")
		}
		generation = held.Generation
	}
	cause := m.a.Request.Cause
	cause.ID, cause.Kind, cause.EffectID = "review-release", api.InternalHelperRelease, "review-release-effect"
	record, err := s.BeginCredentialWithdrawal(ctx, api.CredentialWithdrawalRequest{ProjectionID: m.a.ID, ExpectedGeneration: generation, Cause: cause, Reason: reason})
	if err != nil {
		t.Fatal("cannot fence review withdrawal")
	}
	observation := m.c.finish(t, api.ProcessObservation{Handle: api.ProcessHandle{ID: "process-a", Target: m.c.target, ContainmentID: m.a.Request.Prepared.ContainmentID, Generation: m.a.Request.Prepared.ProcessGeneration}})
	observation.ObservedAt = api.Timestamp(m.c.clock.Now().Format(time.RFC3339Nano))
	zero := uint64(0)
	m.withdrawal = api.CredentialWithdrawalReceipt{ProjectionID: m.a.ID, Generation: record.Generation + 1, Cause: cause, Prepared: m.a.Request.Prepared, HelperLeaseID: m.a.Request.Lease.ID, Home: m.a.Request.Home, Observation: observation, HelperDescriptors: &zero, ProjectedFiles: &zero, EnvironmentBuffers: &zero, OpenGates: &zero, ObservedAt: observation.ObservedAt}
	return record, transfer
}
func TestExposureQuarantine(t *testing.T) {
	for _, reason := range []string{"cancelled", "revoked"} {
		t.Run(reason, func(t *testing.T) {
			m, _ := projectionCase(t)
			record, transfer := reviewWithdrawal(t, m, reason, false)
			_, err := m.c.service.FinishCredentialWithdrawal(context.Background(), record, m.withdrawal)
			stageCode(t, err, api.CodeContainmentUnknown)
			var owner bstate.Login
			if err := m.c.backend.WithBroker(context.Background(), func(j bstate.Journal) error { return j.Read("login", m.c.profile.LoginID, &owner) }); err != nil {
				t.Fatal("cannot read quarantined owner")
			}
			defer clear(owner.Material)
			if !owner.Quarantined || owner.SlotID == "" {
				t.Fatal("exposure did not quarantine its retained canonical owner")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, acquireErr := m.c.acquire(ctx, m.c.target, m.c.grant)
			cancel()
			if !hasCode(acquireErr, api.CodeForbidden) {
				t.Fatal("quarantined login did not refuse acquisition immediately")
			}
			material, deliveryErr := m.c.service.SlotMaterial(context.Background(), m.a.Request.Handoff.Spec.LaunchID, m.a.Targets[0].SlotID)
			defer clear(material.Bytes)
			if !hasCode(deliveryErr, api.CodeForbidden) || len(material.Bytes) != 0 {
				t.Fatal("quarantined canonical material was delivered")
			}
			for _, file := range transfer.Files {
				if _, err := file.Stat(); err == nil {
					t.Fatal("exposure retained an original export descriptor")
				}
			}
			slot := readCaseSlot(t, m.c, m.a.Targets[0].SlotID)
			defer clear(slot.Material)
			if slot.Released || len(slot.Material) == 0 {
				t.Fatal("exposure freed an unreconciled slot")
			}
		})
	}
}

type failCompletion struct{ api.StateStore }

func (s failCompletion) CompleteCredentialWithdrawal(context.Context, api.Scope, api.CredentialWithdrawalReceipt) (api.CredentialProjectionRecord, error) {
	return api.CredentialProjectionRecord{}, wire.Error(api.CodeUnavailable, "synthetic completion interruption")
}
func TestWithdrawalCommit(t *testing.T) {
	m, _ := projectionCase(t)
	record, _ := reviewWithdrawal(t, m, "release", true)
	real := m.c.service.deps.Store
	m.c.service.deps.Store = failCompletion{real}
	_, err := m.c.service.FinishCredentialWithdrawal(context.Background(), record, m.withdrawal)
	for _, id := range m.a.Request.Handoff.Spec.Injection.SlotIDs {
		slot := readCaseSlot(t, m.c, id)
		defer clear(slot.Material)
		if slot.Released || len(slot.Material) == 0 {
			t.Fatal("failed completion released canonical material")
		}
	}
	var owner bstate.Login
	if err := m.c.backend.WithBroker(context.Background(), func(j bstate.Journal) error { return j.Read("login", m.c.profile.LoginID, &owner) }); err != nil {
		t.Fatal("cannot inspect interrupted completion")
	}
	defer clear(owner.Material)
	if owner.SlotID == "" {
		t.Fatal("failed completion released canonical material")
	}
	stageCode(t, err, api.CodeUnavailable)
	m.c.service.deps.Store = real
	if _, err := m.c.service.FinishCredentialWithdrawal(context.Background(), record, m.withdrawal); err != nil {
		t.Fatal("exact completion retry did not reconcile")
	}
}
func TestDurableFence(t *testing.T) {
	for _, phase := range []string{"exchange", "guard"} {
		t.Run(phase, func(t *testing.T) {
			m, peer := projectionCase(t)
			s := m.c.service
			if phase == "exchange" {
				_, err := s.transferCredentials(context.Background(), peer, m.a.Request, func(bstate.Journal, *projectionFlight) error {
					return wire.Error(api.CodeUnavailable, "synthetic control disconnect")
				})
				stageCode(t, err, api.CodeUnavailable)
			} else {
				transfer, err := s.TransferCredentials(context.Background(), peer, m.a.Request)
				if err != nil {
					t.Fatal("cannot export guard fence control")
				}
				held, err := s.AcknowledgeCredentials(context.Background(), m.hold(t, transfer))
				if err != nil {
					t.Fatal("cannot hold guard fence control")
				}
				ctx, cancel := context.WithCancel(context.Background())
				guard, err := s.LockCredentialProjection(ctx, api.CredentialGateRequest{ProjectionID: m.a.ID, ExpectedGeneration: held.Generation, Open: m.open})
				if err != nil {
					cancel()
					t.Fatal("cannot acquire guard fence control")
				}
				cancel()
				stageCode(t, guard.Close(), api.CodeCancelled)
			}
			var journal bstate.Projection
			if err := m.c.backend.WithBroker(context.Background(), func(j bstate.Journal) error { return j.Read("projection", m.a.ID, &journal) }); err != nil {
				t.Fatal("cannot inspect durable projection fence")
			}
			if !journal.Fenced {
				t.Fatal("native failure was fenced only in memory")
			}
		})
	}
}
func TestLiveSlotPolicy(t *testing.T) {
	c := newLaunchCase(t, "headless_token")
	ctx := context.Background()
	slot, err := c.acquire(ctx, c.target, c.grant)
	if err != nil {
		t.Fatal("cannot acquire live delivery control")
	}
	injection, err := c.inject(ctx, c.target, []api.SecretGrant{})
	if err != nil {
		t.Fatal("cannot inject live delivery control")
	}
	c.bind(t, slot, injection)
	material, err := c.service.SlotMaterial(ctx, c.plan(t).Reservation.LaunchID, slot.ID)
	if err != nil || !bytes.Equal(material.Bytes, c.material) {
		clear(material.Bytes)
		t.Fatal("current live slot did not deliver its selected material")
	}
	clear(material.Bytes)
	c.store.policy.Generation++
	c.store.lane.PolicyGeneration = c.store.policy.Generation
	material, err = c.service.SlotMaterial(ctx, c.plan(t).Reservation.LaunchID, slot.ID)
	defer clear(material.Bytes)
	if !hasCode(err, api.CodeConflict) || len(material.Bytes) != 0 {
		t.Fatal("stale live slot delivered credential material")
	}
}
func TestLockedPolicyRead(t *testing.T) {
	m, peer := projectionCase(t)
	b := &reviewBackend{measuredBackend: m.c.backend, before: func() { m.c.store.policy.Generation++ }}
	m.c.service.deps.Backend = b
	_, err := m.c.service.TransferCredentials(context.Background(), peer, m.a.Request)
	stageCode(t, err, api.CodeConflict)
}
func TestPartialBind(t *testing.T) {
	for _, kind := range []string{"profile", "task", "worker"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			var c *launchCase
			var bind func() error
			failAt := 2
			if kind == "worker" {
				var lease api.WorkerLease
				var credentials []api.WorkerCredential
				c, lease, credentials, _ = newWorkerCase(t)
				bind = func() error { _, err := c.service.InjectWorker(ctx, lease, credentials); return err }
			} else {
				c = newLaunchCase(t, "file_login")
				if kind == "profile" {
					failAt = 3
					bind = func() error { _, err := c.acquire(ctx, c.target, c.grant); return err }
				} else {
					// The profile and task must pin the same completed grant set.
					grant, _ := c.addSecret(t, "partial-task", "env", "PARTIAL_TASK")
					if _, err := c.acquire(ctx, c.target, c.grant); err != nil {
						t.Fatal("cannot establish partial task profile")
					}
					bind = func() error { _, err := c.inject(ctx, c.target, []api.SecretGrant{grant}); return err }
				}
			}
			b := &reviewBackend{measuredBackend: c.backend, failAt: failAt}
			c.service.deps.Backend = b
			err := bind()
			if b.writes != failAt {
				t.Fatal("partial bind did not reach its interrupted journal write")
			}
			stageCode(t, err, api.CodeUnavailable)
			b.failAt = 0
			if err := bind(); !hasCode(err, api.CodeConflict) {
				t.Fatal("partial credential bind was retried")
			}
		})
	}
}
func TestAckReplayShape(t *testing.T) {
	m, peer := projectionCase(t)
	s := m.c.service
	ctx := context.Background()
	transfer, err := s.TransferCredentials(ctx, peer, m.a.Request)
	if err != nil {
		t.Fatal("cannot export replay shape control")
	}
	receipt := m.hold(t, transfer)
	record, err := s.AcknowledgeCredentials(ctx, receipt)
	if err != nil {
		t.Fatal("cannot hold replay shape control")
	}
	receipt.Targets[0].ObjectID = receipt.Targets[0].SourceObjectID
	record.Receipt = &receipt
	if m.c.store.save("projection-held.json", receipt) != nil || m.c.store.save("projection-record.json", record) != nil {
		t.Fatal("cannot retain malformed correlated replay")
	}
	_, err = s.AcknowledgeCredentials(ctx, receipt)
	if !hasCode(err, api.CodeInvalid) {
		t.Fatal("held replay bypassed receipt validation")
	}
}
func TestTransferAckID(t *testing.T) {
	m, peer := projectionCase(t)
	s := m.c.service
	ctx := context.Background()
	transfer, err := s.TransferCredentials(ctx, peer, m.a.Request)
	if err != nil {
		t.Fatal("cannot export receipt ID control")
	}
	receipt := m.hold(t, transfer)
	if err := validateTransferReceiptID(transfer, receipt); err != nil {
		t.Fatal("matching receipt was refused")
	}
	receipt.ProjectionID = "foreign-projection"
	err = validateTransferReceiptID(transfer, receipt)
	if !hasCode(err, api.CodeForbidden) {
		t.Fatal("receipt selected another native transfer")
	}
	if _, exists := s.projections[receipt.ProjectionID]; exists {
		t.Fatal("foreign receipt created another flight")
	}
}

type approvedReviewStore struct {
	api.StateStore
	store *launchCaseStore
}

func (s approvedReviewStore) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	return s.store.Policy(ctx, scope)
}
func TestWorkerProjection(t *testing.T) {
	for _, phase := range []string{"binding", "marker"} {
		t.Run(phase, func(t *testing.T) {
			c, lease, credentials, _ := newWorkerCase(t, "usage")
			ctx := context.Background()
			injection, err := c.service.InjectWorker(ctx, lease, credentials)
			if err != nil {
				t.Fatal("cannot prepare native worker selection")
			}
			spec := c.retainWorkerSpec(t, lease, injection)
			var handoff api.PreparedSpecHandoff
			if c.store.read("handoff.json", &handoff) != nil {
				t.Fatal("cannot read native worker handoff")
			}
			c.service.deps.Store = approvedReviewStore{c.store, c.store}
			selected := credentials[0]
			a := api.CredentialProjectionAuthority{ID: "native-worker-projection", Request: api.CredentialProjectionRequest{Worker: &lease, Handoff: handoff, Prepared: api.PreparedLaunch{Target: lease.Target}, Lease: api.HelperLease{ID: spec.UIDLeaseID}}, Targets: []api.CredentialTarget{{Key: api.ID(selected.Name), GrantID: api.ID(selected.Name), SourceHandle: selected.SourceHandle, Version: selected.Version, Delivery: selected.Delivery, EnvironmentName: selected.Target}}}
			var slots []bstate.Slot
			err = c.backend.WithBroker(ctx, func(j bstate.Journal) error {
				var err error
				slots, _, err = c.service.projectionSlots(ctx, j, a)
				return err
			})
			if err != nil || len(slots) != 1 {
				t.Fatal("valid native worker selection was refused")
			}
			defer clearProjectionSlots(slots)
			if phase == "marker" {
				if err := c.backend.WithBroker(ctx, func(j bstate.Journal) error {
					var marker bstate.Slot
					id := credentialID("worker-selection", lease.ID)
					if err := j.Read("slot", id, &marker); err != nil {
						return err
					}
					marker.Injection.TaskSecretNames = []string{"changed"}
					return j.Write("slot", id, marker)
				}); err != nil {
					t.Fatal("cannot change native worker selection marker")
				}
				err = c.backend.WithBroker(ctx, func(j bstate.Journal) error {
					fresh, _, err := c.service.projectionSlots(ctx, j, a)
					clearProjectionSlots(fresh)
					return err
				})
				if !hasCode(err, api.CodeForbidden) {
					t.Fatal("native worker bypassed its selection marker")
				}
				return
			}
			bindProjectionSlot(&slots[0], a)
			slot := slots[0]
			if slot.Handoff == nil || !reflect.DeepEqual(*slot.Handoff, handoff) || slot.LaunchID != spec.LaunchID || slot.HelperLeaseID != spec.UIDLeaseID || slot.Backend != spec.Backend {
				t.Fatal("native worker lost its retained cleanup binding")
			}
			if err := c.backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Write("slot", slot.ID, slot) }); err != nil {
				t.Fatal("cannot retain native worker binding")
			}
			c.bindWorker(t, spec)
			var binding api.LaunchBindingRequest
			if c.store.read("binding.json", &binding) != nil {
				t.Fatal("cannot read native worker identity")
			}
			if err := c.service.workerSlotBinding(ctx, slot, binding); err != nil {
				t.Fatal("native worker cleanup rejected its retained handoff")
			}
		})
	}
}

type releaseEventHook struct {
	api.StateStore
	n     int
	hook  func() error
	fired bool
}

func (s *releaseEventHook) Events(ctx context.Context, scope api.Scope, q api.EventTailRequest) (api.EventPage, error) {
	page, err := s.StateStore.Events(ctx, scope, q)
	if err != nil {
		return page, err
	}
	s.n++
	if s.n == 3 {
		s.fired = true
		if err := s.hook(); err != nil {
			return api.EventPage{}, err
		}
	}
	return page, nil
}
func TestInjectionReleaseGroup(t *testing.T) {
	c := newLaunchCase(t, "file_login")
	ctx := context.Background()
	grant, _ := c.addSecret(t, "group-task", "env", "GROUP_TASK")
	profile, err := c.acquire(ctx, c.target, c.grant)
	if err != nil {
		t.Fatal("cannot acquire release group")
	}
	injection, err := c.inject(ctx, c.target, []api.SecretGrant{grant})
	if err != nil {
		t.Fatal("cannot inject release group")
	}
	observation := c.finish(t, c.bind(t, profile, injection))
	taskID := injection.SlotIDs[1]
	events := &releaseEventHook{StateStore: c.store}
	events.hook = func() error {
		return c.backend.WithBroker(ctx, func(j bstate.Journal) error {
			var slot bstate.Slot
			if err := j.Read("slot", taskID, &slot); err != nil {
				return err
			}
			defer clear(slot.Material)
			defer clear(slot.Returned)
			slot.Fingerprint = digestFixture("changed after complete measurement")
			return j.Write("slot", taskID, slot)
		})
	}
	c.service.deps.Store = events
	err = c.service.RevokeInjection(ctx, injection, observation)
	if !events.fired {
		t.Fatal("release group did not reach its final-slot interleave")
	}
	slot := readCaseSlot(t, c, profile.ID)
	defer clear(slot.Material)
	var owner bstate.Login
	if readErr := c.backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("login", c.profile.LoginID, &owner) }); readErr != nil {
		t.Fatal("cannot inspect release group owner")
	}
	defer clear(owner.Material)
	if slot.Released || owner.SlotID != profile.ID || !bytes.Equal(slot.Material, c.material) {
		t.Fatal("injection failure freed a profile lease")
	}
	stageCode(t, err, api.CodeConflict)
}
