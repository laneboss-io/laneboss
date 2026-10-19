//go:build linux

package secrets

import (
	"bytes"
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// Change actual retained authority at the final selected-slot read, after the
// earlier claim/policy checks. The hook runs under the real canonical journal;
// it neither substitutes material nor implements a successful delivery port.
type preparedReadBackend struct {
	*measuredBackend
	id    api.ID
	reads int
	fired bool
	hook  func(bstate.Journal) error
}
type preparedReadJournal struct {
	bstate.Journal
	owner *preparedReadBackend
}

func (j preparedReadJournal) Read(kind string, id api.ID, out any) error {
	if kind == "slot" && id == j.owner.id {
		j.owner.reads++
		if j.owner.reads == 2 {
			j.owner.fired = true
			if err := j.owner.hook(j.Journal); err != nil {
				return err
			}
		}
	}
	return j.Journal.Read(kind, id, out)
}
func (b *preparedReadBackend) WithBroker(ctx context.Context, fn func(bstate.Journal) error) error {
	return b.measuredBackend.WithBroker(ctx, func(j bstate.Journal) error {
		return fn(preparedReadJournal{Journal: j, owner: b})
	})
}

func TestPreparedPolicy(t *testing.T) {
	for _, port := range []string{"profile", "task"} {
		for _, fault := range []string{"quarantine", "pending", "excluded"} {
			t.Run(port+"/"+fault, func(t *testing.T) {
				c := newLaunchCase(t, "file_login")
				ctx := context.Background()
				grants := []api.SecretGrant{}
				want := c.material
				if port == "task" {
					grant, value := c.addSecret(t, "prepared-policy", "env", "PREPARED_POLICY")
					grants, want = append(grants, grant), value
				}
				// Acquire pins the complete grant digest in the profile slot.
				// Finish task enrollment before creating that retained selection.
				issued, err := c.acquire(ctx, c.target, c.grant)
				if err != nil {
					t.Fatal("cannot acquire prepared policy control")
				}
				injection, err := c.inject(ctx, c.target, grants)
				if err != nil {
					t.Fatal("cannot inject prepared policy control")
				}
				id := issued.ID
				if port == "task" {
					if len(injection.SlotIDs) != 2 {
						t.Fatal("prepared task control has no exact selected slot")
					}
					id = injection.SlotIDs[1]
				}
				c.beforeBind = func(t *testing.T, spec api.LaunchSpec) {
					material, err := c.service.PreparedSlotMaterial(ctx, spec, id)
					if err != nil || !bytes.Equal(material.Bytes, want) {
						clear(material.Bytes)
						t.Fatal("current prepared authority did not deliver selected bytes")
					}
					clear(material.Bytes)
					backend := &preparedReadBackend{measuredBackend: c.backend, id: id}
					backend.hook = func(j bstate.Journal) error {
						if fault == "excluded" {
							c.store.policy.ProfileExclusions = append(c.store.policy.ProfileExclusions, issued.ProfileID)
							return nil
						}
						var owner bstate.Login
						if err := j.Read("login", c.profile.LoginID, &owner); err != nil {
							return err
						}
						defer clear(owner.Material)
						if fault == "quarantine" {
							owner.Quarantined = true
						} else {
							owner.PendingRelease = issued.ID
						}
						return j.Write("login", owner.ID, owner)
					}
					c.service.deps.Backend = backend
					defer func() { c.service.deps.Backend = c.backend }()
					material, err = c.service.PreparedSlotMaterial(ctx, spec, id)
					defer clear(material.Bytes)
					if !backend.fired {
						t.Fatal("prepared policy control missed the final journal read")
					}
					if !hasCode(err, api.CodeForbidden) || len(material.Bytes) != 0 {
						t.Fatal("prepared material ignored live delivery policy")
					}
					retained := readCaseSlot(t, c, id)
					defer clear(retained.Material)
					defer clear(retained.Returned)
					if retained.Released || !bytes.Equal(retained.Material, want) || c.helper.process != nil {
						t.Fatal("prepared policy refusal changed material or executed a process")
					}
				}
				c.bind(t, issued, injection)
			})
		}
	}
}

func TestPreparedWorkerPolicy(t *testing.T) {
	for _, phase := range []string{"first", "retry"} {
		t.Run(phase, func(t *testing.T) {
			c, lease, credentials, want := newWorkerCase(t)
			ctx := context.Background()
			injection, err := c.service.InjectWorker(ctx, lease, credentials)
			if err != nil {
				t.Fatal("cannot prepare final worker policy control")
			}
			spec := c.retainWorkerSpec(t, lease, injection)
			id := injection.SlotIDs[0]
			if phase == "retry" {
				material, err := c.service.PrepareWorkerMaterial(ctx, spec, id)
				if err != nil || !bytes.Equal(material.Bytes, want) {
					clear(material.Bytes)
					t.Fatal("current prepared worker did not deliver selected bytes")
				}
				clear(material.Bytes)
			}
			before := readCaseSlot(t, c, id)
			defer clear(before.Material)
			defer clear(before.Returned)
			if !bytes.Equal(before.Material, want) || (before.Handoff != nil) != (phase == "retry") {
				t.Fatal("worker policy control missed its first or retry state")
			}
			backend := &preparedReadBackend{measuredBackend: c.backend, id: id, hook: func(bstate.Journal) error {
				c.store.policy.Generation++
				return nil
			}}
			c.service.deps.Backend = backend
			var material api.SecretMaterial
			if phase == "first" {
				material, err = c.service.PreparedSlotMaterial(ctx, spec, id)
			} else {
				material, err = c.service.PrepareWorkerMaterial(ctx, spec, id)
			}
			defer clear(material.Bytes)
			if !backend.fired {
				t.Fatal("worker policy control missed the final journal read")
			}
			if !hasCode(err, api.CodeConflict) || len(material.Bytes) != 0 {
				t.Fatal("prepared worker ignored final delivery policy")
			}
			after := readCaseSlot(t, c, id)
			defer clear(after.Material)
			defer clear(after.Returned)
			if after.Released || !bytes.Equal(after.Material, before.Material) || (after.Handoff != nil) != (before.Handoff != nil) {
				t.Fatal("worker policy refusal published or erased its binding")
			}
		})
	}
}

func TestGuardRefusal(t *testing.T) {
	for _, fault := range []string{"policy", "claim"} {
		t.Run(fault, func(t *testing.T) {
			m, peer := projectionCase(t)
			s := m.c.service
			ctx := context.Background()
			transfer, err := s.TransferCredentials(ctx, peer, m.a.Request)
			if err != nil {
				t.Fatal("cannot export guard interface control")
			}
			held, err := s.AcknowledgeCredentials(ctx, m.hold(t, transfer))
			if err != nil {
				t.Fatal("cannot hold guard interface control")
			}
			request := api.CredentialGateRequest{ProjectionID: m.a.ID, ExpectedGeneration: held.Generation, Open: m.open}
			live, err := s.LockCredentialProjection(ctx, request)
			if err != nil || wire.Nil(live) {
				t.Fatal("valid guard interface was not returned")
			}
			checkErr, closeErr := live.Check(ctx), live.Close()
			if checkErr != nil || closeErr != nil {
				t.Fatal("valid guard interface could not be checked and closed")
			}
			if fault == "policy" {
				m.c.store.policy.Generation++
			} else {
				claim := m.effects[m.open.EffectID]
				claim.State = api.EffectCompleted
				m.effects[m.open.EffectID] = claim
			}
			guard, err := s.LockCredentialProjection(ctx, request)
			t.Cleanup(func() {
				if !wire.Nil(guard) {
					guard.Close()
				}
			})
			stageCode(t, err, api.CodeConflict)
			if guard != nil {
				t.Fatal("refused projection returned a nonnil guard")
			}
			var projection bstate.Projection
			if err := m.c.backend.WithBroker(ctx, func(j bstate.Journal) error { return j.Read("projection", m.a.ID, &projection) }); err != nil {
				t.Fatal("cannot read refused guard fence")
			}
			if !projection.Fenced {
				t.Fatal("guard interface fix skipped durable refusal")
			}
		})
	}
}
