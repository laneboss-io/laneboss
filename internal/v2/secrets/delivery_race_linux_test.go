//go:build linux

package secrets

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// Return the actual previous policy, then advance the source before delivery's
// final journal read. This isolates the bound port's final recheck.
type advanceDeliveryPolicy struct {
	api.StateStore
	store    *launchCaseStore
	advanced bool
}

func (p *advanceDeliveryPolicy) CurrentApprovedPolicy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	policy, err := p.StateStore.CurrentApprovedPolicy(ctx, scope)
	if err == nil && !p.advanced {
		p.advanced = true
		p.store.policy.Generation++
	}
	return policy, err
}

func TestWorkerPolicyDelivery(t *testing.T) {
	for _, port := range []string{"prepared", "bound", "copy"} {
		t.Run(port, func(t *testing.T) {
			c, lease, credentials, want := newWorkerCase(t)
			ctx := context.Background()
			injection, err := c.service.InjectWorker(ctx, lease, credentials)
			if err != nil {
				t.Fatal("cannot prepare stale worker generation control")
			}
			spec := c.retainWorkerSpec(t, lease, injection)
			id := injection.SlotIDs[0]
			material, err := c.service.PrepareWorkerMaterial(ctx, spec, id)
			if err != nil || !bytes.Equal(material.Bytes, want) {
				clear(material.Bytes)
				t.Fatal("current worker generation did not deliver its actual selected bytes")
			}
			clear(material.Bytes)
			read := func() (api.SecretMaterial, error) {
				return c.service.PrepareWorkerMaterial(ctx, spec, id)
			}
			if port != "prepared" {
				c.bindWorker(t, spec)
				read = func() (api.SecretMaterial, error) {
					return c.service.SlotMaterial(ctx, spec.LaunchID, id)
				}
				material, err = read()
				if err != nil || !bytes.Equal(material.Bytes, want) {
					clear(material.Bytes)
					t.Fatal("current bound worker generation did not deliver its actual selected bytes")
				}
				clear(material.Bytes)
			}
			var advancing *advanceDeliveryPolicy
			if port == "copy" {
				advancing = &advanceDeliveryPolicy{StateStore: c.store, store: c.store}
				c.service.deps.Store = advancing
			} else {
				c.store.policy.Generation++
			}
			material, err = read()
			defer clear(material.Bytes)
			if advancing != nil && !advancing.advanced {
				t.Fatal("worker delivery did not reach the policy advance")
			}
			if !hasCode(err, api.CodeConflict) || len(material.Bytes) != 0 {
				t.Fatal("stale worker generation returned material")
			}
		})
	}
}

// Pause only after the real helper receipt has been committed. measuredRelease
// has passed its outer projection check, while its final slot transaction has
// not begun. A second operation can now acquire the real canonical journal.
type releaseBarrier struct {
	api.LaunchControlSource
	reached chan struct{}
	resume  chan struct{}
	once    sync.Once
	allow   sync.Once
}

func (p *releaseBarrier) RecordRelease(ctx context.Context, request api.HelperReleaseRequest, receipt api.ReleaseReceipt) error {
	if err := p.LaunchControlSource.RecordRelease(ctx, request, receipt); err != nil {
		return err
	}
	p.once.Do(func() { close(p.reached) })
	select {
	case <-p.resume:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *releaseBarrier) proceed() { p.allow.Do(func() { close(p.resume) }) }

func TestReleaseBindRace(t *testing.T) {
	for _, kind := range []string{"profile", "worker"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			var c *launchCase
			var id api.ID
			var release func() error
			var bindLate func() (api.ID, error)
			if kind == "profile" {
				m, peer := projectionCase(t)
				c = m.c
				slot := m.a.Request.Handoff.Spec.Runner.Slot
				id = slot.ID
				observation := c.finish(t, api.ProcessObservation{Handle: api.ProcessHandle{ID: "process-a", Target: c.target,
					ContainmentID: m.a.Request.Prepared.ContainmentID, Generation: m.a.Request.Prepared.ProcessGeneration}})
				release = func() error { return c.service.Release(ctx, slot, observation) }
				bindLate = func() (api.ID, error) {
					transfer, err := c.service.TransferCredentials(ctx, peer, m.a.Request)
					if err != nil {
						return "", err
					}
					record, err := c.service.AcknowledgeCredentials(ctx, m.hold(t, transfer))
					if err != nil {
						return "", err
					}
					if record.State != "held" {
						return "", wire.Error(api.CodeIntegrity, "late binding did not retain held")
					}
					return record.Authority.ID, nil
				}
			} else {
				var lease api.WorkerLease
				var credentials []api.WorkerCredential
				c, lease, credentials, _ = newWorkerCase(t)
				injection, err := c.service.InjectWorker(ctx, lease, credentials)
				if err != nil {
					t.Fatal("cannot prepare worker release race")
				}
				id = injection.SlotIDs[0]
				spec := c.retainWorkerSpec(t, lease, injection)
				material, err := c.service.PrepareWorkerMaterial(ctx, spec, id)
				clear(material.Bytes)
				if err != nil {
					t.Fatal("cannot retain worker release race handoff")
				}
				observation := c.finish(t, c.bindWorker(t, spec))
				release = func() error { return c.service.RevokeInjection(ctx, injection, observation) }
				// Model the binder's protected slot write, not native helper
				// authentication. The profile cell above uses the real producer.
				bindLate = func() (api.ID, error) {
					projection := api.ID("late-worker-projection")
					err := c.backend.WithBroker(ctx, func(j bstate.Journal) error {
						var current bstate.Slot
						if err := j.Read("slot", id, &current); err != nil {
							return err
						}
						defer clear(current.Material)
						defer clear(current.Returned)
						if current.Released || current.ProjectionID != "" {
							return wire.Error(api.CodeConflict, "late worker bind missed the live slot")
						}
						current.ProjectionID = projection
						return j.Write("slot", id, current)
					})
					return projection, err
				}
			}
			before := readCaseSlot(t, c, id)
			defer clear(before.Material)
			defer clear(before.Returned)
			barrier := &releaseBarrier{LaunchControlSource: c.service.deps.Control, reached: make(chan struct{}), resume: make(chan struct{})}
			c.service.deps.Control = barrier
			done, finished := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(finished)
				done <- release()
			}()
			t.Cleanup(func() {
				barrier.proceed()
				cancel()
				select {
				case <-finished:
				case <-time.After(2 * time.Second):
					t.Error("release race operation did not stop after cancellation")
				}
			})
			select {
			case <-barrier.reached:
			case <-done:
				t.Fatal("release returned before the late bind interleave")
			case <-ctx.Done():
				t.Fatal("release did not reach its committed measurement barrier")
			}
			if current := readCaseSlot(t, c, id); current.Released || current.ProjectionID != "" {
				clear(current.Material)
				clear(current.Returned)
				t.Fatal("release race did not pause before the binding write")
			} else {
				clear(current.Material)
				clear(current.Returned)
			}
			projection, err := bindLate()
			if err != nil {
				t.Fatal("late projection could not bind while cleanup was paused")
			}
			barrier.proceed()
			select {
			case err = <-done:
			case <-ctx.Done():
				t.Fatal("release did not finish after the late binding")
			}
			retained := readCaseSlot(t, c, id)
			defer clear(retained.Material)
			defer clear(retained.Returned)
			if retained.Released || retained.ProjectionID != projection || !bytes.Equal(retained.Material, before.Material) {
				t.Fatal("late projection binding was released")
			}
			if !hasCode(err, api.CodeConflict) {
				t.Fatal("late projection binding did not refuse ordinary cleanup")
			}
		})
	}
}
