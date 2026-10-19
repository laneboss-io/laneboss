//go:build linux

package secrets

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

// Real encrypted broker state, sealed exports and live duplicate descriptors
// exercise the completion gate. Helper receipts are component observations;
// this test does not substitute them for native root canary measurements.
func TestLB304StopRevoke(t *testing.T) {
	for _, mode := range []string{"claude-api-key", "claudock-headless", "codex-file"} {
		controls := []string{"stop-zero", "stop-held", "revoke-zero", "stop-then-revoke", "revoke-then-stop", "revoked-record", "revoked-authority"}
		if mode == "claudock-headless" {
			controls = append(controls, "release-zero")
		}
		for _, control := range controls {
			t.Run(mode+"/"+control, func(t *testing.T) {
				var m *projectionModel
				var peer api.VerifiedPeer
				if mode == "codex-file" {
					m, peer = projectionCase(t)
				} else {
					m, peer = projectionCase(t, mode)
				}
				ctx := context.Background()
				s := m.c.service
				transfer, err := s.TransferCredentials(ctx, peer, m.a.Request)
				if err != nil || len(transfer.Files) == 0 {
					t.Fatal("LB-304 could not export its selected credential", err)
				}
				var held *os.File
				if control == "stop-held" {
					fd, err := unix.Dup(int(transfer.Files[0].Fd()))
					if err != nil {
						t.Fatal(err)
					}
					held = os.NewFile(uintptr(fd), "lb304-held-export")
					t.Cleanup(func() {
						if err := held.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
							t.Error(err)
						}
					})
				}
				record, err := s.AcknowledgeCredentials(ctx, m.hold(t, transfer))
				if err != nil {
					t.Fatal("LB-304 could not acknowledge its holding", err)
				}
				if held != nil {
					// Retain an actual owned export after acknowledgement closed
					// the originals. The stale closed flag must not hide its FD.
					s.flight(m.a.ID).transfer.Files = append(s.flight(m.a.ID).transfer.Files, held)
				}
				reason := "cancelled"
				if control == "revoke-zero" || control == "revoke-then-stop" {
					reason = "revoked"
				} else if control == "release-zero" {
					reason = "release"
				}
				cause := m.a.Request.Cause
				cause.ID, cause.Kind, cause.EffectID = "lb304-stop", api.InternalHelperStop, "lb304-stop-effect"
				fenced, err := s.BeginCredentialWithdrawal(ctx, api.CredentialWithdrawalRequest{
					ProjectionID: m.a.ID, ExpectedGeneration: record.Generation, Cause: cause, Reason: reason})
				if err != nil {
					t.Fatal("LB-304 could not retain its fence", err)
				}
				if control == "stop-then-revoke" || control == "revoke-then-stop" {
					next := api.CredentialWithdrawalRequest{ProjectionID: m.a.ID, ExpectedGeneration: fenced.Generation,
						Cause: cause, Reason: "revoked"}
					if control == "revoke-then-stop" {
						next.Reason = api.CredentialStopReason
					}
					fenced, err = s.BeginCredentialWithdrawal(ctx, next)
					if err != nil || fenced.Fence == nil || fenced.Fence.Reason != "revoked" {
						t.Fatal("LB-304 revocation must dominate either withdrawal order", err)
					}
					persisted, readErr := s.deps.Store.CredentialProjection(ctx, s.deps.Config, m.a.Request.Prepared.ID)
					if readErr != nil || persisted.Generation != fenced.Generation || persisted.Fence == nil || persisted.Fence.Reason != "revoked" {
						t.Fatal("LB-304 revocation escalation was not durably retained", readErr)
					}
				}
				if control == "revoked-record" || control == "revoked-authority" {
					// Change the protected fixture's revocation decision after its
					// cancelled fence, without changing that fence's reason.
					if control == "revoked-record" {
						fenced.Revoked = true
					} else {
						fenced.Authority.Revoked = true
					}
					if err := m.c.store.save("projection-record.json", fenced); err != nil {
						t.Fatal(err)
					}
				}
				r := m.a.Request
				observed := m.c.finish(t, api.ProcessObservation{Handle: api.ProcessHandle{ID: "lb304-process", Target: m.c.target,
					ContainmentID: r.Prepared.ContainmentID, Generation: r.Prepared.ProcessGeneration}})
				observed.ObservedAt = api.Timestamp(m.c.clock.Now().Format(time.RFC3339Nano))
				zero, executed := uint64(0), true
				m.withdrawal = api.CredentialWithdrawalReceipt{ProjectionID: m.a.ID, Generation: fenced.Generation + 1,
					Cause: cause, Prepared: r.Prepared, HelperLeaseID: r.Lease.ID, Home: r.Home, Observation: observed,
					HelperDescriptors: &zero, ProjectedFiles: &zero, EnvironmentBuffers: &zero, OpenGates: &zero,
					RotationRequired: true, AgentExecuted: &executed, ObservedAt: observed.ObservedAt}
				count, err := s.flight(m.a.ID).brokerDescriptorCount()
				wantCount := uint64(0)
				if held != nil {
					wantCount = 1
				}
				if err != nil || count != wantCount {
					t.Fatal("LB-304 did not measure its actual descriptor control", err)
				}
				done, err := s.FinishCredentialWithdrawal(ctx, fenced, m.withdrawal)
				if mode == "codex-file" && control == "stop-zero" {
					// Reclaiming the same stop effect used to repeat the identical
					// containment_unknown forever, despite measured zero resources.
					for attempt := 2; attempt <= 3; attempt++ {
						again, retryErr := s.FinishCredentialWithdrawal(ctx, fenced, m.withdrawal)
						t.Logf("Codex requested stop attempt=%d code=%s state=%s", attempt, apiKeyErrorCode(retryErr), again.State)
						if err == nil {
							if retryErr != nil || !reflect.DeepEqual(again, done) {
								t.Fatal("Codex requested stop did not replay its terminal withdrawal exactly", retryErr)
							}
						} else if !hasCode(err, api.CodeContainmentUnknown) || !hasCode(retryErr, api.CodeContainmentUnknown) {
							t.Fatal("Codex requested stop retry failed for an unrelated reason", err, retryErr)
						}
						done, err = again, retryErr
					}
				}
				wantBlock := control != "release-zero" && control != "stop-zero"
				t.Logf("LB-304 mode=%s reason=%s descriptors=%d code=%s state=%s", mode, reason, count, apiKeyErrorCode(err), done.State)
				if wantBlock {
					if !hasCode(err, api.CodeContainmentUnknown) && !(control == "revoked-authority" && hasCode(err, api.CodeIntegrity)) {
						t.Fatalf("LB-304 quarantine must block: mode=%s reason=%s descriptors=%d code=%s err=%v state=%s", mode, reason, count, apiKeyErrorCode(err), err, done.State)
					}
					retained, readErr := s.deps.Store.CredentialProjection(ctx, s.deps.Config, r.Prepared.ID)
					if readErr != nil || retained.State != "withdrawing" || retained.Withdrawal != nil {
						t.Fatal("LB-304 blocking fence published a completion", readErr)
					}
				} else if err != nil || done.State != "withdrawn" || done.Withdrawal == nil || !done.Withdrawal.RotationRequired ||
					done.Withdrawal.BrokerDescriptors == nil || *done.Withdrawal.BrokerDescriptors != 0 {
					t.Fatal("LB-304 quiescent stop lost its rotation-required completion", err)
				}
				if mode == "codex-file" && control == "stop-zero" {
					if done.Withdrawal.RefreshLeases == nil || *done.Withdrawal.RefreshLeases != 0 || done.Fence == nil ||
						done.Fence.Reason != api.CredentialStopReason || done.Fence.Cause.Kind != api.InternalHelperStop {
						t.Fatal("Codex requested stop lost its zero refresh leases or original cancellation fence")
					}
					persisted, readErr := s.deps.Store.CredentialProjection(ctx, s.deps.Config, r.Prepared.ID)
					if readErr != nil || !reflect.DeepEqual(persisted, done) {
						t.Fatal("Codex requested stop did not persist its owner-visible rotation-required completion", readErr)
					}
					var owner bstate.Login
					if readErr := m.c.backend.WithBroker(ctx, func(j bstate.Journal) error {
						return j.Read("login", m.c.profile.LoginID, &owner)
					}); readErr != nil {
						t.Fatal("Codex requested stop lost its canonical seat marker", readErr)
					}
					defer clear(owner.Material)
					if !owner.Quarantined || owner.SlotID != "" || owner.PendingRelease != "" || owner.ProjectionID != "" {
						t.Fatal("Codex requested stop released the canonical seat or retained the lane copy owner")
					}
					acquireCtx, cancel := context.WithTimeout(ctx, time.Second)
					retried, acquireErr := m.c.acquire(acquireCtx, m.c.target, m.c.grant)
					cancel()
					if !hasCode(acquireErr, api.CodeConflict) || retried.ID != "" {
						t.Fatal("Codex requested stop allowed reacquisition of its retired lane slot", acquireErr)
					}
				}
				for _, id := range r.Handoff.Spec.Injection.SlotIDs {
					slot := readCaseSlot(t, m.c, id)
					retained := len(slot.Material) > 0
					clear(slot.Material)
					clear(slot.Returned)
					if slot.Released == wantBlock || retained != wantBlock {
						t.Fatal("LB-304 slot retirement disagrees with its quarantine decision")
					}
				}
			})
		}
	}
}
