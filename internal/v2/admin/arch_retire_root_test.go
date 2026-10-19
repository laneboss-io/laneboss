//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func callRetirement(t *testing.T, ctx context.Context, m *leaseManager, q archiveRetireQuery) (archivejob.Retirement, error) {
	t.Helper()
	result, err := m.dispatch(ctx, "archive_retire", encodeLaunchFixture(t, q))
	if err != nil {
		return archivejob.Retirement{}, err
	}
	proof, ok := result.(archivejob.Retirement)
	if !ok {
		t.Fatal("retirement dispatch returned another wire type")
	}
	raw := encodeLaunchFixture(t, proof)
	var readback archivejob.Retirement
	if err := decodeStrict(raw, &readback); err != nil {
		t.Fatal("acceptance: native archive retirement lost its strict result readback")
	}
	return readback, nil
}

func TestArchiveRetire(t *testing.T) {
	for _, mode := range []string{"live", "exited", "expired-worker", "unopened", "prepared", "absent", "foreign-job", "foreign-lease", "expired-claim", "survivor", "socket", "lost-wait"} {
		t.Run(mode, func(t *testing.T) {
			m, e, q, group, live, hold := retirementFixture(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if mode == "expired-worker" {
				deadline, err := time.Parse(time.RFC3339Nano, string(q.Job.Lease.ExpiresAt))
				if err != nil {
					t.Fatal(err)
				}
				timer := time.NewTimer(time.Until(deadline))
				defer timer.Stop()
				<-timer.C
				// A newly reclaimed live effect claim retires the unchanged,
				// actually expired original worker capability. No clock moves.
				q.Claim.ClaimID, q.Claim.Record.ClaimID = "retirement-recovery", "retirement-recovery"
				q.Claim.Record.Generation++
				q.Claim.ExpiresAt = api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
				q.Claim.Record.ClaimExpiresAt = q.Claim.ExpiresAt
			}
			if mode == "exited" {
				if err := hold.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-live.done:
				case <-ctx.Done():
					t.Fatal("original archive process did not exit")
				}
			}
			p, err := m.find(e.LeaseID)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "foreign-job" || mode == "foreign-lease" || mode == "expired-claim" || mode == "lost-wait" {
				expected := "archive retirement selected a foreign native job"
				code := api.CodeForbidden
				switch mode {
				case "foreign-job":
					q.Job.ID = "foreign-job"
				case "foreign-lease":
					q.Allocation.ID = "foreign-allocation"
					expected = "archive retirement selected a foreign native lease or process"
				case "expired-claim":
					q.Claim.ExpiresAt = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
					q.Claim.Record.ClaimExpiresAt = q.Claim.ExpiresAt
					expected = "archive retirement differs from its original job and live effect claim"
				case "lost-wait":
					delete(m.gates, q.Allocation.ID)
					expected, code = "archive retirement lost its original native wait owner", api.CodeContainmentUnknown
				}
				_, refused := callRetirement(t, ctx, m, q)
				var typed *api.Error
				after, readErr := m.find(e.LeaseID)
				_, groupErr := os.Stat(group)
				observation, observeErr := live.Observe(ctx, archiveHandle(*p.Archive.Worker))
				if !errors.As(refused, &typed) || typed.Code != code || typed.Message != expected || readErr != nil || after.Archive.Worker.Collected || after.Archive.Retirement != nil && after.Archive.Retirement.Proof != nil || groupErr != nil || observeErr != nil || observation.State != "running" {
					t.Fatalf("acceptance: archive retirement accepted a foreign or unmeasured selector: mode=%s err=%v", mode, refused)
				}
				return
			}
			if mode == "survivor" {
				outside := cleanupCgroup(t, m.binding, api.ID(string(e.LeaseID)+"-survivor"))
				blocker, release, _ := cleanupHolder(t, outside, p.Archive.Worker.Lease, p.BootID)
				_, refused := callRetirement(t, ctx, m, q)
				after, readErr := m.find(e.LeaseID)
				used := map[uint32]bool{}
				reserveArchiveUIDs([]leaseRecord{after}, used)
				_, groupErr := os.Stat(group)
				if refused == nil || readErr != nil || after.Archive.Worker.Collected || !used[q.Allocation.UID] || groupErr != nil || after.Archive.Retirement != nil && after.Archive.Retirement.Proof != nil {
					t.Fatal("acceptance: archive retirement released a UID with an outside survivor")
				}
				if err := release.Close(); err != nil {
					t.Fatal(err)
				}
				if err := blocker.Wait(); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "socket" {
				listener := retirementSocket(t, m, q.Job.Lease.ID)
				_, refused := callRetirement(t, ctx, m, q)
				after, readErr := m.find(e.LeaseID)
				if refused == nil || readErr != nil || after.Archive.Worker.Collected || after.Archive.Retirement != nil && after.Archive.Retirement.Proof != nil {
					t.Fatal("acceptance: archive retirement ignored an unlinked live endpoint")
				}
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
			}
			proof, err := callRetirement(t, ctx, m, q)
			if err != nil || validateRetirementProof(q.Job, proof, time.Now()) != nil {
				t.Fatalf("acceptance: native archive retirement lacks measured release or abort: mode=%s err=%v", mode, err)
			}
			if mode == "absent" {
				if !proof.Absent || proof.Release != nil || proof.Abort != nil || proof.Allocation.ID != "" {
					t.Fatal("acceptance: native archive absence fabricated an allocation")
				}
			} else {
				after, readErr := m.find(e.LeaseID)
				used := map[uint32]bool{}
				reserveArchiveUIDs([]leaseRecord{after}, used)
				_, groupErr := os.Stat(group)
				if readErr != nil || !after.Archive.Worker.Collected || used[q.Allocation.UID] || !errors.Is(groupErr, os.ErrNotExist) || proof.Allocation != q.Allocation {
					t.Fatal("acceptance: native retirement kept its allocated UID or cgroup")
				}
				if mode == "unopened" || mode == "prepared" {
					if proof.Abort == nil || proof.Abort.AgentExecuted || proof.Release != nil || proof.Abort.Quiescence.State != "not_started" {
						t.Fatal("acceptance: unopened archive allocation lacked measured abort")
					}
				} else {
					if proof.Release == nil || proof.Abort != nil || proof.Release.Quiescence.Handle != q.Process {
						t.Fatal("acceptance: opened archive retirement replaced its actual process")
					}
					if mode == "exited" && (proof.Release.Quiescence.ExitCode == nil || *proof.Release.Quiescence.ExitCode != 0) || mode == "live" && (proof.Release.Quiescence.Signal == nil || *proof.Release.Quiescence.Signal != 9) {
						t.Fatal("acceptance: archive retirement fabricated its actual terminal wait")
					}
				}
			}
			again, err := callRetirement(t, ctx, m, q)
			if err != nil || !reflect.DeepEqual(proof, again) {
				t.Fatal("acceptance: archive retirement changed its original replay evidence")
			}
			if mode == "live" || mode == "absent" {
				_, refused := m.archiveWorker(ctx, archiveReg{Job: q.Job, Claim: q.Claim, LaunchID: "forbidden-replacement"})
				var typed *api.Error
				if !errors.As(refused, &typed) || typed.Code != api.CodeConflict || typed.Message != "retiring archive worker cannot allocate or reopen" {
					t.Fatal("acceptance: retired archive regained native execution authority")
				}
			}
			if mode == "socket" {
				retirementSocket(t, m, q.Job.Lease.ID)
				_, refused := callRetirement(t, ctx, m, q)
				if refused == nil {
					t.Fatal("acceptance: archive retirement replay accepted a live socket inode")
				}
			}
		})
	}
}
