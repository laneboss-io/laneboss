//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestArchiveBootRetire(t *testing.T) {
	for _, mode := range []string{"opened", "unopened", "cgroup", "survivor", "socket", "kernel", "owner"} {
		t.Run(mode, func(t *testing.T) {
			fixtureMode := "live"
			if mode == "unopened" {
				fixtureMode = "unopened"
			}
			m, e, q, group, live, hold := retirementFixture(t, fixtureMode)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			p, err := m.find(e.LeaseID)
			if err != nil {
				t.Fatal(err)
			}
			if live != nil {
				if err := hold.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-live.done:
				case <-ctx.Done():
					t.Fatal("boot fixture could not reap its original native worker")
				}
				if err := live.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "cgroup" {
				if err := unix.Rmdir(group); err != nil {
					t.Fatal(err)
				}
			}
			boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
			if err != nil || strings.TrimSpace(string(boot)) == p.BootID {
				t.Fatal("boot fixture must retain a different original journal boot")
			}
			// Reproduce a retained previous-boot snapshot with real current
			// kernel measurements. This does not pretend to reboot the host.
			restarted := newLeaseManager(m.binding, strings.TrimSpace(string(boot)), m.store, m.resources)
			expected := ""
			switch mode {
			case "cgroup":
				expected = "archive previous-boot retirement still has a native cgroup"
			case "survivor":
				outside := cleanupCgroup(t, m.binding, api.ID(string(e.LeaseID)+"-new-boot"))
				cleanupHolder(t, outside, q.Allocation, restarted.bootID)
				expected = "lane UID still owns a live process; retain its lease"
			case "socket":
				retirementSocket(t, restarted, q.Job.Lease.ID)
				expected = "archive retirement still has a native socket endpoint"
			case "kernel":
				restarted.bootID = "unmeasured-kernel-boot"
				expected = "archive previous-boot retirement lost its actual kernel identity"
			case "owner":
				restarted.gates = map[api.ID]ownedGate{q.Allocation.ID: live}
				expected = "archive previous-boot retirement lost its actual kernel identity"
			}
			if expected != "" {
				// Exercise this measurement boundary before any independent
				// publication/replay validator can conceal a removed guard.
				_, err := restarted.retirementPreviousBoot(ctx, p)
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || typed.Message != expected {
					t.Fatal("acceptance: boot retirement released an unmeasured native allocation", err)
				}
				_, err = callRetirement(t, ctx, restarted, q)
				after, readErr := restarted.find(e.LeaseID)
				used := map[uint32]bool{}
				reserveArchiveUIDs([]leaseRecord{after}, used)
				if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || typed.Message != expected || readErr != nil || after.Archive.Worker.Collected || !used[q.Allocation.UID] || after.Archive.Retirement == nil || after.Archive.Retirement.Proof != nil {
					t.Fatal("acceptance: refused boot retirement discarded its original reservation", err)
				}
				return
			}
			proof, err := callRetirement(t, ctx, restarted, q)
			if err != nil || proof.Boot == nil || proof.Release != nil || proof.Abort != nil || proof.Absent || proof.Allocation != q.Allocation || proof.Boot.PreviousBootID != p.BootID || proof.Boot.BootID != restarted.bootID || proof.Boot.Process != retirementProcess(*p.Archive.Worker) || validateRetirementProof(q.Job, proof, time.Now()) != nil {
				t.Fatal("acceptance: previous-boot retirement lost its measured absence or invented a wait", err)
			}
			after, err := restarted.find(e.LeaseID)
			used := map[uint32]bool{}
			reserveArchiveUIDs([]leaseRecord{after}, used)
			if err != nil || !after.Archive.Worker.Collected || used[q.Allocation.UID] || after.Archive.Worker.State != p.Archive.Worker.State || after.Archive.Retirement.Observation != nil || !reflect.DeepEqual(after.Archive.Retirement.Boot, proof.Boot) {
				t.Fatal("acceptance: boot retirement fabricated a terminal journal or kept its UID")
			}
			again, err := callRetirement(t, ctx, restarted, q)
			if err != nil || !reflect.DeepEqual(again, proof) {
				t.Fatal("acceptance: boot retirement changed its immutable replay", err)
			}
		})
	}
}
