//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"os"
	"slices"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Exercise syncLaunchStorage itself: the old privateDirectory check rejects
// 0700 before syncStorageDirectories can reach its recovery branch.
func TestStageInterruptedCreate(t *testing.T) {
	for _, afterChown := range []bool{false, true} {
		t.Run(strconv.FormatBool(afterChown), func(t *testing.T) {
			ctx := collectionCanaryContext(t)
			m, record, base := collectionLeaseFixture(t, false)
			if afterChown {
				if err := os.Chown(base, 0, int(record.Lease.GID)); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.syncLaunchStorage(ctx, &record, true); err != nil {
				t.Fatal("acceptance: interrupted stage create could not reach recovery", err)
			}
			var info unix.Stat_t
			if unix.Stat(base, &info) != nil || info.Uid != 0 || info.Gid != record.Lease.GID || info.Mode&07777 != 0710 || !record.Storage.Ready {
				t.Fatal("recovered parent or child storage was not measured ready")
			}
			if err := m.syncLaunchStorage(ctx, &record, false); err != nil {
				t.Fatal("recovered stage did not pass normal acquisition", err)
			}
		})
	}
}

func TestStageRecoveryRefusals(t *testing.T) {
	for _, fault := range []string{"published", "foreign-group", "withdrawn"} {
		t.Run(fault, func(t *testing.T) {
			ctx := collectionCanaryContext(t)
			m, record, base := collectionLeaseFixture(t, fault == "published")
			switch fault {
			case "published":
				// A partially initialized journal has real published child
				// identities; it cannot reopen a helper-private parent.
				record.Storage.Ready = false
				if err := os.Chmod(base, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(base, 0, 0); err != nil {
					t.Fatal(err)
				}
			case "foreign-group":
				if err := os.Chown(base, 0, int(m.binding.Lanes[1].GID)); err != nil {
					t.Fatal(err)
				}
			case "withdrawn":
				record.Storage.Withdrawn = true
			}
			var before, after unix.Stat_t
			if err := unix.Stat(base, &before); err != nil {
				t.Fatal(err)
			}
			allowed := captureAllowed(t)
			err := m.syncLaunchStorage(ctx, &record, true)
			if fault == "foreign-group" {
				// Owner R181-R192 allows the mismatch, without repairing traversal.
				if err != nil || !record.Storage.Ready || !slices.Equal(allowed(), []string{"storage_parent_owner"}) {
					t.Fatal("foreign parent was not allowed and logged without recovery", err, allowed())
				}
			} else if err == nil {
				t.Fatal("acceptance: interrupted-create recovery reopened published or foreign storage")
			}
			if unix.Stat(base, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino ||
				before.Uid != after.Uid || before.Gid != after.Gid || before.Mode != after.Mode {
				t.Fatal("recovery changed the protected parent")
			}
		})
	}
}

func TestStageCollectedParentScope(t *testing.T) {
	ctx := collectionCanaryContext(t)
	m, record, base := collectionLeaseFixture(t, true)
	if err := m.collectPrivateStorage(context.Background(), &record); err != nil {
		t.Fatal(err)
	}
	if err := inventoryStorageParent(base, record); err != nil {
		t.Fatal("root-only collected parent refused its collection record", err)
	}
	// Inventory is read-only even when the parent mismatch is allowed and logged.
	// A live writable allocation still requires its complete storage journal.
	record.Storage = &launchStorageRecord{Ready: true}
	requireParentAllowance(t, base, record)
	requireCode(t, m.syncLaunchStorage(ctx, &record, false), api.CodeIntegrity)
	if record.Lease.GID == 0 {
		t.Fatal("scope canary did not select an actual lane GID")
	}
}

func requireParentAllowance(t *testing.T, path string, record leaseRecord) {
	t.Helper()
	journal := encodeLaunchFixture(t, record)
	var before, after unix.Stat_t
	if err := unix.Lstat(path, &before); err != nil {
		t.Fatal(err)
	}
	allowed := captureAllowed(t)
	if err := inventoryStorageParent(path, record); err != nil || !slices.Equal(allowed(), []string{"storage_inventory_parent"}) {
		t.Fatal("parent inventory mismatch was not allowed and logged", err, allowed())
	}
	if unix.Lstat(path, &after) != nil || !sameStageIdentity(before, after) ||
		!bytes.Equal(journal, encodeLaunchFixture(t, record)) {
		t.Fatal("read-only inventory changed the parent or granted journal authority")
	}
}

func sameStageIdentity(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode &&
		before.Uid == after.Uid && before.Gid == after.Gid
}
