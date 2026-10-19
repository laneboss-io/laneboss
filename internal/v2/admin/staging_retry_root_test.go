//go:build linux && laneboss_root_canary

package admin

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestStageInterruptedWithdrawalInventory(t *testing.T) {
	for _, phase := range []string{"collecting", "withdrawing", "withdrawn"} {
		t.Run(phase, func(t *testing.T) {
			ctx := collectionCanaryContext(t)
			m, record, base := collectionLeaseFixture(t, true)
			count, inventory, err := m.storageReferences(ctx, record)
			if err != nil || count != 0 {
				t.Fatal("withdrawal control has native references before interruption", err)
			}
			record.Storage.Collecting = phase == "collecting"
			record.Storage.Withdrawing = phase == "withdrawing"
			record.Storage.Withdrawn = phase == "withdrawn"
			if record.Storage.Withdrawn {
				for _, item := range record.Storage.Directories {
					if err := os.Chown(filepath.Join(base, string(item.ID)), 0, 0); err != nil {
						t.Fatal(err)
					}
				}
			}
			if record.Storage.Collecting {
				record.Storage.Inventory = inventory
			}
			if err := m.save(record); err != nil {
				t.Fatal(err)
			}
			parent, err := os.Open(base)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			// Reproduce the real interruption between Fchmod and Fchown.
			if err := unix.Fchmod(int(parent.Fd()), 0700); err != nil {
				t.Fatal(err)
			}
			var before unix.Stat_t
			if unix.Fstat(int(parent.Fd()), &before) != nil || before.Uid != 0 || before.Gid != record.Lease.GID || before.Mode&07777 != 0700 {
				t.Fatal("interrupted withdrawal did not establish its native input")
			}
			if err := inventoryStorageParent(base, record); err != nil {
				t.Fatal("interrupted withdrawal could not reach its existing retry gate", err)
			}
			unstarted := record
			storage := *record.Storage
			storage.Collecting, storage.Withdrawing, storage.Withdrawn = false, false, false
			unstarted.Storage = &storage
			requireParentAllowance(t, base, unstarted)
			// Read-only inventory cannot replace the durable collection journal.
			// Refuse that write and measure that no native mutation follows it.
			children := make([]unix.Stat_t, len(storage.Directories))
			for index, item := range storage.Directories {
				if err := unix.Lstat(filepath.Join(base, string(item.ID)), &children[index]); err != nil {
					t.Fatal(err)
				}
			}
			journal := m.store
			m.store = refusedLeaseStore{leaseStorage: journal, write: true}
			err = m.collectPrivateStorage(ctx, &unstarted)
			m.store = journal
			if err == nil || api.HelperReason(err) != "lease_write" {
				t.Fatal("collection did not stop at its refused authority journal", err)
			}
			var retained unix.Stat_t
			if unix.Fstat(int(parent.Fd()), &retained) != nil || !sameStageIdentity(before, retained) {
				t.Fatal("unjournaled collection withdrew the parent")
			}
			for index, item := range storage.Directories {
				if unix.Lstat(filepath.Join(base, string(item.ID)), &retained) != nil || !sameStageIdentity(children[index], retained) {
					t.Fatal("unjournaled collection changed a protected child")
				}
			}
			if record.Storage.Collecting {
				// Keep the original child inodes present until the collector's
				// actual zero-reference gate permits their removal. Unlinking
				// them here would allow unrelated jobs to reuse inventory IDs.
				if err := m.collectPrivateStorage(ctx, &record); err != nil || !record.Storage.Collected {
					t.Fatal("actual collection could not finish interrupted traversal withdrawal", err)
				}
				for _, item := range record.Storage.Directories {
					if _, err := os.Lstat(filepath.Join(base, string(item.ID))); !os.IsNotExist(err) {
						t.Fatal("actual collection retained a journaled child directory", err)
					}
				}
			} else if err := withdrawStageTraversal(parent, record.Lease.GID); err != nil {
				t.Fatal(err)
			}
			var after unix.Stat_t
			if unix.Fstat(int(parent.Fd()), &after) != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Gid != 0 || after.Mode&07777 != 0700 {
				t.Fatal("withdrawal retry did not clear the old group on its original inode")
			}
		})
	}
}
