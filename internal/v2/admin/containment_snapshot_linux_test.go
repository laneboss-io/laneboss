//go:build linux

package admin

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type countedContainmentStore struct {
	*fileLeaseStore
	reads int
}

func (s *countedContainmentStore) Records() ([]leaseRecord, error) {
	s.reads++
	return s.fileLeaseStore.Records()
}

func TestContainmentRecordSnapshot(t *testing.T) {
	for _, change := range []string{"unchanged", "ordinary-read", "manager-save", "atomic-save", "in-place-restored-mtime", "mode", "added", "removed", "proof"} {
		t.Run(change, func(t *testing.T) {
			root, err := os.OpenRoot(privateTestDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			store := &countedContainmentStore{fileLeaseStore: &fileLeaseStore{root: root, owner: uint32(os.Geteuid())}}
			r := leaseRecord{Schema: "laneboss.helper-lease.v2", BootID: "snapshot-boot", Request: testAllocation(),
				Lease: api.HelperLease{ID: "snapshot-lease", UID: 61001, GID: 61001, ContainmentID: "snapshot-cgroup", EndpointGeneration: 1},
				Phase: "active", IssuedAt: gateTimestamp()}
			allocation := r.Request
			allocation.Cause.EffectID = "history-effect"
			r.Allocations = []api.HelperLeaseRequest{allocation}
			if err := store.Save(r); err != nil {
				t.Fatal(err)
			}
			var proof *os.Root
			reservation := probeReservation{Schema: "laneboss.isolation-reservation.v1", ID: "probe-a", BootID: r.BootID, Lease: r.Lease, Phase: "collected"}
			if change == "proof" {
				if err := root.Mkdir("proofs", 0700); err != nil {
					t.Fatal(err)
				}
				proofs, err := root.OpenRoot("proofs")
				if err != nil {
					t.Fatal(err)
				}
				defer proofs.Close()
				if err := proofs.Mkdir("probe-a", 0700); err != nil {
					t.Fatal(err)
				}
				proof, err = proofs.OpenRoot("probe-a")
				if err != nil {
					t.Fatal(err)
				}
				defer proof.Close()
				if err := proofWrite(proof, "reservation.json", reservation); err != nil {
					t.Fatal(err)
				}
			}
			manager := newLeaseManager(testBinding(), r.BootID, store, nil)
			read := func() (leaseRecord, error) {
				current, _, err := manager.containmentRecord(context.Background(), r.Lease.ID, false)
				return current, err
			}
			if current, err := read(); err != nil || current.Lease != r.Lease {
				t.Fatal("cannot warm the exact validated record", err)
			}
			wantCode := api.ErrorCode("")
			switch change {
			case "unchanged":
				for range 20 {
					if current, err := read(); err != nil || current.Lease != r.Lease {
						t.Fatal("unchanged containment record was lost", err)
					}
				}
				if store.reads != 1 {
					t.Fatalf("unchanged generation decoded the full journal %d times; want one", store.reads)
				}
			case "ordinary-read":
				ordinary, err := manager.find(r.Lease.ID)
				if err != nil {
					t.Fatal(err)
				}
				ordinary.Allocations[0].Budget.WallMS++
				current, err := read()
				if err != nil || current.Allocations[0] != allocation {
					t.Fatal("ordinary mutable read aliased the containment snapshot", err)
				}
			case "manager-save", "atomic-save":
				r.Revoked = true
				if change == "manager-save" {
					err = manager.save(r)
				} else {
					err = store.Save(r) // A writer outside manager.save must also invalidate.
				}
				if err != nil {
					t.Fatal(err)
				}
				current, err := read()
				if err != nil || !current.Revoked {
					t.Fatal("journal publication retained the unrevoked snapshot", err)
				}
			case "in-place-restored-mtime":
				file, err := root.OpenFile(string(r.Lease.ID)+".json", os.O_RDWR|unix.O_NOFOLLOW, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				var before unix.Stat_t
				if err := unix.Fstat(int(file.Fd()), &before); err != nil {
					t.Fatal(err)
				}
				raw, err := io.ReadAll(file)
				if err != nil {
					t.Fatal(err)
				}
				changed := bytes.Replace(raw, []byte(`"schema":"laneboss.helper-lease.v2"`), []byte(`"schema":"laneboss.helper-lease.v1"`), 1)
				if bytes.Equal(raw, changed) || len(raw) != len(changed) {
					t.Fatal("in-place control did not replace exactly the retained schema")
				}
				if n, err := file.WriteAt(changed, 0); err != nil || n != len(changed) {
					t.Fatal(err)
				}
				if err := unix.UtimesNanoAt(int(file.Fd()), "", []unix.Timespec{before.Atim, before.Mtim}, unix.AT_EMPTY_PATH); err != nil {
					t.Fatal(err)
				}
				var after unix.Stat_t
				if err := unix.Fstat(int(file.Fd()), &after); err != nil || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim == after.Ctim {
					t.Fatal("in-place control did not isolate ctime from inode, size and mtime", err)
				}
				wantCode = api.CodeIntegrity
			case "mode":
				if err := root.Chmod(string(r.Lease.ID)+".json", 0644); err != nil {
					t.Fatal(err)
				}
				wantCode = api.CodeIntegrity
			case "added":
				file, err := root.OpenFile("unexpected", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				wantCode = api.CodeIntegrity
			case "removed":
				if err := root.Remove(string(r.Lease.ID) + ".json"); err != nil {
					t.Fatal(err)
				}
				wantCode = api.CodeNotFound
			case "proof":
				reservation.Phase = "held"
				if err := proofWrite(proof, "reservation.json", reservation); err != nil {
					t.Fatal(err)
				}
				wantCode = api.CodeContainmentUnknown
			}
			if wantCode != "" {
				_, err := read()
				requireCode(t, err, wantCode)
			}
		})
	}
}
