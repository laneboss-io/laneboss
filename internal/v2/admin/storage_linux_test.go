//go:build linux

package admin

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func storageFixture(t *testing.T) (*os.Root, leaseRecord, api.LaunchReservation) {
	t.Helper()
	service, store, _, _ := seedLaunchFiles(t)
	sources, err := service.ResolveLaunchSources(context.Background(), api.LaunchSourceRequest{ReservationID: store.plan.Reservation.ID, GrantSetID: store.grants.ID, Claim: fixtureLaunchClaim(store)})
	if err != nil {
		t.Fatal(err)
	}
	r := store.plan.Reservation
	request := testAllocation()
	request.ReservationID, request.Cause.CancellationEpoch = r.ID, r.CancellationEpoch
	allocation := launchAllocation{Request: request, Reservation: r, Inputs: api.LaunchInputs{Grants: store.grants, Sources: sources}, Policy: store.policy}
	if err := validateLaunchAllocation(allocation, "admin-case"); err != nil {
		t.Fatal(err)
	}
	lease := api.HelperLease{ID: "storage-lease", UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), ContainmentID: "containment-a", EndpointGeneration: 1}
	storage, err := newLaunchStorage(allocation, lease)
	if err != nil {
		t.Fatal(err)
	}
	directory := privateTestDir(t)
	if err := os.Chmod(directory, 0710); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root, leaseRecord{Schema: "laneboss.helper-lease.v2", BootID: "component-boot", Request: request, Lease: lease,
		Phase: "active", LaunchAllocations: []launchAllocation{allocation}, Storage: &storage}, r
}

func TestLaunchStorageInodes(t *testing.T) {
	root, record, reservation := storageFixture(t)
	if err := syncStorageDirectories(context.Background(), root, &record, uint32(os.Geteuid()), true); err != nil {
		t.Fatal(err)
	}
	if !record.Storage.Ready {
		t.Fatal("actual storage inodes were not retained")
	}
	data := encodeLaunchFixture(t, record)
	var recovered leaseRecord
	if err := decodeStrict(data, &recovered); err != nil {
		t.Fatal(err)
	}
	if err := validateLaunchJournal(recovered); err != nil {
		t.Fatal(err)
	}
	if err := syncStorageDirectories(context.Background(), root, &recovered, uint32(os.Geteuid()), false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recovered.Storage, record.Storage) {
		t.Fatal("storage read-back changed allocation identities")
	}
	if err := validateLaunchStorage(recovered.Storage.Binding, reservation, recovered.Lease.ID); err != nil {
		t.Fatal(err)
	}
	name := string(record.Storage.Binding.Home.RootID)
	if err := root.Rename(name, name+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := root.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	// Owner R181-R192: inode pinning of the private storage is allowed and logged instead of refused.
	allowed := captureAllowed(t)
	if err := syncStorageDirectories(context.Background(), root, &recovered, uint32(os.Geteuid()), false); err != nil || !slices.Equal(allowed(), []string{"private_storage_inode"}) {
		t.Fatal("replaced private storage inode was not allowed and logged", err, allowed())
	}
}

func TestLaunchStorageRefusals(t *testing.T) {
	for _, fault := range []string{"foreign-life", "alias", "escape", "missing-binding", "linked-home", "missing-directory", "writable-home"} {
		t.Run(fault, func(t *testing.T) {
			root, record, reservation := storageFixture(t)
			if err := syncStorageDirectories(context.Background(), root, &record, uint32(os.Geteuid()), true); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "foreign-life":
				record.Storage.Binding.Home.LifeID = "another-life"
			case "alias":
				record.Storage.Binding.Home.RootID = record.Storage.Binding.WorkspaceID
			case "escape":
				record.Storage.Binding.Home.Home.VendorDirectory = "../outside"
			case "missing-binding":
				record.Storage.Directories[1].Device, record.Storage.Directories[1].Inode = "", ""
			case "linked-home", "missing-directory":
				name := string(record.Storage.Binding.Home.RootID)
				if err := root.Rename(name, name+"-retained"); err != nil {
					t.Fatal(err)
				}
				if fault == "linked-home" {
					if err := root.Symlink(name+"-retained", name); err != nil {
						t.Fatal(err)
					}
				}
			case "writable-home":
				file, err := root.Open(string(record.Storage.Binding.Home.RootID))
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Chmod(0777); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			allowed := captureAllowed(t)
			err := validateLaunchStorage(record.Storage.Binding, reservation, record.Lease.ID)
			if err == nil {
				err = syncStorageDirectories(context.Background(), root, &record, uint32(os.Geteuid()), false)
			}
			if fault == "writable-home" {
				// Owner R181-R192: owner and mode pinning of the private storage is allowed and logged.
				if err != nil || !slices.Equal(allowed(), []string{"private_storage_owner"}) {
					t.Fatal("writable private storage was not allowed and logged", err, allowed())
				}
				return
			}
			if err == nil {
				t.Fatal("acceptance: unsafe private storage accepted")
			}
		})
	}
}

func TestLaunchStorageAbortRetains(t *testing.T) {
	m, store, resources := testManager()
	lease, err := m.allocate(context.Background(), testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	root, record, _ := storageFixture(t)
	if err := syncStorageDirectories(context.Background(), root, &record, uint32(os.Geteuid()), true); err != nil {
		t.Fatal(err)
	}
	// The guard is tested on the real abort transition. A private writable
	// root, even empty, is not an independent job/export collection receipt.
	store.records[0].Storage = record.Storage
	store.records[0].Storage.Binding.LeaseID = lease.ID
	store.records[0].LaunchAllocations = record.LaunchAllocations
	cause := testCause(api.InternalHelperAbort, "life-a")
	_, err = m.abort(context.Background(), api.HelperAbortRequest{Cause: cause, LeaseID: lease.ID, OperationID: cause.CauseOperationID, EffectID: cause.EffectID})
	if err == nil || len(resources.removed) != 0 || store.records[0].Phase != "active" {
		t.Fatal("acceptance: private storage abort recycled its UID")
	}
	requireCode(t, err, api.CodeContainmentUnknown)
}

func TestLaunchRootRelativeReads(t *testing.T) {
	service, _, _, _ := seedLaunchFiles(t)
	for _, name := range []string{"/etc/passwd", "../outside", "objects/../manifest.json"} {
		if _, _, err := service.files.read(name, api.MaxFrameBytes); err == nil {
			t.Fatal("acceptance: caller path entered installed runtime")
		}
	}
	if _, _, err := service.files.read(filepath.Join("objects", "agent"), api.MaxFrameBytes); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateRootLinks(t *testing.T) {
	directory := privateTestDir(t)
	real := filepath.Join(directory, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(real, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := openStorageRoot(filepath.Join(real, "child"))
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(directory, "linked")); err != nil {
		t.Fatal(err)
	}
	t.Run("middle", func(t *testing.T) {
		linked, err := openStorageRoot(filepath.Join(directory, "linked", "child"))
		if linked != nil {
			linked.Close()
		}
		if err == nil {
			t.Fatal("acceptance: private storage root followed an ancestor link")
		}
	})
}

func TestPrivateOpenedName(t *testing.T) {
	root, record, _ := storageFixture(t)
	if err := syncStorageDirectories(context.Background(), root, &record, uint32(os.Geteuid()), true); err != nil {
		t.Fatal(err)
	}
	parent, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	name := string(record.Storage.Binding.Home.RootID)
	opened, err := openStorageDirectory(parent, name)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := root.Rename(name, name+"-held"); err != nil {
		t.Fatal(err)
	}
	if err := root.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkOpenedStorageDirectory(opened, parent, name); err == nil {
		t.Fatal("acceptance: held private directory accepted a replaced name")
	}
}
