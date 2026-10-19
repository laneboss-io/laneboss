//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

func (m *leaseManager) claudockPlanning(ctx context.Context, method string, query claudockNativePlanning) (_ api.Empty, resultErr error) {
	q, r := query.Input, query.Reservation
	if os.Geteuid() != 0 || q.RequiredUmask != claudock.RequiredUmask || r.Driver != api.DriverClaudock ||
		q.Request.Target != r.Target || q.Home.LifeID != r.Target.LifeID || q.Request.Home != q.Home.Home ||
		q.Home.Home.VendorDirectory != ".claude" || q.Claim.ReservationID != r.ID {
		return api.Empty{}, failure(api.CodeForbidden, "credential worker lacks its exact native home selection")
	}
	lease, ok := api.EffectLeaseFromContext(ctx)
	if !ok || api.CheckPlanningClaim(lease.Record, q.Claim, m.binding.Config, time.Now()) != nil {
		return api.Empty{}, failure(api.CodeForbidden, "credential worker lost its planning effect claim")
	}
	storage, err := m.resolveStorage(ctx, launchStorageQuery{Request: api.LaunchDataRequest{ReservationID: r.ID, GrantSetID: r.GrantSetID, LeaseID: q.LeaseID}, Reservation: r})
	if err != nil {
		return api.Empty{}, err
	}
	if storage.Home != q.Home {
		return api.Empty{}, failure(api.CodeForbidden, "credential worker home is outside its lane confinement")
	}
	record, err := m.findActive(q.LeaseID, storageReady)
	if err != nil {
		return api.Empty{}, err
	}
	// No running lane or materialization process can race the home transaction.
	if err := m.resources.Quiescent(ctx, record); err != nil {
		return api.Empty{}, err
	}
	home := filepath.Join("/var/lib/laneboss-v2/lanes", m.binding.Config, string(record.Lease.ID), string(storage.Home.RootID))
	if err := checkClaudockHomeIdentity(home, record); err != nil {
		return api.Empty{}, err
	}
	identity, err := json.Marshal(struct {
		Reservation api.LaunchReservation
		Lease       api.HelperLease
		Home        api.PrivateHomeBinding
		Request     api.RunnerRequest
	}{r, record.Lease, q.Home, q.Request})
	if err != nil {
		return api.Empty{}, err
	}
	binding := digestBytes(identity)
	if method == "claudock_bootstrap" {
		if q.Plan != nil {
			return api.Empty{}, failure(api.CodeInvalid, "bootstrap measurement cannot perform home work")
		}
		var mask uint32
		if err := m.measureCredentialBootstrap(ctx, record, &mask); err != nil {
			return api.Empty{}, err
		}
		record.Claudock = &claudockHomeJournal{ReservationID: r.ID, BindingSHA256: binding,
			Bootstrap: m.binding.Artifact.SHA256, BootID: m.bootID, Umask: &mask, Findings: []claudock.Finding{}}
		return api.Empty{}, m.save(record)
	}
	proof := record.Claudock
	if method != "claudock_home" || q.Plan == nil || !reflect.DeepEqual(q.Plan.Request, q.Request) || q.Plan.Home != q.Home ||
		q.Plan.ReservationID != r.ID || q.Plan.Start != (r.Mode == "start") || !validDigest(q.Plan.InputsSHA256) ||
		proof == nil || proof.Umask == nil || *proof.Umask != claudock.RequiredUmask || proof.Bootstrap != m.binding.Artifact.SHA256 ||
		proof.BootID != m.bootID || proof.ReservationID != r.ID || proof.BindingSHA256 != binding {
		return api.Empty{}, failure(api.CodeForbidden, "credential home has no matching measured bootstrap proof")
	}
	if err := m.checkClaudockPin(ctx, record, r.ID, *q.Plan); err != nil {
		return api.Empty{}, err
	}
	// These paths are selected solely from the authenticated helper journal.
	// The service receives neither a path nor any record descriptor. The root
	// credential worker stays within the helper unit's existing writable mounts.
	directory := filepath.Join(m.binding.statePath(), "claudock")
	if err := protectedPath(m.binding.statePath(), true); err != nil {
		return api.Empty{}, err
	}
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return api.Empty{}, err
	}
	records, err := claudock.NewRecords(directory)
	if err != nil {
		return api.Empty{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, records.Close()) }()
	if err := claudock.InitializeAllocatedHome(home, records); err != nil {
		return api.Empty{}, err
	}
	err = claudock.PlanPrivateHome(home, records, *q.Plan, func(findings []claudock.Finding) error {
		record.Claudock.Findings = findings
		return m.save(record)
	}, nil)
	if err != nil {
		return api.Empty{}, err
	}
	// Recheck owner/mode/device/inode after the descriptor-bound operation.
	if err := m.syncLaunchStorage(ctx, &record, false); err != nil {
		return api.Empty{}, err
	}
	return api.Empty{}, checkClaudockHomeIdentity(home, record)
}

func (m *leaseManager) checkClaudockPin(ctx context.Context, record leaseRecord, id api.ID, plan claudock.HomePlanRequest) error {
	for _, allocation := range record.LaunchAllocations {
		if allocation.Reservation.ID != id {
			continue
		}
		runtime := allocation.Inputs.Sources.Runtime
		manifest, err := loadInstalledRuntime(ctx, m.binding, runtime.Manifest)
		if err != nil {
			return err
		}
		vendor, err := api.RuntimeSessionExecutable(runtime, manifest)
		if err != nil {
			return err
		}
		for _, object := range manifest.Objects {
			if object.ID == vendor.ID && plan.Claude == vendor && plan.ClaudePath == nativeRuntimeTarget(object) {
				return nil
			}
		}
		return failure(api.CodeForbidden, "credential home CLI pin differs from its enrolled runtime")
	}
	return failure(api.CodeForbidden, "credential home CLI has no retained launch allocation")
}

func checkClaudockHomeIdentity(home string, record leaseRecord) error {
	if record.Storage == nil || len(record.Storage.Directories) != 3 || filepath.Base(home) != string(record.Storage.Binding.Home.RootID) {
		return failure(api.CodeForbidden, "credential home has no exact storage journal")
	}
	root, err := openStorageRoot(filepath.Dir(home))
	if err != nil {
		return err
	}
	defer root.Close()
	parent, err := root.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	file, err := openStorageDirectory(parent, filepath.Base(home))
	if err != nil {
		return err
	}
	defer file.Close()
	var actual unix.Stat_t
	item := record.Storage.Directories[1]
	if unix.Fstat(int(file.Fd()), &actual) != nil || actual.Uid != record.Lease.UID || actual.Gid != record.Lease.GID || actual.Mode&07777 != 0700 ||
		item.ID != record.Storage.Binding.Home.RootID || item.Device != strconv.FormatUint(uint64(actual.Dev), 10) || item.Inode != strconv.FormatUint(actual.Ino, 10) {
		return failure(api.CodeForbidden, "credential home inode owner or mode differs from its lane confinement")
	}
	return checkClaudockOwnedOwners(home, record.Lease.UID, record.Lease.GID)
}

func checkClaudockOwnedOwners(home string, uid, gid uint32) (resultErr error) {
	root, err := openStorageRoot(home)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	count := 0
	check := func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return failure(api.CodeContainmentUnknown, "credential owned-entry inventory is unavailable")
		}
		count++
		if count > 100000 {
			return failure(api.CodeBudget, "credential owned-entry inventory exceeds its fixed bound")
		}
		info, err := entry.Info()
		if err != nil {
			return failure(api.CodeContainmentUnknown, "credential owned-entry owner is unavailable")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uid || owner.Gid != gid {
			return failure(api.CodeForbidden, "credential owned-entry owner differs from its lane allocation")
		}
		return nil
	}
	for _, name := range []string{".claude", ".runnerhome-runtime", ".config/claudock"} {
		if _, err := root.Lstat(name); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return failure(api.CodeContainmentUnknown, "credential owned-entry inventory is unavailable")
		}
		if err := fs.WalkDir(root.FS(), name, check); err != nil {
			return err
		}
	}
	if info, err := root.Lstat(".config"); err == nil {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uid || owner.Gid != gid {
			return failure(api.CodeForbidden, "credential owned-entry owner differs from its lane allocation")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return failure(api.CodeContainmentUnknown, "credential owned-entry owner is unavailable")
	}
	return nil
}

func (m *leaseManager) appendClaudockSettings(ctx context.Context, record leaseRecord, mounts []*nativeMount) (result []*nativeMount, resultErr error) {
	defer func() {
		if resultErr != nil {
			for _, mount := range mounts {
				resultErr = errors.Join(resultErr, mount.file.Close())
			}
		}
	}()
	spec := record.Spec.Handoff.Spec
	if spec.Runner == nil || spec.Runner.Driver != api.DriverClaudock {
		return mounts, nil
	}
	if err := validateClaudockHomeJournal(record, m.binding); err != nil {
		return nil, err
	}
	if record.Claudock == nil || record.Claudock.ReservationID != spec.PlanID || record.Storage == nil || spec.Runner.Home != record.Storage.Binding.Home.Home {
		return nil, failure(api.CodeForbidden, "Claudock launch has no measured credential home binding")
	}
	if err := m.resources.Quiescent(ctx, record); err != nil {
		return nil, err
	}
	home := filepath.Join("/var/lib/laneboss-v2/lanes", m.binding.Config, string(record.Lease.ID), string(record.Storage.Binding.Home.RootID))
	if err := checkClaudockHomeIdentity(home, record); err != nil {
		return nil, err
	}
	records, err := claudock.NewRecords(filepath.Join(m.binding.statePath(), "claudock"))
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, records.Close()) }()
	opened, err := claudock.OpenHome(home, records)
	if err != nil {
		return nil, err
	}
	files, err := opened.GeneratedProjections()
	if err != nil {
		return nil, err
	}
	for _, projection := range files {
		mount, err := pinNativeMount(filepath.Join(home, projection.Path), "/home/lane/"+projection.Path, false, false, false, record.Lease.UID, record.Lease.GID)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, mount)
		reader, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(mount.file.Fd())))
		if err != nil {
			return nil, err
		}
		info, err := reader.Stat()
		if err != nil {
			return nil, errors.Join(err, reader.Close())
		}
		ref := api.BlobRef{ID: "generated-projection", Class: "artifact", Bytes: info.Size(), SHA256: projection.SHA256}
		if info.Mode().Perm() != 0400 {
			return nil, errors.Join(failure(api.CodeIntegrity, "generated credential projection is not protected read-only"), reader.Close())
		}
		if err := errors.Join(hashRuntime(reader, api.RuntimeObject{Content: ref, Mode: 0400}), reader.Close()); err != nil {
			return nil, err
		}
	}
	return mounts, nil
}
