//go:build linux

package admin

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// A damaged journal cannot authorize a resource acquisition. Its unowned
// kernel groups must still be stopped, with every problem retained for review.
func (m *leaseManager) stopDamagedContainments(ctx context.Context) error {
	if m.recovery == nil || len(m.recovery.issues) == 0 {
		return nil
	}
	resources, ok := m.resources.(*linuxResources)
	if !ok {
		return failure(api.CodeContainmentUnknown, "damaged journal stop has no native containment inventory")
	}
	base := resources.binding.cgroupPath()
	if err := protectedPath(base, true); err != nil {
		return err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return failure(api.CodeContainmentUnknown, "cannot pin damaged journal containment inventory")
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(directory.Fd()), &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return failure(api.CodeContainmentUnknown, "damaged journal stop requires actual cgroup-v2")
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	var groups []api.ID
	var inventoryErrors []error
	for _, entry := range entries {
		var st unix.Stat_t
		if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			inventoryErrors = append(inventoryErrors, err)
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		groups = append(groups, api.ID(entry.Name()))
	}
	// Queue every kill before waiting on population. One slow or failed group
	// must not prevent the remaining unowned groups from receiving their kill.
	type pendingGroup struct {
		id   api.ID
		root *os.Root
	}
	var pending []pendingGroup
	stopErr := stopUnownedGroups(ctx, m.recovery.records, m.recovery.allowed, groups, func(id api.ID) error {
		group, err := root.OpenRoot(string(id))
		if err != nil {
			return err
		}
		pending = append(pending, pendingGroup{id, group})
		if err := writeControl(group, "cgroup.kill", "1"); err != nil {
			return err
		}
		return nil
	})
	for _, group := range pending {
		if err := waitCgroupEvent(ctx, group.root, "populated", "0"); err != nil {
			inventoryErrors = append(inventoryErrors, fmt.Errorf("unowned containment %s population: %w", group.id, err))
		}
		if err := group.root.Close(); err != nil {
			inventoryErrors = append(inventoryErrors, err)
		}
	}
	return errors.Join(append(inventoryErrors, stopErr)...)
}

func stopUnownedGroups(ctx context.Context, records []leaseRecord, allowed map[api.ID]bool, groups []api.ID, stop func(api.ID) error) error {
	owned := map[api.ID]bool{}
	for _, record := range records {
		if !allowed[record.Lease.ID] {
			continue
		}
		owned[record.Lease.ContainmentID] = true
		if record.Archive != nil && record.Archive.Worker != nil {
			owned[record.Archive.Worker.Lease.ContainmentID] = true
		}
		for _, review := range record.Reviews {
			if review != nil && review.Worker != nil {
				owned[review.Worker.Lease.ContainmentID] = true
			}
		}
		for _, job := range record.DataJobs {
			owned[job.Lease.ContainmentID] = true
		}
		for _, capture := range record.Captures {
			if capture.Native != nil {
				owned[capture.Native.Lease.ContainmentID] = true
			}
		}
	}
	var reports []error
	for _, id := range groups {
		if err := contextError(ctx); err != nil {
			reports = append(reports, err)
			break
		}
		if owned[id] {
			continue
		}
		if err := stop(id); err != nil {
			reports = append(reports, fmt.Errorf("unowned containment %s stop failed: %w", id, err))
		} else {
			reports = append(reports, failure(api.CodeIntegrity, fmt.Sprintf("requested stop for unowned containment %s; damaged journal and UID ownership retained", id)))
		}
	}
	return errors.Join(reports...)
}
