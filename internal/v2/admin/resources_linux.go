//go:build linux

package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type linuxResources struct {
	binding installation
	manager *leaseManager
}

func (r *linuxResources) Survivors(ctx context.Context, record leaseRecord) (uint64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	root, err := r.open(record)
	if err != nil {
		return 0, err
	}
	count, readErr := readSurvivors(root)
	closeErr := root.Close()
	if readErr != nil || closeErr != nil {
		return 0, errors.Join(readErr, closeErr)
	}
	return count, nil
}

func readSurvivors(root *os.Root) (uint64, error) {
	value, err := readControl(root, "pids.current")
	if err != nil {
		return 0, err
	}
	if value == "" || strings.Trim(value, "0123456789") != "" {
		return 0, failure(api.CodeContainmentUnknown, "native task count is malformed")
	}
	count, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, failure(api.CodeContainmentUnknown, "native task count is outside its numeric bound")
	}
	return count, nil
}

func (r *linuxResources) ObserveRelease(ctx context.Context, record leaseRecord) (releaseFacts, error) {
	if err := r.Quiescent(ctx, record); err != nil {
		return releaseFacts{}, err
	}
	if r.manager == nil || record.Gate == nil || record.Spec == nil ||
		record.Gate.NativeProfile != "offline-private-v1" && record.Gate.NativeProfile != "enrolled-capabilities-v1" || record.Gate.Permit == nil {
		return releaseFacts{}, failure(api.CodeContainmentUnknown, "native release has no exact owned gate and connection inventory")
	}
	live, ok := r.manager.gates[record.Lease.ID].(*nativeGate)
	if !ok || live.PID() != record.Gate.PID || live.Generation() != record.Gate.Prepared.ProcessGeneration {
		return releaseFacts{}, failure(api.CodeContainmentUnknown, "native wait ownership was lost; release cannot invent an exit")
	}
	observation, err := live.Observe(ctx, gateHandle(record))
	if err != nil {
		return releaseFacts{}, err
	}
	if observation.State != "exited" {
		return releaseFacts{}, failure(api.CodeContainmentUnknown, "native wait is not terminal")
	}
	zeroSurvivors := uint64(0) // Quiescent above measured both the cgroup and every UID thread.
	observation.Survivors = &zeroSurvivors
	connections, err := live.connectionCount()
	if err != nil {
		return releaseFacts{}, err
	}
	if err := releaseCaptureInventory(record); err != nil {
		return releaseFacts{}, err
	}
	jobs, err := r.manager.captureJobs(ctx, record)
	if err != nil {
		return releaseFacts{}, err
	}
	exports, _, err := r.manager.storageReferences(ctx, record)
	if err != nil {
		return releaseFacts{}, err
	}
	return releaseFacts{Observation: observation, LiveConnections: &connections, QueuedJobs: &jobs, WritableExports: &exports}, nil
}

func readControl(root *os.Root, name string) (_ string, resultErr error) {
	defer helperCheck(&resultErr, "cgroup_read")
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", failure(api.CodeContainmentUnknown, "cannot open a required cgroup control")
	}
	data, readErr := io.ReadAll(io.LimitReader(f, 65537))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(data) > 65536 {
		return "", failure(api.CodeContainmentUnknown, "cannot read a bounded cgroup control")
	}
	return strings.TrimSpace(string(data)), nil
}

func writeControl(root *os.Root, name, value string) (resultErr error) {
	defer helperCheck(&resultErr, "cgroup_write")
	f, err := root.OpenFile(name, os.O_WRONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return failure(api.CodePrerequisite, "cannot open delegated cgroup control for writing")
	}
	n, writeErr := f.WriteString(value + "\n")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil || n != len(value)+1 {
		return failure(api.CodePrerequisite, "kernel refused a delegated cgroup control")
	}
	return nil
}

func controllerSet(value string) map[string]bool {
	result := map[string]bool{}
	for _, name := range strings.Fields(value) {
		result[name] = true
	}
	return result
}

func enableControllers(root *os.Root) error {
	available, err := readControl(root, "cgroup.controllers")
	if err != nil {
		return err
	}
	controllers := controllerSet(available)
	if !controllers["cpu"] || !controllers["memory"] || !controllers["pids"] {
		return failure(api.CodePrerequisite, "cpu, memory and pids cgroup-v2 controllers must be delegated by systemd")
	}
	if err := writeControl(root, "cgroup.subtree_control", "+cpu +memory +pids"); err != nil {
		return err
	}
	value, err := readControl(root, "cgroup.subtree_control")
	if err != nil {
		return err
	}
	set := controllerSet(value)
	if !set["cpu"] || !set["memory"] || !set["pids"] {
		return failure(api.CodePrerequisite, "delegated cgroup controllers did not read back")
	}
	return nil
}

func setupCgroups(b installation) error {
	unit := filepath.Dir(b.cgroupPath())
	if err := protectedPath(unit, true); err != nil {
		return err
	}
	root, err := os.OpenRoot(unit)
	if err != nil {
		return failure(api.CodePrerequisite, "cannot pin the installed helper cgroup")
	}
	defer root.Close()
	var fs unix.Statfs_t
	if err := unix.Statfs(unit, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return failure(api.CodePrerequisite, "helper delegation must be on the actual cgroup-v2 filesystem")
	}
	if err := root.Mkdir("control", 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return failure(api.CodePrerequisite, "cannot create helper control cgroup")
	}
	controlPath := filepath.Join(unit, "control")
	if err := protectedPath(controlPath, true); err != nil {
		return err
	}
	// The fixed unit's 0077 umask must not hide its kernel process inventory
	// from the unprivileged verifier. Only root retains directory write access.
	if err := os.Chmod(controlPath, 0755); err != nil {
		return failure(api.CodePrerequisite, "cannot expose read-only helper control facts")
	}
	control, err := root.OpenRoot("control")
	if err != nil {
		return failure(api.CodeIntegrity, "cannot pin helper control cgroup")
	}
	defer control.Close()
	if err := writeControl(control, "cgroup.procs", strconv.Itoa(os.Getpid())); err != nil {
		return err
	}
	if err := enableControllers(root); err != nil {
		return err
	}
	if err := root.Mkdir("lanes", 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return failure(api.CodePrerequisite, "cannot create lane delegation root")
	}
	lanesPath := filepath.Join(unit, "lanes")
	if err := protectedPath(lanesPath, true); err != nil {
		return err
	}
	if err := readableCgroup(lanesPath); err != nil {
		return err
	}
	lanes, err := root.OpenRoot("lanes")
	if err != nil {
		return failure(api.CodeIntegrity, "cannot pin lane delegation root")
	}
	defer lanes.Close()
	return enableControllers(lanes)
}

func (r *linuxResources) open(record leaseRecord) (_ *os.Root, resultErr error) {
	defer helperCheck(&resultErr, "cgroup_open")
	path := filepath.Join(r.binding.cgroupPath(), string(record.Lease.ContainmentID))
	if err := protectedPath(path, true); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "cannot pin leased containment")
	}
	return root, nil
}

func limitValues(record leaseRecord) [][2]string {
	memory := record.Request.Budget.MemoryBytes
	memory -= memory % uint64(os.Getpagesize())
	return [][2]string{
		{"pids.max", strconv.FormatUint(uint64(record.Request.Budget.Processes), 10)},
		{"memory.max", strconv.FormatUint(memory, 10)},
		{"memory.swap.max", "0"},
		{"memory.oom.group", "1"},
		{"cgroup.max.depth", "0"},
		{"cgroup.max.descendants", "0"},
	}
}

func (r *linuxResources) Ensure(ctx context.Context, record leaseRecord) (resultErr error) {
	defer helperCheck(&resultErr, "cgroup_limits")
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := checkAccount(accountForLease(r.binding, record.Lease)); err != nil {
		return err
	}
	if record.Phase == "reserved" {
		if err := uidQuiescent(ctx, record.Lease.UID); err != nil {
			return err
		}
		path := filepath.Join(r.binding.cgroupPath(), string(record.Lease.ContainmentID))
		if err := os.Mkdir(path, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return failure(api.CodePrerequisite, "cannot create reserved lane cgroup")
		}
		if err := protectedPath(path, true); err != nil {
			return err
		}
		if err := readableCgroup(path); err != nil {
			return err
		}
	}
	root, err := r.open(record)
	if err != nil {
		return err
	}
	defer root.Close()
	if record.Phase == "reserved" {
		if err := r.Quiescent(ctx, record); err != nil {
			return err
		}
	}
	for _, pair := range limitValues(record) {
		if record.Phase == "reserved" {
			if err := writeControl(root, pair[0], pair[1]); err != nil {
				return err
			}
		}
		got, err := readControl(root, pair[0])
		if err != nil {
			return err
		}
		if got != pair[1] {
			return failure(api.CodeIntegrity, "leased cgroup limit did not read back exactly")
		}
	}
	return nil
}

func accountForLease(b installation, lease api.HelperLease) account {
	for _, a := range b.Lanes {
		if a.UID == lease.UID && a.GID == lease.GID {
			return a
		}
	}
	return account{}
}

func uidQuiescent(ctx context.Context, uid uint32) (resultErr error) {
	defer helperCheck(&resultErr, "uid_scan")
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return api.WithHelperReason(failure(api.CodeContainmentUnknown, "cannot enumerate UID survivors"), "uid_inventory")
	}
	for _, entry := range entries {
		if err := contextError(ctx); err != nil {
			return err
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		threads, err := os.ReadDir(filepath.Join("/proc", entry.Name(), "task"))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return api.WithHelperReason(failure(api.CodeContainmentUnknown, "cannot enumerate every process thread"), "uid_threads")
		}
		for _, thread := range threads {
			data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "task", thread.Name(), "status"))
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
				continue
			}
			if err != nil {
				return api.WithHelperReason(failure(api.CodeContainmentUnknown, "a process UID is unreadable; retain its lease"), "uid_status")
			}
			found := false
			for _, line := range strings.Split(string(data), "\n") {
				if !strings.HasPrefix(line, "Uid:") {
					continue
				}
				fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
				if len(fields) != 4 {
					return api.WithHelperReason(failure(api.CodeContainmentUnknown, "a process UID observation is malformed"), "uid_shape")
				}
				found = true
				for _, field := range fields {
					value, err := strconv.ParseUint(field, 10, 32)
					if err != nil {
						return api.WithHelperReason(failure(api.CodeContainmentUnknown, "a process UID observation is invalid"), "uid_shape")
					}
					if uint32(value) == uid {
						return api.WithHelperReason(failure(api.CodeContainmentUnknown, "lane UID still owns a live process; retain its lease"), "uid_survivor")
					}
				}
			}
			if !found {
				return api.WithHelperReason(failure(api.CodeContainmentUnknown, "a process UID observation is absent"), "uid_shape")
			}
		}
	}
	return nil
}

func (r *linuxResources) Quiescent(ctx context.Context, record leaseRecord) (resultErr error) {
	defer helperCheck(&resultErr, "cgroup_population")
	root, err := r.open(record)
	if err != nil {
		// Absence is meaningful only after a durable releasing/released record.
		path := filepath.Join(r.binding.cgroupPath(), string(record.Lease.ContainmentID))
		_, statErr := os.Lstat(path)
		if errors.Is(statErr, os.ErrNotExist) {
			return uidQuiescent(ctx, record.Lease.UID)
		}
		return err
	}
	defer root.Close()
	value, err := readControl(root, "cgroup.events")
	if err != nil {
		return err
	}
	populated := ""
	for _, line := range strings.Split(value, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			if populated != "" {
				return failure(api.CodeContainmentUnknown, "duplicate cgroup population observation")
			}
			populated = fields[1]
		}
	}
	if populated != "0" {
		return failure(api.CodeContainmentUnknown, "kernel containment is populated or unknown; retain its lease")
	}
	processes, err := readControl(root, "cgroup.procs")
	if err != nil {
		return err
	}
	if processes != "" {
		return failure(api.CodeContainmentUnknown, "leased containment still has processes")
	}
	return uidQuiescent(ctx, record.Lease.UID)
}

func (r *linuxResources) Remove(ctx context.Context, record leaseRecord) error {
	if err := r.Quiescent(ctx, record); err != nil {
		return err
	}
	// Rmdir removes only the empty, root-owned kernel cgroup. No agent-authored
	// workspace, path supplied in a request, or recursive root deletion is used.
	path := filepath.Join(r.binding.cgroupPath(), string(record.Lease.ContainmentID))
	if err := unix.Rmdir(path); err != nil && !errors.Is(err, unix.ENOENT) {
		return failure(api.CodeContainmentUnknown, "kernel refused empty containment collection; retain its lease")
	}
	return nil
}

func cgroupMembership(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", failure(api.CodeUnauthenticated, "cannot verify helper process containment")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::/") {
			return strings.TrimPrefix(line, "0::"), nil
		}
	}
	return "", failure(api.CodePrerequisite, "unified cgroup-v2 membership is required")
}
