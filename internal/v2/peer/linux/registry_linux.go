package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Registry is a live kernel-handle projection for the authenticated helper.
// Its control methods are not public RPCs. Admin must validate a real allocated
// lease and journal it before RegisterContainment, then reconstruct the same
// live projection on recovery. New never invents or enrolls a lease.
type Registry struct {
	mu      sync.RWMutex
	boot    string
	root    objectKey
	entries map[api.ID]api.ContainmentBinding
	objects map[objectKey]api.ID
	leases  map[api.ID]bool
	uids    map[uint32]api.ID
	closed  bool
}

var _ api.ContainmentRegistry = (*Registry)(nil)

func NewRegistry() (*Registry, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(strings.TrimSpace(string(boot))) != 36 {
		return nil, peerError(api.CodePrerequisite, "host boot identity is unavailable")
	}
	fd, key, err := openGroup(".")
	if err != nil {
		return nil, err
	}
	if err := unix.Close(fd); err != nil {
		return nil, peerError(api.CodeIntegrity, "cgroup root probe could not close")
	}
	return &Registry{boot: strings.TrimSpace(string(boot)), root: key, entries: make(map[api.ID]api.ContainmentBinding),
		objects: make(map[objectKey]api.ID), leases: make(map[api.ID]bool), uids: make(map[uint32]api.ID)}, nil
}

func registryConfig(value string) bool {
	if len(value) < 1 || len(value) > 32 || value[0] == '-' {
		return false
	}
	for _, c := range value {
		if c != '-' && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func (r *Registry) RegisterContainment(ctx context.Context, binding api.ContainmentBinding) (resultErr error) {
	if r == nil || r.entries == nil || r.boot == "" {
		return peerError(api.CodePrerequisite, "containment registry was not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !registryConfig(binding.Config) || binding.Backend != "linux-bwrap-landlock" || binding.BootID != r.boot ||
		binding.Generation == 0 || binding.Revoked || binding.Directory == nil || !validID(binding.Target.LifeID) || binding.Target.Run == 0 ||
		!validID(binding.Lease.ID) || !validID(binding.Lease.ContainmentID) || binding.Lease.UID == 0 || binding.Lease.GID == 0 || binding.Lease.EndpointGeneration == 0 {
		return peerError(api.CodeInvalid, "incomplete helper containment registration")
	}
	fd, err := unix.FcntlInt(binding.Directory.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return peerError(api.CodeContainmentUnknown, "helper directory handle cannot be pinned")
	}
	owned := os.NewFile(uintptr(fd), "registered-cgroup")
	retained := false
	defer func() {
		if !retained {
			resultErr = errors.Join(resultErr, owned.Close())
		}
	}()
	var stat unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &stat) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Mode&0022 != 0 {
		return peerError(api.CodeContainmentUnknown, "helper containment directory is not protected cgroup v2")
	}
	key := objectKey{device: uint64(stat.Dev), inode: stat.Ino}
	if key == r.root || key.device != r.root.device {
		return peerError(api.CodeInvalid, "a dedicated host cgroup is required")
	}
	// Reopen only the kernel-reported directory through the protected cgroup
	// root. A detached/deleted directory or a different mount is not enrolled.
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return peerError(api.CodeContainmentUnknown, "helper directory identity is unavailable")
	}
	relative, err := filepath.Rel("/sys/fs/cgroup", path)
	if err != nil || relative == "." {
		return peerError(api.CodeInvalid, "a dedicated host cgroup is required")
	}
	current, currentKey, err := openGroup(relative)
	if err != nil {
		return err
	}
	if err := unix.Close(current); err != nil {
		return peerError(api.CodeIntegrity, "directory verification handle could not close")
	}
	if currentKey != key {
		return peerError(api.CodeContainmentUnknown, "helper directory was replaced")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.closed {
		return peerError(api.CodeUnavailable, "containment registry is closed")
	}
	id := binding.Lease.ContainmentID
	if _, exists := r.entries[id]; exists || r.leases[binding.Lease.ID] || r.objects[key] != "" || r.uids[binding.Lease.UID] != "" {
		return peerError(api.CodeConflict, "containment, lease, UID or directory is already allocated")
	}
	binding.Directory = owned
	r.entries[id], r.leases[binding.Lease.ID], r.objects[key], r.uids[binding.Lease.UID] = binding, true, id, id
	retained = true
	return nil
}

// ResolveContainment consumes actual kernel facts and an installed endpoint,
// without a Scope, store read or identity callback. Directory in the returned
// binding is borrowed from this registry until Close; callers must not close it.
func (r *Registry) ResolveContainment(ctx context.Context, facts api.PeerFacts, binding api.InstalledBinding) (api.ContainmentBinding, error) {
	var empty api.ContainmentBinding
	if r == nil || r.entries == nil || r.boot == "" {
		return empty, peerError(api.CodePrerequisite, "containment registry was not initialized")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := api.ValidateBinding(binding, binding.Config, binding.ServiceVersion); err != nil {
		return empty, err
	}
	if binding.Backend != "linux-bwrap-landlock" || binding.Class != api.EndpointLane && binding.Class != api.EndpointWorker ||
		facts.HostPID <= 1 || facts.HostUID == 0 || facts.HostGID == 0 {
		return empty, peerError(api.CodeContainmentUnknown, "lane containment requires host kernel facts and a lane or worker endpoint")
	}
	observed, err := readProcess(facts.HostPID, facts.HostUID, facts.HostGID)
	if err != nil {
		return empty, err
	}
	if facts.ProcessGeneration != observed.generation || !strings.HasPrefix(observed.generation, r.boot+":") {
		return empty, peerError(api.CodeUnauthenticated, "peer process generation differs from the current host")
	}
	fd, key, err := openGroup(observed.group)
	if err != nil {
		return empty, err
	}
	if err := unix.Close(fd); err != nil {
		return empty, peerError(api.CodeIntegrity, "peer group probe could not close")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	id := r.objects[key]
	entry, exists := r.entries[id]
	if r.closed || !exists || entry.Revoked || entry.Directory == nil || entry.Config != binding.Config ||
		binding.Target == nil || entry.Target != *binding.Target || entry.Backend != binding.Backend || entry.BootID != r.boot ||
		entry.Lease.UID != facts.HostUID || entry.Lease.GID != facts.HostGID || entry.Lease.EndpointGeneration != binding.EndpointGeneration ||
		facts.ContainmentID != "" && facts.ContainmentID != id {
		return empty, peerError(api.CodeContainmentUnknown, "peer has no matching current helper allocation")
	}
	return entry, nil
}

func (r *Registry) RevokeContainment(ctx context.Context, id api.ID) error {
	if r == nil || r.entries == nil {
		return peerError(api.CodePrerequisite, "containment registry was not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, exists := r.entries[id]
	if r.closed || !exists {
		return peerError(api.CodeNotFound, "containment registration is absent")
	}
	entry.Revoked = true
	r.entries[id] = entry
	// Keep the pin, UID and retired IDs until helper shutdown. Revocation does
	// not prove quiescence, authorize lease release, or permit allocation reuse.
	return nil
}

func (r *Registry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	for id, entry := range r.entries {
		err = errors.Join(err, entry.Directory.Close())
		entry.Directory = nil
		r.entries[id] = entry
	}
	return err
}
