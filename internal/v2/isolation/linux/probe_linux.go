//go:build linux

package linux

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func readSysctl(name string) (*int, error) {
	data, err := os.ReadFile("/proc/sys/kernel/" + name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func versionAtLeast(version string, major, minor int) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}
	first, e1 := strconv.Atoi(parts[0])
	second, e2 := strconv.Atoi(parts[1])
	return e1 == nil && e2 == nil && (first > major || first == major && second >= minor)
}

// Cache successful pinned-binary behavior by boot and executable/caller
// identity. Mutable host prerequisites do not use this cache. Per-run opened
// objects/leases still require validation; failed observations are not cached.
type probeCache struct {
	mu    sync.Mutex
	key   string
	facts api.IsolationCapabilities
}

func cloneFacts(facts api.IsolationCapabilities) api.IsolationCapabilities {
	facts.Checks = append([]api.Capability{}, facts.Checks...)
	return facts
}

func (cache *probeCache) get(key string, measure func() (api.IsolationCapabilities, error)) (api.IsolationCapabilities, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.key == key && key != "" {
		return cloneFacts(cache.facts), nil
	}
	facts, err := measure()
	if err == nil {
		cache.key, cache.facts = key, cloneFacts(facts)
	}
	return facts, err
}

func probePrerequisites(ctx context.Context) (api.IsolationCapabilities, error) {
	// Sysctls, mount topology and path ancestry can change without a boot or
	// executable inode change. Recheck them even on restriction-zero hosts.
	return measureHost(ctx)
}

func probeHost(ctx context.Context) (api.IsolationCapabilities, error) {
	facts, err := probePrerequisites(ctx)
	if err != nil {
		return facts, err
	}
	for _, name := range []string{"bwrap_options", "namespace_boundary", "seccomp_deny_filter", "uid_pool",
		"cgroup_containment", "controlled_egress", "runtime_projection", "capture_pipes", "launch_gate"} {
		facts.Checks = append(facts.Checks, api.Capability{Name: name, Available: false,
			Reason: "requires resolved protected objects and causal helper receipts"})
	}
	// Host filesystem/version checks are not confinement proof. Even though the
	// filter is authored, seccomp_deny_filter stays false until a real bootstrap
	// canary through the installed production helper attests its enforcement.
	return facts, missingControl("Probe")
}

func measureHost(ctx context.Context) (api.IsolationCapabilities, error) {
	facts, err := measureHostBasics(ctx)
	if err != nil {
		return facts, err
	}
	return measureAppArmor(ctx, facts)
}

func measureAppArmor(ctx context.Context, facts api.IsolationCapabilities) (api.IsolationCapabilities, error) {
	restricted, err := readSysctl("apparmor_restrict_unprivileged_userns")
	if err == nil && restricted != nil && *restricted != 0 && *restricted != 1 {
		err = errors.New("unknown AppArmor user namespace restriction")
	}
	facts.Checks = append(facts.Checks, api.Capability{Name: "apparmor_sysctl", Available: err == nil})
	if err != nil {
		return facts, &PrerequisiteError{Check: "apparmor_sysctl", Err: err}
	}
	if restricted != nil && *restricted == 1 {
		err := checkAppArmorProfile(ctx)
		facts.Checks = append(facts.Checks, api.Capability{Name: "apparmor_profile", Available: err == nil})
		if err != nil {
			return facts, &PrerequisiteError{Check: "apparmor_profile", Err: err}
		}
	}
	return facts, nil
}

func measureHostBasics(ctx context.Context) (api.IsolationCapabilities, error) {
	facts := api.IsolationCapabilities{Backend: backendName}
	check := func(name string, err error) error {
		facts.Checks = append(facts.Checks, api.Capability{Name: name, Available: err == nil})
		if err != nil {
			return &PrerequisiteError{Check: name, Err: err}
		}
		return nil
	}
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return facts, check("kernel", err)
	}
	facts.Kernel = strings.TrimSpace(string(kernel))
	if !versionAtLeast(facts.Kernel, 6, 6) {
		return facts, check("kernel", errors.New("Linux 6.6 or newer is required"))
	}
	if err := check("kernel", nil); err != nil {
		return facts, err
	}
	facts.LandlockABI, err = landlockABI()
	if err := check("landlock_abi", err); err != nil {
		return facts, err
	}
	var cgroup unix.Statfs_t
	err = unix.Statfs("/sys/fs/cgroup", &cgroup)
	if err == nil && uint64(cgroup.Type) != uint64(unix.CGROUP2_SUPER_MAGIC) {
		err = errors.New("cgroup v2 mount is required")
	}
	if err := check("cgroup_v2_mount", err); err != nil {
		return facts, err
	}
	clone, err := readSysctl("unprivileged_userns_clone")
	if err == nil && clone != nil && *clone != 1 {
		err = errors.New("unprivileged user namespaces are disabled")
	}
	if err := check("userns_switch", err); err != nil {
		return facts, err
	}
	resolved, err := safeSystemPath(bwrapPath)
	if err == nil && resolved != bwrapPath {
		err = errors.New("distro bwrap path changed")
	}
	if err := check("distro_bwrap", err); err != nil {
		return facts, err
	}
	info, err := os.Stat(bwrapPath)
	if err == nil && (!info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0) {
		err = errors.New("distro bwrap must be a regular non-setuid executable")
	}
	if err := check("bwrap_mode", err); err != nil {
		return facts, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(probeCtx, bwrapPath, "--version")
	command.Env = []string{}
	output, err := command.Output()
	if err == nil {
		fields := strings.Fields(string(output))
		if len(fields) != 2 || fields[0] != "bubblewrap" || !versionAtLeast(fields[1], 0, 8) {
			err = errors.New("bubblewrap 0.8 or newer is required")
		}
	}
	if err := check("bwrap_version", err); err != nil {
		return facts, err
	}
	// Option semantics are proved by requireBwrapOptions with the pinned
	// runtime/bootstrap before a runner starts. Help or manual text is not
	// capability evidence; this host-only observation does not advertise it.
	return facts, nil
}
