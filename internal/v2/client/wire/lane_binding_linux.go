//go:build linux

package wire

import (
	"os"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// LaneEndpointBinding is shared by the service listener and helper projection.
// Its inputs come from the protected installed host and retained spec/UID lease,
// never a lane request. The fixed gate maps only that distinct lane UID/GID;
// the outside service therefore appears as the kernel's overflow IDs inside.
func LaneEndpointBinding(installed api.InstalledBinding, spec api.LaunchSpec, lease api.HelperLease) (api.InstalledBinding, error) {
	var zero api.InstalledBinding
	if err := api.ValidateBinding(installed, installed.Config, installed.ServiceVersion); err != nil {
		return zero, err
	}
	if installed.Class != api.EndpointHuman || installed.Backend != "linux-bwrap-landlock" ||
		spec.Kind != "agent" || spec.Runner == nil || spec.Worker != nil || spec.Backend != installed.Backend ||
		!ValidID(string(spec.LaunchID)) || !ValidID(string(spec.Target.LifeID)) || spec.Target.Run == 0 || uint64(spec.Target.Run) > 1<<53-1 ||
		!ValidID(string(lease.ID)) || !ValidID(string(lease.ContainmentID)) || spec.UIDLeaseID != lease.ID ||
		spec.EndpointGeneration != lease.EndpointGeneration || lease.EndpointGeneration != installed.EndpointGeneration ||
		lease.UID == 0 || lease.GID == 0 || lease.UID == installed.ServiceUID || lease.GID == installed.ServiceGID {
		return zero, bindingError("lane endpoint differs from its retained native spec and distinct UID lease")
	}
	uid, gid, err := NamespaceServiceIDs()
	if err != nil {
		return zero, err
	}
	binding := installed
	target := spec.Target
	binding.Class, binding.LaunchID, binding.Target, binding.WorkerLeaseID = api.EndpointLane, spec.LaunchID, &target, ""
	binding.Socket = LaneSocketPath
	binding.MappedServiceUID, binding.MappedServiceGID = uid, gid
	return binding, api.ValidateBinding(binding, installed.Config, installed.ServiceVersion)
}

// NamespaceServiceIDs is used outside the gate when sealing lane/worker
// bindings for the fixed single-UID user namespace. Never infer mapped server
// IDs from the host IDs or from a caller's environment.
func NamespaceServiceIDs() (uint32, uint32, error) {
	uid, err := kernelOverflowID("/proc/sys/kernel/overflowuid")
	if err != nil {
		return 0, 0, err
	}
	gid, err := kernelOverflowID("/proc/sys/kernel/overflowgid")
	return uid, gid, err
}

func kernelOverflowID(path string) (uint32, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, bindingError("kernel namespace service identity is unavailable")
	}
	var raw [33]byte
	n, readErr := file.Read(raw[:])
	closeErr := file.Close()
	value, parseErr := strconv.ParseUint(strings.TrimSpace(string(raw[:n])), 10, 32)
	if readErr != nil || closeErr != nil || parseErr != nil || n == len(raw) || value == 1<<32-1 {
		return 0, bindingError("kernel namespace service identity is invalid")
	}
	return uint32(value), nil
}
