//go:build linux

package admin

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const bwrapProfile = "abi <abi/4.0>,\ninclude <tunables/global>\n\n" +
	"profile laneboss-bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n}\n"

func probeAdmin(ctx context.Context, b installation, manager *leaseManager) []api.Capability {
	checks := []api.Capability{}
	add := func(name string, err error) {
		check := api.Capability{Name: name, Available: err == nil, Reason: "verified installed OS prerequisite"}
		if err != nil {
			var typed *api.Error
			if errors.As(err, &typed) {
				check.Reason = typed.Message
			} else {
				check.Reason = "OS prerequisite is unavailable"
			}
		}
		checks = append(checks, check)
	}
	add("helper.artifact", verifyExecutable(b.binaryPath(), b.Artifact))
	add("helper.service_account", checkAccount(b.Service))
	var accountErr error
	for _, a := range b.Lanes {
		if err := checkAccount(a); err != nil {
			accountErr = err
			break
		}
	}
	add("helper.lane_accounts", accountErr)
	_, storeErr := manager.records()
	add("helper.lease_store", storeErr)
	if store, ok := manager.store.(interface{ Pending() uint64 }); ok && store.Pending() != 0 {
		add("helper.unpublished_state", failure(api.CodeIntegrity, "unpublished helper write retained for administrator diagnosis"))
	}
	add("helper.cgroup_v2", probeCgroups(b))
	add("helper.bwrap_unprivileged", probeBwrap(ctx, b))
	add("helper.apparmor", probeAppArmor())
	add("helper.gate_primitives", probeGatePrimitives())
	add("helper.egress", probeDefaultDenyNetwork(ctx))
	return checks
}

// This prerequisite proves only the installed offline backend. Nonempty
// network grants still require an enrolled forwarding owner and are refused.
func probeDefaultDenyNetwork(ctx context.Context) error {
	namespace, err := newEmptyNetworkNamespace(ctx)
	if err != nil {
		return err
	}
	defer namespace.Close()
	var created, current unix.Stat_t
	if unix.Fstat(int(namespace.Fd()), &created) != nil || unix.Stat("/proc/self/ns/net", &current) != nil || created.Dev == current.Dev && created.Ino == current.Ino {
		return failure(api.CodeContainmentUnknown, "default-deny network namespace was not independently created")
	}
	return nil
}

func probeGatePrimitives() error {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 3 {
		return failure(api.CodePrerequisite, "fixed gate requires actual Landlock ABI 3 or newer")
	}
	sealed, err := sealedBootstrap(api.Empty{})
	if err != nil {
		return err
	}
	seals, sealErr := unix.FcntlInt(sealed.Fd(), unix.F_GET_SEALS, 0)
	closeErr := sealed.Close()
	if sealErr != nil || closeErr != nil || seals&bootstrapSeals != bootstrapSeals {
		return failure(api.CodePrerequisite, "fixed gate sealed-descriptor probe failed")
	}
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return failure(api.CodePrerequisite, "fixed gate requires native pidfd lifetime ownership")
	}
	if err := unix.Close(pidfd); err != nil {
		return failure(api.CodeContainmentUnknown, "cannot collect gate lifetime probe")
	}
	return nil
}

func probeCgroups(b installation) error {
	if err := protectedPath(b.cgroupPath(), true); err != nil {
		return err
	}
	root, err := os.OpenRoot(b.cgroupPath())
	if err != nil {
		return failure(api.CodePrerequisite, "lane cgroup delegation is missing")
	}
	defer root.Close()
	value, err := readControl(root, "cgroup.subtree_control")
	if err != nil {
		return err
	}
	set := controllerSet(value)
	if !set["cpu"] || !set["memory"] || !set["pids"] {
		return failure(api.CodePrerequisite, "lane cgroup controllers are not delegated")
	}
	return nil
}

func verifyBwrap() error {
	if err := protectedPath("/usr/bin/bwrap", false); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Lstat("/usr/bin/bwrap", &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&06022 != 0 || st.Mode&0111 == 0 {
		return failure(api.CodeIntegrity, "distro bwrap must be root-owned and unprivileged; setuid/setgid workaround refused")
	}
	_, err := unix.Getxattr("/usr/bin/bwrap", "security.capability", nil)
	if err == nil || !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return failure(api.CodeIntegrity, "bwrap file capabilities are present or cannot be verified")
	}
	return nil
}

func bwrapCommand(ctx context.Context, b installation, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "HOME=/nonexistent"}
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: b.Service.UID, Gid: b.Service.GID, Groups: []uint32{},
	}, Pdeathsig: syscall.SIGKILL}
	return command
}

func probeBwrap(parent context.Context, b installation) error {
	if err := verifyBwrap(); err != nil {
		return err
	}
	probe, err := user.Lookup("nobody")
	if err != nil {
		return failure(api.CodePrerequisite, "nonservice namespace probe account is missing")
	}
	uid, uidErr := strconv.ParseUint(probe.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(probe.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 || uint32(uid) == b.Service.UID {
		return failure(api.CodeIntegrity, "namespace probe must use a dedicated nonservice identity")
	}
	b.Service.UID, b.Service.GID = uint32(uid), uint32(gid)
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	version, err := bwrapCommand(ctx, b, "--version").Output()
	if err != nil {
		return failure(api.CodePrerequisite, "unprivileged bwrap version probe failed")
	}
	fields := strings.Fields(string(version))
	if len(fields) != 2 || fields[0] != "bubblewrap" {
		return failure(api.CodeUnsupported, "unrecognized distro bwrap version")
	}
	parts := strings.Split(fields[1], ".")
	if len(parts) < 2 {
		return failure(api.CodeUnsupported, "unrecognized distro bwrap version")
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil || major < 0 || minor < 0 || major == 0 && minor < 8 {
		return failure(api.CodeUnsupported, "bwrap 0.8 or later is required")
	}
	// This fixed, read-only host bind probes namespace availability only. It
	// is never a runner layout, accepts no request argv, and runs as service UID.
	if err := bwrapCommand(ctx, b, "--unshare-user", "--unshare-pid", "--ro-bind", "/", "/", "--", "/usr/bin/true").Run(); err != nil {
		return failure(api.CodePrerequisite, "unprivileged bwrap namespace probe failed; retain restriction and install only the bwrap profile when required")
	}
	return nil
}

func probeAppArmor() error {
	data, err := os.ReadFile("/proc/sys/kernel/" + "apparmor_restrict_unprivileged_userns")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return failure(api.CodePrerequisite, "cannot read actual AppArmor namespace restriction")
	}
	required, err := profileRequired(data)
	if err != nil {
		return err
	}
	if !required {
		return nil
	}
	profile, err := readProtected("/etc/apparmor.d/laneboss-bwrap", 4096)
	if err != nil {
		return err
	}
	loaded, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
	if err != nil {
		return failure(api.CodePrerequisite, "cannot verify loaded bwrap AppArmor profile")
	}
	return verifyProfileState(profile, loaded)
}

func profileRequired(data []byte) (bool, error) {
	switch strings.TrimSpace(string(data)) {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, failure(api.CodeUnsupported, "unknown AppArmor namespace restriction value")
	}
}

func verifyProfileState(profile, loaded []byte) error {
	if !bytes.Equal(profile, []byte(bwrapProfile)) {
		return failure(api.CodeIntegrity, "installed bwrap profile differs from the reviewed executable-only source")
	}
	for _, line := range strings.Split(string(loaded), "\n") {
		if line == "laneboss-bwrap (unconfined)" {
			return nil
		}
	}
	return failure(api.CodePrerequisite, "bwrap-only AppArmor profile is not loaded")
}
