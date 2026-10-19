//go:build linux

package admin

import (
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type processSetUID struct {
	effective       bool
	permitted       bool
	bounding        bool
	permittedSetGID bool
	permittedBits   uint64
}

// /proc/self/status describes the thread-group leader. /proc/thread-self
// would repeat the launch-thread observation and hide a per-thread difference.
func readProcessSetUID() (processSetUID, error) {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return processSetUID{}, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 65537))
	closeErr := file.Close()
	if readErr != nil {
		return processSetUID{}, readErr
	}
	if closeErr != nil {
		return processSetUID{}, closeErr
	}
	if len(data) > 65536 {
		return processSetUID{}, unix.EOVERFLOW
	}
	return parseProcessSetUID(data)
}

func parseProcessSetUID(data []byte) (processSetUID, error) {
	var result processSetUID
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found || name != "CapEff" && name != "CapPrm" && name != "CapBnd" {
			continue
		}
		if seen[name] {
			return processSetUID{}, unix.EINVAL
		}
		seen[name] = true
		parts := strings.Fields(value)
		if len(parts) != 1 {
			return processSetUID{}, unix.EINVAL
		}
		bits, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			return processSetUID{}, unix.EINVAL
		}
		present := bits&(uint64(1)<<unix.CAP_SETUID) != 0
		switch name {
		case "CapEff":
			result.effective = present
		case "CapPrm":
			result.permittedBits = bits
			result.permitted = present
			result.permittedSetGID = bits&(uint64(1)<<unix.CAP_SETGID) != 0
		case "CapBnd":
			result.bounding = present
		}
	}
	if len(seen) != 3 {
		return processSetUID{}, unix.EINVAL
	}
	return result, nil
}

func nativeMainCapabilityFacts() string {
	state, err := readProcessSetUID()
	return processCapabilityFacts(state, err)
}

func processCapabilityFacts(state processSetUID, err error) string {
	if err != nil {
		return "process CAP_SETUID=" + nativeFactError(err)
	}
	verdict := func(present bool) string {
		if present {
			return "present"
		}
		return "absent"
	}
	return "process CAP_SETUID CapEff=" + verdict(state.effective) + ", CapPrm=" + verdict(state.permitted) + ", CapBnd=" + verdict(state.bounding)
}

// Read once so the retained checkpoint and the startup decision describe the
// same process state. This is a prerequisite, not a capability repair.
func helperBeforeAccounts(output io.Writer, read func() (processSetUID, error), readUIDs func() ([3]uint32, error)) error {
	state, err := read()
	if encodeErr := json.NewEncoder(output).Encode(map[string]string{"stage": "helper.before_accounts", "observation": processCapabilityFacts(state, err)}); encodeErr != nil {
		return failure(api.CodeUnavailable, "cannot retain helper startup capability observation")
	}
	if err != nil {
		return failure(api.CodePrerequisite, "helper.before_accounts: cannot read process permitted CAP_SETUID/CAP_SETGID; inspect the installed laneboss-helper systemd unit")
	}
	ids, uidErr := readUIDs()
	if uidErr != nil {
		return failure(api.CodePrerequisite, "helper.before_accounts: cannot observe real, effective and saved UIDs")
	}
	if ids[0] != 0 || ids[1] != 0 || ids[2] != 0 {
		return failure(api.CodeForbidden, "helper.before_accounts: real, effective and saved UIDs must all be root; inspect the installed laneboss-helper systemd unit")
	}
	var missing []string
	if !state.permitted {
		missing = append(missing, "CAP_SETUID")
	}
	if !state.permittedSetGID {
		missing = append(missing, "CAP_SETGID")
	}
	if len(missing) != 0 {
		return failure(api.CodePrerequisite, "helper.before_accounts: process permitted set lacks "+strings.Join(missing, ", ")+"; inspect the installed laneboss-helper systemd unit (User/NoNewPrivileges policy)")
	}
	expected, policyErr := intendedHelperCapabilities()
	if policyErr != nil {
		return failure(api.CodeIntegrity, "helper.before_accounts: cannot resolve the installed helper unit capability policy")
	}
	if missing := expected &^ state.permittedBits; missing != 0 {
		return failure(api.CodePrerequisite, "helper.before_accounts: process permitted set is missing intended capabilities; inspect the installed laneboss-helper systemd unit")
	}
	if extra := state.permittedBits &^ expected; extra != 0 {
		return failure(api.CodePrerequisite, "helper.before_accounts: process permitted set has unexpected capabilities; inspect the installed laneboss-helper systemd unit")
	}
	return nil
}
