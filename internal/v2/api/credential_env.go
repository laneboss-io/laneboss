package api

import (
	"reflect"
	"slices"
	"time"
)

// Native observations immediately before final execve; no values are carried.
type CredentialExecEnvironment struct {
	PreparedID     ID
	Stage          string
	UID            uint32
	GID            uint32
	Capabilities   *uint64
	Backend        string
	IsolationReady bool
	ObservedAt     Timestamp
	EarlierNames   []string
	VendorNames    []string
}

// These fixed names are derived by the pinned adapter, never task grants.
func credentialFixedEnvironment(driver Driver, name string) bool {
	if driver != DriverCodex && driver != DriverClaudock {
		return false
	}
	if slices.Contains([]string{"HOME", "PATH", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "GOMAXPROCS"}, name) {
		return true
	}
	if driver == DriverCodex {
		return name == "CODEX_HOME"
	}
	return slices.Contains([]string{"CLAUDE_CONFIG_DIR", "CLAUDOCK_CREDENTIAL_STORE", "CLAUDOCK_REGISTRY_DIR"}, name)
}

// ClaudeSlotEnvironment derives the single vendor variable for a supported
// Claudock slot. An unsupported mode has no environment projection.
func ClaudeSlotEnvironment(mode string) string {
	switch mode {
	case "claudock-headless":
		return "CLAUDE_CODE_OAUTH_TOKEN"
	case "claude-api-key":
		return "ANTHROPIC_API_KEY"
	default:
		return ""
	}
}

func ValidateCredentialEnvironment(record CredentialProjectionRecord, exec CredentialExecEnvironment) error {
	a := record.Authority
	r := a.Request
	now, stampErr := time.Parse(time.RFC3339Nano, string(exec.ObservedAt))
	if stampErr != nil || record.State != "held" || record.Receipt == nil || a.Revoked || record.Fence != nil || record.Withdrawal != nil ||
		!launchGeneration(a.Generation) || a.Generation >= launchMaxInteger || record.Generation != a.Generation+1 ||
		exec.PreparedID != r.Prepared.ID || exec.Stage != "vendor_exec" ||
		exec.UID == 0 || exec.UID != r.Lease.UID || exec.GID == 0 || exec.GID != r.Lease.GID ||
		exec.Capabilities == nil || *exec.Capabilities != 0 || !exec.IsolationReady || exec.Backend != r.Handoff.Spec.Backend {
		return launchInvalid("credential environment preceded the final isolated vendor exec")
	}
	expected, err := CredentialTargets(r, now)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(a.Targets, expected) || len(a.Sources) != len(a.Targets) {
		return launchInvalid("credential environment changed its complete selected targets")
	}
	if err := validateCredentialHolding(a, *record.Receipt); err != nil {
		return err
	}
	selected := map[string]bool{}
	taskNames := map[string]bool{}
	for index, target := range a.Targets {
		source := a.Sources[index]
		if source.Revoked || source.Key != target.Key || !launchGeneration(source.Generation) || source.Version == "" ||
			target.SlotID == "" && source.Version != target.Version {
			return launchInvalid("credential environment source was revoked or replaced")
		}
		name := target.EnvironmentName
		if name == "" {
			continue
		}
		if target.SlotID == "" && !credentialEnvironment(name) ||
			target.SlotID != "" && (r.Handoff.Spec.Runner == nil || name != ClaudeSlotEnvironment(r.Handoff.Spec.Runner.Slot.Mode)) {
			return launchInvalid("credential environment selected a reserved or foreign name")
		}
		selected[name] = true
		if slices.Contains(exec.EarlierNames, name) {
			return launchInvalid("credential environment reached a privileged or outer process")
		}
		count := 0
		for _, actual := range exec.VendorNames {
			if actual == name {
				count++
			}
		}
		if count != 1 {
			return launchInvalid("credential environment is absent or duplicated at vendor exec")
		}
	}
	for _, grant := range r.Handoff.Spec.Grants.Secrets {
		if grant.Delivery == "env" && slices.Contains(r.Handoff.Spec.Injection.GrantIDs, grant.ID) && selected[grant.Target] {
			taskNames[grant.Target] = true
		}
	}
	for _, grant := range r.WorkerCredentials {
		if grant.Delivery == "env" && selected[grant.Target] {
			taskNames[grant.Target] = true
		}
	}
	for _, name := range r.Handoff.Spec.Injection.TaskSecretNames {
		if !taskNames[name] {
			return launchInvalid("credential environment omitted a named injected task secret")
		}
	}
	if runner := r.Handoff.Spec.Runner; runner != nil {
		for _, name := range runner.EnvironmentNames {
			if !credentialFixedEnvironment(runner.Driver, name) && !selected[name] {
				return launchInvalid("credential environment omitted a required runner name")
			}
		}
	}
	return nil
}
