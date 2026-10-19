package hookconfig

import (
	"errors"
	"strconv"
	"strings"
)

func sandboxKey(key string) bool {
	return key == "writable_roots" || key == "sandbox_workspace_write" || key == "sandbox_mode" ||
		key == "exclude_slash_tmp" || key == "exclude_tmpdir_env_var"
}

// Permission sources that bypass the vetted workspace model are never trusted.
// Unknown permission, sandbox or approval directives also fail closed.
func permissionKey(key string) bool {
	switch key {
	case "default_permissions":
		return true
	case "permissions", "approvals_reviewer", "mcp_servers", "notify", "use_legacy_landlock", "guardianv2", "guardian_ext":
		return true
	case "approval_policy", "sandbox_mode", "sandbox_workspace_write", "exclude_slash_tmp", "exclude_tmpdir_env_var", "writable_roots":
		return false
	}
	name := strings.ToLower(key)
	return strings.Contains(name, "permission") || strings.Contains(name, "sandbox") || strings.Contains(name, "approval")
}

func sandboxSafe(value any) bool {
	table, ok := value.(map[string]any)
	return ok && table["exclude_slash_tmp"] == true && table["exclude_tmpdir_env_var"] == true
}

func agentsSafe(value any) bool {
	table, ok := value.(map[string]any)
	return ok && len(table) == 1 && table["enabled"] == false
}

func agentFeature(key string) bool { return key == "multi_agent_v2" || key == "collab" }

type codexFlagSpec struct {
	value   bool
	allowed []string
}

// This is the flag inventory used by lane start/resume, the bundled acceptance
// adapter, invocation-local hook trust, and version/feature probes.
var codexFlags = map[string]codexFlagSpec{
	"-c": {value: true}, "--config": {value: true},
	"--model": {value: true}, "-m": {value: true},
	"-p": {value: true}, "--profile": {value: true},
	"--enable":           {value: true, allowed: []string{"hooks"}},
	"--disable":          {value: true, allowed: []string{"plugins"}},
	"--ask-for-approval": {value: true, allowed: []string{"never"}},
	"-a":                 {value: true, allowed: []string{"never"}},
	"--sandbox":          {value: true, allowed: []string{"workspace-write", "read-only"}},
	"-s":                 {value: true, allowed: []string{"workspace-write", "read-only"}},
	"--json":             {}, "--skip-git-repo-check": {}, "--last": {}, "--version": {},
	CodexTrustBypass: {},
}

func codexFlag(word string) (string, string, bool) {
	if strings.HasPrefix(word, "--") {
		return strings.Cut(word, "=")
	}
	if len(word) > 2 {
		return word[:2], strings.TrimPrefix(word[2:], "="), true
	}
	return word, "", false
}

func flagRefusal(flag string) error {
	if strings.ContainsAny(flag, " \t\r\n") {
		return errors.New("Codex flag name cannot be vetted")
	}
	if flag == "-C" || flag == "--cd" {
		return errors.New("Codex directory overrides cannot be vetted: flag " + strconv.Quote(flag))
	}
	if flag == "-a" || flag == "--ask-for-approval" {
		return errors.New("Codex approval_policy must be never: flag " + strconv.Quote(flag))
	}
	if flag == "-s" || flag == "--sandbox" {
		return errors.New("Codex sandbox mode cannot expose unvetted roots: flag " + strconv.Quote(flag))
	}
	return errors.New("Codex flag is outside the vetted argv allowlist: " + strconv.Quote(flag))
}

// HOME chooses the already-vetted instance source. The other two names are
// transport inputs used by the acceptance provider; unknown CODEX_* controls
// cannot introduce an unvetted configuration or execution policy.
func vetEnvironment(environment map[string]string) error {
	for key := range environment {
		if !strings.HasPrefix(key, "CODEX_") || key == "CODEX_HOME" || key == "CODEX_API_KEY" || key == "CODEX_BASE_URL" {
			continue
		}
		if strings.ContainsAny(key, " \t\r\n") {
			return errors.New("Codex environment name cannot be vetted")
		}
		return errors.New("Codex unvetted environment control " + strconv.Quote(key))
	}
	return nil
}

func VetCodexEnvironment(environment []string) error {
	keys := map[string]string{}
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		keys[key] = ""
	}
	return vetEnvironment(keys)
}

func vetSandboxArgs(args []string, laneSandbox ...bool) error {
	replaced := len(laneSandbox) == 1 && laneSandbox[0]
	role, operands := "", 0
	options := true
	for i := 0; i < len(args); i++ {
		word := args[i]
		if options && word == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(word, "-") && word != "-" {
			flag, value, inline := codexFlag(word)
			spec, known := codexFlags[flag]
			if !known {
				return flagRefusal(flag)
			}
			if !spec.value {
				if inline {
					return flagRefusal(flag)
				}
				continue
			}
			if !inline {
				i++
				if i >= len(args) {
					return flagRefusal(flag)
				}
				value = args[i]
			}
			if value == "" || strings.HasPrefix(value, "-") {
				return flagRefusal(flag)
			}
			if flag == "--enable" || flag == "--disable" {
				for _, feature := range strings.Split(value, ",") {
					if key := strings.TrimSpace(feature); agentFeature(key) {
						return errors.New("Codex collaboration feature cannot carry hook trust: " + strconv.Quote(key))
					}
				}
			}
			if len(spec.allowed) > 0 {
				found := false
				if replaced && (flag == "--sandbox" || flag == "-s") && value == "danger-full-access" {
					found = true
				}
				for _, allowed := range spec.allowed {
					found = found || value == allowed
				}
				if !found {
					return flagRefusal(flag)
				}
			}
			continue
		}
		if role == "" {
			switch word {
			case "exec", "features":
				role = word
				continue
			default:
				return errors.New("Codex invocation requires exec or a vetted probe")
			}
		}
		if role == "features" {
			if word != "list" || operands != 0 {
				return errors.New("Codex feature probe requires list")
			}
		} else if role == "exec" && operands == 0 && word == "resume" {
			role = "resume"
			continue
		} else if role == "exec" && operands == 0 && (word == "review" || word == "help") {
			return errors.New("Codex exec subcommand is outside the vetted argv allowlist")
		}
		operands++
		if (role != "resume" && operands > 1) || operands > 2 {
			return errors.New("Codex invocation has extra positional arguments")
		}
	}
	return nil
}

func writableRoots(path, cwd string, launchArgs ...[]string) ([]string, error) {
	return writableRootsForLane(path, cwd, false, launchArgs...)
}

func writableRootsForLane(path, cwd string, replaced bool, launchArgs ...[]string) ([]string, error) {
	return writableRootsIn(path, cwd, replaced, nil, launchArgs...)
}

func writableRootsIn(path, cwd string, replaced bool, environment map[string]string, launchArgs ...[]string) ([]string, error) {
	for _, args := range launchArgs {
		if err := vetSandboxArgs(args, replaced); err != nil {
			return nil, trustError(path, "user config layer cannot be assumed to load: "+err.Error())
		}
	}
	document, err := instanceDocument(path, environment)
	if err != nil {
		return nil, err
	}
	if !sandboxSafe(document["sandbox_workspace_write"]) {
		return nil, trustError(path, "sandbox_workspace_write must exclude_slash_tmp and exclude_tmpdir_env_var; re-render")
	}
	if !agentsSafe(document["agents"]) {
		return nil, trustError(path, "agents.enabled must be false without role tables; re-render")
	}
	// The CLI store is independently vetted and hook-protected. Only the cwd is
	// an ordinary writable workspace; both implicit temp roots remain excluded.
	return []string{cwd}, nil
}

func vetWriteRoots(home string, roots, protected []string) error {
	for _, root := range roots {
		if err := vetCwd(home, root, protected...); err != nil {
			return err
		}
	}
	return nil
}
