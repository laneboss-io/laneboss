//go:build darwin

package lanesandbox

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"laneboss.io/laneboss/internal/rolepolicy"
)

// ReplacesRunner is evaluated before a runner's own sandbox is disabled.
// An unavailable outer wrapper never grants a full-access runner invocation.
func ReplacesRunner(data map[string]any) bool {
	if !Enabled(data) {
		return false
	}
	info, err := os.Stat("/usr/bin/sandbox-exec")
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}

// CheckClaudeSettings accepts only a rendered settings file which explicitly
// disables the opt-in Claude sandbox. Claudock passes these options to Claude.
func CheckClaudeSettings(argv []string) error {
	program, args, _, err := runnerInvocation(argv, nil)
	if err != nil {
		return err
	}
	if program != "claude" && program != "claudock" {
		return nil
	}
	path, err := claudeSettingsPath(program, args)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New("Claude settings for the lane sandbox cannot be read")
	}
	var settings map[string]any
	if json.Unmarshal(data, &settings) != nil {
		return errors.New("Claude settings for the lane sandbox are not valid JSON")
	}
	sandbox, _ := settings["sandbox"].(map[string]any)
	if sandbox["enabled"] != false {
		return errors.New("Claude settings must keep sandbox.enabled=false when the Laneboss sandbox replaces it; prepare the lane settings overlay")
	}
	return nil
}

func nativeRunner(cmd *exec.Cmd, paths []string, allowed []writeAllowance) (bool, string, string) {
	prepared, notice := darwinRunner(cmd, paths, allowed)
	if !prepared {
		return false, "", notice
	}
	return true, "sandbox-exec", ""
}

// DarwinRunner wraps a prepared runner command without constraining its parent.
// It must be called after role and hook vetting of the original runner argv.
// An unavailable sandbox-exec leaves the command unchanged and returns a notice
// for the supervisor to record. It does not start a process.
func DarwinRunner(cmd *exec.Cmd, paths []string) (applied bool, notice string) {
	return darwinRunner(cmd, paths, nil)
}

func darwinRunner(cmd *exec.Cmd, paths []string, allowed []writeAllowance) (applied bool, notice string) {
	const program = "/usr/bin/sandbox-exec"
	info, err := os.Stat(program)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return false, "sandbox-exec is unavailable; runner continues without a Laneboss-files sandbox"
	}
	if cmd == nil || cmd.Path == "" || len(cmd.Args) == 0 {
		return false, "runner command is incomplete; no Laneboss-files sandbox was prepared"
	}
	profile, err := darwinProfile(paths, allowed)
	if err != nil {
		return false, "protected paths could not be profiled; no Laneboss-files sandbox was prepared"
	}
	argv := []string{program, "-p", profile, cmd.Path}
	argv = append(argv, cmd.Args[1:]...)
	cmd.Path = program
	cmd.Args = argv
	return true, ""
}

// Exceptions are explicit rules for the selected runner's own data only.
// Never grant the vendor home or another configuration's data as a whole.
func nativeAllowedWrites(cmd *exec.Cmd, c Configuration, protected []string) ([]writeAllowance, error) {
	if cmd == nil {
		return nil, errors.New("runner command is missing")
	}
	program, args, effective, err := runnerInvocation(cmd.Args, cmd.Env)
	if err != nil {
		return nil, err
	}
	provider, home := "", ""
	if strings.HasPrefix(program, "codex") {
		provider, home = "codex", effective["CODEX_HOME"]
	} else if program == "claude" || program == "claudock" {
		settings, err := claudeSettingsPath(program, args)
		if err != nil {
			return nil, err
		}
		provider, home = "claude", claudeDataHome(settings)
	}
	if provider == "" {
		return nil, nil
	}
	if !validPath(home) || filepath.Base(home) != "."+provider {
		return nil, errors.New("runner data exceptions require the selected rendered vendor home")
	}
	org, err := rolepolicy.ConfigRoot(c.Home, c.Data)
	if err != nil || org == "" {
		return nil, errors.New("runner data exceptions require the configured org")
	}
	instances := filepath.Join(org, ".laneboss", "instances")
	instance := filepath.Dir(filepath.Clean(home))
	if filepath.Dir(instance) != instances {
		return nil, errors.New("runner data exceptions must belong to an instance of the configured org")
	}
	info, err := os.Lstat(filepath.Join(instance, "instance.toml"))
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("selected runner instance cannot be inspected")
	}
	canonicalHome, err := filepath.EvalSymlinks(home)
	if err != nil || canonicalHome != filepath.Clean(home) {
		return nil, errors.New("selected runner data home must resolve without instance aliases")
	}
	directories := []string{"sessions", "log", "tmp", "cache"}
	files := []string{"auth.json", "history.jsonl", "state_5.sqlite", "state_5.sqlite-wal", "state_5.sqlite-shm"}
	if provider == "claude" {
		directories = []string{"sessions", "projects", "cache", "debug", "todos", "session-env"}
		files = []string{"history.jsonl"}
	}
	permits := []writeAllowance{}
	for _, suffix := range directories {
		permits = append(permits, writeAllowance{path: filepath.Join(home, suffix), recursive: true})
	}
	for _, suffix := range files {
		permits = append(permits, writeAllowance{path: filepath.Join(home, suffix)})
	}
	allowed, err := normalizeAllowances(permits)
	if err != nil {
		return nil, err
	}
	lanes, _ := c.Data["lanes"].(map[string]any)
	extra := []string{}
	if items, ok := lanes["sandbox_deny_extra"].([]any); ok {
		for _, item := range items {
			extra = append(extra, item.(string))
		}
	}
	if len(extra) > 0 {
		extra, err = normalizePaths(extra)
		if err != nil {
			return nil, err
		}
	}
	roots, err := normalizePaths([]string{c.Home, c.StateHome, filepath.Join(org, ".laneboss"), instances, instance})
	if err != nil {
		return nil, err
	}
	rootSet := map[string]bool{}
	for _, root := range roots {
		rootSet[root] = true
	}
	// Only this invocation's rendered vendor home can have data exceptions.
	// Other instances' vendor homes and every explicit policy file stay denied.
	rootSet[canonicalHome] = true
	result := []writeAllowance{}
	for _, permit := range allowed {
		path := permit.path
		if !strings.HasPrefix(path, filepath.Clean(home)+string(filepath.Separator)) && !strings.HasPrefix(path, canonicalHome+string(filepath.Separator)) {
			return nil, errors.New("runner-data exception resolves outside the selected vendor home")
		}
		blocked := false
		for _, deny := range extra {
			if path == deny || strings.HasPrefix(path, deny+string(filepath.Separator)) || strings.HasPrefix(deny, path+string(filepath.Separator)) {
				blocked = true
			}
		}
		if blocked {
			continue
		}
		for _, root := range roots {
			if path == root || strings.HasPrefix(root, path+string(filepath.Separator)) {
				return nil, errors.New("runner-data exception would expose a launcher-owned root")
			}
		}
		for _, policy := range protected {
			if rootSet[policy] {
				continue
			}
			if path == policy || strings.HasPrefix(policy, path+string(filepath.Separator)) || strings.HasPrefix(path, policy+string(filepath.Separator)) {
				return nil, errors.New("runner-data exception overlaps a protected policy path")
			}
		}
		result = append(result, permit)
	}
	return result, nil
}
