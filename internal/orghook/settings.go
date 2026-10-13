package orghook

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

func hookExecutable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", invalid("the Go hook executable cannot be located")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil || !regular(path) {
		return "", invalid("the Go hook executable must be a regular file")
	}
	return path, nil
}

func binaryManifest() (map[string]any, error) {
	executable, err := hookExecutable()
	if err != nil {
		return nil, err
	}
	file, err := os.Open(executable)
	if err != nil {
		return nil, invalid("the Go hook executable is unreadable")
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, invalid("the Go hook executable is unreadable")
	}
	return map[string]any{"schema_version": json.Number("1"), "executable": executable, "sha256": hex.EncodeToString(hash.Sum(nil))}, nil
}

func manifestPath(home string) string { return filepath.Join(home, "shared", "hooks", "org-hook.json") }
func settingsPath(inst *instance, runner string) string {
	if runner == "claude" {
		return filepath.Join(inst.directory, ".claude", "settings.json")
	}
	return filepath.Join(inst.directory, ".codex", "hooks.json")
}
func shellQuote(word string) string {
	if word != "" && strings.IndexFunc(word, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_@%+=:,./-", c))
	}) < 0 {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", "'\"'\"'") + "'"
}
func hookCommand(inst *instance, runner string) (string, error) {
	executable, err := hookExecutable()
	if err != nil {
		return "", err
	}
	words := []string{executable, "hook", "--runner", runner, "--instance", filepath.Join(inst.directory, "instance.toml")}
	for i, word := range words {
		words[i] = shellQuote(word)
	}
	return strings.Join(words, " "), nil
}
func settingsRow(inst *instance, runner string) (map[string]any, error) {
	command, err := hookCommand(inst, runner)
	if err != nil {
		return nil, err
	}
	return map[string]any{"matcher": "", "hooks": []any{map[string]any{"type": "command", "command": command}}}, nil
}
func runnerCommand(inst *instance, runner string) []string {
	if runner == "claude" {
		return []string{"claude", "--settings", settingsPath(inst, runner)}
	}
	return []string{"env", "CODEX_HOME=" + filepath.Join(inst.directory, ".codex"), "codex"}
}
func jsonDocument(data any) ([]byte, error) {
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, invalid("generated hook data cannot be encoded")
	}
	return append(encoded, '\n'), nil
}

type generatedFile struct {
	path string
	data []byte
}

func safeGeneratedPath(path string) error {
	if isSymlink(path) {
		return invalid("a generated hook file may not replace a symlink")
	}
	cwd, err := currentDirectory()
	if err != nil {
		return err
	}
	parent, err := pathAt(filepath.Dir(path), cwd)
	if err != nil {
		return err
	}
	if parent != filepath.Dir(path) {
		return invalid("a generated hook directory may not be a symlink")
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return invalid("a generated hook file must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return invalid("a generated hook file is unreadable")
	}
	return nil
}
func writeGenerated(path string, data []byte) error {
	if err := safeGeneratedPath(path); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm() == 0444 {
		existing, err := readBytes(path, "generated hook file")
		if err != nil {
			return err
		}
		if bytes.Equal(existing, data) {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return invalid("a generated hook directory cannot be created")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".org-hook-")
	if err != nil {
		return invalid("a generated hook file cannot be created")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return invalid("a generated hook file cannot be written")
	}
	if err := file.Chmod(0444); err != nil {
		file.Close()
		return invalid("a generated hook file cannot be made read-only")
	}
	if err := file.Close(); err != nil {
		return invalid("a generated hook file cannot be closed")
	}
	if err := os.Rename(temporary, path); err != nil {
		return invalid("a generated hook file cannot be installed")
	}
	return nil
}

func policyFiles(inst *instance) ([]string, error) {
	paths := []string{}
	for _, layer := range []string{filepath.Join(inst.home, "shared"), filepath.Join(inst.home, "L"+string(rune('0'+inst.level))), inst.directory} {
		if layer != inst.directory {
			paths = append(paths, filepath.Join(layer, "hooks", "rules.toml"))
		}
		entries, err := os.ReadDir(filepath.Join(layer, "refusals"))
		// Empty layers need no refusal directory. loadRules already requires every
		// description referenced by a rule, including inline instance rules.
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, invalid("a policy refusals directory is missing or unreadable")
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".toml") {
				paths = append(paths, filepath.Join(layer, "refusals", entry.Name()))
			}
		}
	}
	return paths, nil
}

// RenderHookSettings writes direct Go command hooks and returns the mandatory launch prefixes.
// Policy and every existing settings document are validated before any file is changed.
func RenderHookSettings(org string) (map[string]map[string][]string, error) {
	home, err := orgHome(org)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(home, "instances"))
	if err != nil {
		return nil, invalid("the instances directory is missing or unreadable")
	}
	instances := []*instance{}
	for _, entry := range entries {
		path := filepath.Join(home, "instances", entry.Name())
		if !isDirectory(path) {
			continue
		}
		inst, err := loadInstance(path)
		if err != nil {
			return nil, err
		}
		if _, err := loadRules(inst); err != nil {
			return nil, err
		}
		instances = append(instances, inst)
	}
	manifest, err := binaryManifest()
	if err != nil {
		return nil, err
	}
	manifestBytes, err := jsonDocument(manifest)
	if err != nil {
		return nil, err
	}
	files := []generatedFile{{manifestPath(home), manifestBytes}}
	result := map[string]map[string][]string{}
	protected := map[string]bool{}
	for _, inst := range instances {
		commands := map[string][]string{}
		registry := map[string]any{}
		for _, runner := range []string{"claude", "codex"} {
			path := settingsPath(inst, runner)
			document := map[string]any{}
			if _, err := os.Lstat(path); err == nil {
				data, err := readBytes(path, "hook settings")
				if err != nil {
					return nil, err
				}
				document, err = parseJSON(data, "hook settings")
				if err != nil {
					return nil, err
				}
			} else if !os.IsNotExist(err) {
				return nil, invalid("hook settings are unreadable")
			}
			hooks := map[string]any{}
			if value, exists := document["hooks"]; exists {
				var ok bool
				hooks, ok = object(value)
				if !ok {
					return nil, invalid("hook settings hooks must be an object")
				}
			}
			rows := []any{}
			if value, exists := hooks["PreToolUse"]; exists {
				var ok bool
				rows, ok = array(value)
				if !ok {
					return nil, invalid("hook settings PreToolUse must be an array")
				}
			}
			retained := []any{}
			for _, value := range rows {
				row, ok := object(value)
				if !ok {
					return nil, invalid("hook settings has a malformed registration")
				}
				registrations, ok := array(row["hooks"])
				if !ok {
					return nil, invalid("hook settings has a malformed registration")
				}
				kept := []any{}
				for _, value := range registrations {
					hook, ok := object(value)
					if !ok {
						return nil, invalid("hook settings has a malformed command hook")
					}
					own := false
					if hook["type"] == "command" {
						text, ok := hook["command"].(string)
						if !ok {
							return nil, invalid("hook settings has invalid command words")
						}
						// Unrelated command hooks may contain shell operators. Inspect their
						// words only to recognise our registration; never execute them.
						tokens, err := lexShell(text)
						if err != nil {
							return nil, invalid("hook settings has invalid command words")
						}
						words := []string{}
						for _, token := range tokens {
							if !token.operator {
								words = append(words, token.word)
							}
						}
						// Migrate legacy generated registrations as well as our own direct Go registrations.
						own = contains(words, filepath.Join(home, "shared", "hooks", "org-hook.py")) || (len(words) > 1 && words[0] == manifest["executable"] && words[1] == "hook")
					}
					if !own {
						kept = append(kept, hook)
					}
				}
				if len(kept) > 0 {
					row["hooks"] = kept
					retained = append(retained, row)
				}
			}
			generated, err := settingsRow(inst, runner)
			if err != nil {
				return nil, err
			}
			hooks["PreToolUse"] = append(retained, generated)
			document["hooks"] = hooks
			document["disableAllHooks"] = false
			if value, exists := document["allowManagedHooksOnly"]; exists && value != false {
				return nil, invalid("managed-only hook settings exclude the org hook")
			}
			data, err := jsonDocument(document)
			if err != nil {
				return nil, err
			}
			files = append(files, generatedFile{path, data})
			commands[runner] = runnerCommand(inst, runner)
			registry[runner] = map[string]any{"command": commands[runner]}
		}
		data, err := jsonDocument(registry)
		if err != nil {
			return nil, err
		}
		files = append(files, generatedFile{filepath.Join(inst.directory, "hooks", "runners.json"), data})
		result[inst.name] = commands
		paths, err := policyFiles(inst)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			protected[path] = true
		}
	}
	for _, file := range files {
		if err := safeGeneratedPath(file.path); err != nil {
			return nil, err
		}
	}
	for path := range protected {
		resolved, err := pathAt(path, home)
		if err != nil || resolved != path || isSymlink(path) || !regular(path) {
			return nil, invalid("a policy file must be a regular file and may not be a symlink")
		}
	}
	for _, file := range files {
		if err := writeGenerated(file.path, file.data); err != nil {
			return nil, err
		}
	}
	for path := range protected {
		if err := os.Chmod(path, 0444); err != nil {
			return nil, invalid("a policy file cannot be made read-only")
		}
	}
	return result, nil
}

type runnerRow struct {
	runner, field string
	value         any
}

func runnerRows(inst *instance) ([]runnerRow, error) {
	value, exists := inst.data["runners"]
	if !exists {
		data, err := readBytes(filepath.Join(inst.directory, "hooks", "runners.json"), "rendered runner registry")
		if err != nil {
			return nil, err
		}
		value, err = parseJSON(data, "rendered runner registry")
		if err != nil {
			return nil, err
		}
	}
	runners, ok := object(value)
	if !ok || len(runners) == 0 {
		return nil, invalid("the instance has no runner commands")
	}
	rows := []runnerRow{}
	for _, runner := range sortedKeys(runners) {
		row, ok := object(runners[runner])
		if !ok || !contains([]string{"claude", "codex"}, runner) {
			return nil, invalid("an instance runner needs a known name and a command")
		}
		if _, exists := row["command"]; !exists {
			return nil, invalid("an instance runner needs a known name and a command")
		}
		if !onlyKeys(row, "command", "resume") {
			return nil, invalid("an instance runner has unsupported launch fields")
		}
		for _, field := range []string{"command", "resume"} {
			if value, exists := row[field]; exists {
				rows = append(rows, runnerRow{runner, field, value})
			}
		}
	}
	return rows, nil
}

func hasHookConfig(configuration map[string]any, allowEnabled bool, parent string) bool {
	for key, value := range configuration {
		if strings.Contains(strings.ToLower(key), "hook") && !(allowEnabled && parent == "features" && key == "hooks" && value == true) {
			return true
		}
		if child, ok := object(value); ok && hasHookConfig(child, allowEnabled, key) {
			return true
		}
		if values, ok := array(value); ok {
			for _, value := range values {
				if child, ok := object(value); ok && hasHookConfig(child, allowEnabled, key) {
					return true
				}
			}
		}
	}
	return false
}

func checkRunner(inst *instance, runner string, value any, manifest map[string]any) error {
	var words []string
	var err error
	if text, ok := value.(string); ok {
		words, err = splitWords(text)
	} else {
		words, err = stringList(value, "runner command", false)
	}
	if err != nil {
		return invalid("a runner command needs literal argv")
	}
	for _, word := range words {
		if strings.ContainsAny(word, "$`") || contains([]string{";", "&&", "||", "|", "&"}, word) {
			return invalid("a runner command needs literal argv")
		}
	}
	codexHome := ""
	if len(words) > 0 && filepath.Base(words[0]) == "env" {
		if !standardExecutable(words[0]) {
			return invalid("a runner wrapper must be a standard system executable")
		}
		words = words[1:]
		for len(words) > 0 && strings.Contains(words[0], "=") && !strings.HasPrefix(words[0], "-") {
			parts := strings.SplitN(words[0], "=", 2)
			words = words[1:]
			if parts[0] != "CODEX_HOME" {
				return invalid("a runner command has an unreviewed environment override")
			}
			if codexHome != "" {
				return invalid("a runner command overrides CODEX_HOME more than once")
			}
			codexHome = parts[1]
		}
	}
	if len(words) == 0 || filepath.Base(words[0]) != runner {
		return invalid("the runner command does not directly start its declared runner")
	}
	arguments := words[1:]
	for _, word := range arguments {
		if contains([]string{"--disable-hooks", "--no-hooks", "--bare"}, strings.SplitN(word, "=", 2)[0]) {
			return invalid("the runner command disables hooks")
		}
	}
	if runner == "claude" {
		settings := []string{}
		for i, word := range arguments {
			if word == "--settings" {
				if i+1 >= len(arguments) {
					return invalid("the Claude settings argument has no path")
				}
				settings = append(settings, arguments[i+1])
			} else if strings.HasPrefix(word, "--settings=") {
				settings = append(settings, strings.TrimPrefix(word, "--settings="))
			}
		}
		if len(settings) != 1 {
			return invalid("Claude must pass exactly the instance's org hook settings")
		}
		path, err := pathAt(settings[0], inst.directory)
		if err != nil {
			return err
		}
		if path != settingsPath(inst, runner) {
			return invalid("Claude must pass exactly the instance's org hook settings")
		}
	} else {
		if codexHome == "" {
			return invalid("Codex must start with CODEX_HOME pointing to the instance's hooks config")
		}
		path, err := pathAt(codexHome, inst.directory)
		if err != nil {
			return err
		}
		if path != filepath.Join(inst.directory, ".codex") {
			return invalid("Codex must start with CODEX_HOME pointing to the instance's hooks config")
		}
		for i, word := range arguments {
			override := ""
			found := false
			if contains([]string{"-c", "--config", "--disable"}, word) {
				if i+1 >= len(arguments) {
					return invalid("a Codex config argument has no value")
				}
				override = arguments[i+1]
				found = true
			} else if strings.HasPrefix(word, "--config=") || strings.HasPrefix(word, "--disable=") {
				override = strings.SplitN(word, "=", 2)[1]
				found = true
			} else if strings.HasPrefix(word, "-c") && len(word) > 2 {
				override = strings.TrimLeft(word[2:], "=")
				found = true
			}
			if found && strings.Contains(strings.ToLower(strings.SplitN(override, "=", 2)[0]), "hook") {
				return invalid("the Codex command overrides its mandatory hooks")
			}
			if found && strings.Contains(override, "=") {
				configuration, err := parseTOML([]byte(override), "a Codex config override")
				if err != nil {
					return err
				}
				if hasHookConfig(configuration, false, "") {
					return invalid("the Codex command overrides its mandatory hooks")
				}
			}
		}
		configPath := filepath.Join(inst.directory, ".codex", "config.toml")
		if _, err := os.Lstat(configPath); err == nil {
			configuration, err := readTOML(configPath, "Codex config.toml")
			if err != nil {
				return err
			}
			if hasHookConfig(configuration, true, "") {
				return invalid("Codex config.toml changes its mandatory hooks")
			}
		} else if !os.IsNotExist(err) {
			return invalid("Codex config.toml is unreadable")
		}
	}
	data, err := readBytes(settingsPath(inst, runner), "runner hook settings")
	if err != nil {
		return err
	}
	document, err := parseJSON(data, "runner hook settings")
	if err != nil {
		return err
	}
	if value, exists := document["disableAllHooks"]; exists && value != false {
		return invalid("the runner settings disable all hooks")
	}
	if value, exists := document["allowManagedHooksOnly"]; exists && value != false {
		return invalid("managed-only hook settings exclude the org hook")
	}
	expected, err := settingsRow(inst, runner)
	if err != nil {
		return err
	}
	hooks, ok := object(document["hooks"])
	if !ok {
		return invalid("the runner settings do not register the mandatory synchronous hook for every tool")
	}
	rows, ok := array(hooks["PreToolUse"])
	found := false
	if ok {
		for _, row := range rows {
			if reflect.DeepEqual(row, expected) {
				found = true
			}
		}
	}
	if !found {
		return invalid("the runner settings do not register the mandatory synchronous hook for every tool")
	}
	data, err = readBytes(manifestPath(inst.home), "shared Go hook manifest")
	if err != nil {
		return err
	}
	actual, err := parseJSON(data, "shared Go hook manifest")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, manifest) {
		return invalid("the shared Go hook manifest differs from the installed executable")
	}
	protected, err := policyFiles(inst)
	if err != nil {
		return err
	}
	protected = append(protected, manifestPath(inst.home), settingsPath(inst, runner))
	if _, exists := inst.data["runners"]; !exists {
		protected = append(protected, filepath.Join(inst.directory, "hooks", "runners.json"))
	}
	for _, path := range protected {
		resolved, err := pathAt(path, inst.home)
		info, statErr := os.Stat(path)
		if err != nil || resolved != path || isSymlink(path) || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 {
			return invalid("the shared hook, rule data, refusals and runner settings must be read-only regular files")
		}
	}
	return nil
}

// CheckHooks checks every configured launch and resume and returns {"ok": bool, "checks": [...]}.
func CheckHooks(org string) (report map[string]any, err error) {
	defer func() {
		if recover() != nil {
			report = nil
			err = invalid("org hook inspection failed: internal inspection failure")
		}
	}()
	home, err := orgHome(org)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(home, "instances"))
	if err != nil {
		return map[string]any{"ok": false, "checks": []any{map[string]any{"ok": false, "reason": "the org has no instances directory"}}}, nil
	}
	if len(entries) == 0 {
		return map[string]any{"ok": false, "checks": []any{map[string]any{"ok": false, "reason": "the org has no instances"}}}, nil
	}
	manifest, err := binaryManifest()
	if err != nil {
		return nil, err
	}
	reports := []any{}
	allOK := true
	// os.ReadDir sorts names; reports remain deterministic and never include command text.
	for _, entry := range entries {
		path := filepath.Join(home, "instances", entry.Name())
		inst, loadErr := loadInstance(path)
		var rows []runnerRow
		if loadErr == nil {
			_, loadErr = loadRules(inst)
		}
		if loadErr == nil {
			rows, loadErr = runnerRows(inst)
		}
		if loadErr != nil {
			name := entry.Name()
			if !validName.MatchString(name) {
				name = "invalid-name"
			}
			reports = append(reports, map[string]any{"instance": name, "ok": false, "reason": loadErr.Error()})
			allOK = false
			continue
		}
		for _, row := range rows {
			record := map[string]any{"instance": inst.name, "runner": row.runner, "field": row.field, "ok": true}
			if err := checkRunner(inst, row.runner, row.value, manifest); err != nil {
				record["ok"] = false
				record["reason"] = err.Error()
				allOK = false
			}
			reports = append(reports, record)
		}
	}
	return map[string]any{"ok": allOK, "checks": reports}, nil
}

func sortedFiles(files map[string]string) []string {
	result := make([]string, 0, len(files))
	for path := range files {
		result = append(result, path)
	}
	sort.Strings(result)
	return result
}
