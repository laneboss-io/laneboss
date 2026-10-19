package orghook

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/hookpaths"
	"laneboss.io/laneboss/internal/settings"
)

type action struct {
	tool           string
	raw            string
	rawDirectory   string
	rawDirectories []string
	rawEnvironment map[string]string
	gap            bool
	commands       []command
	writes, reads  []string
	searches       []contentSearch
}
type fileEffect struct {
	word, directory string
	managedRoot     string
	managed         bool
}

// globMatch follows fnmatch semantics: '*' also matches path separators; backslashes are literal.
func globMatch(word, pattern string) bool {
	var expression strings.Builder
	expression.WriteString("(?s)^")
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '*':
			expression.WriteString(".*")
			for i+1 < len(runes) && runes[i+1] == '*' {
				i++
			}
		case '?':
			expression.WriteByte('.')
		case '[':
			end := i + 1
			if end < len(runes) && runes[end] == '!' {
				end++
			}
			if end < len(runes) && runes[end] == ']' {
				end++
			}
			for end < len(runes) && runes[end] != ']' {
				end++
			}
			if end == len(runes) {
				expression.WriteString(`\[`)
				continue
			}
			expression.WriteString(globClass(runes[i+1 : end]))
			i = end
		default:
			expression.WriteString(regexp.QuoteMeta(string(runes[i])))
		}
	}
	expression.WriteByte('$')
	compiled, err := regexp.Compile(expression.String())
	return err == nil && compiled.MatchString(word)
}

// fnmatch removes reversed ranges while retaining the rest of a character class.
// RE2 has no lookahead; contradictory word boundaries represent an empty class.
func globClass(raw []rune) string {
	chunks := [][]rune{}
	start, search := 0, 1
	if len(raw) > 0 && raw[0] == '!' {
		search = 2
	}
	for {
		index := -1
		for j := search; j < len(raw); j++ {
			if raw[j] == '-' {
				index = j
				break
			}
		}
		if index < 0 {
			break
		}
		chunks = append(chunks, append([]rune(nil), raw[start:index]...))
		start, search = index+1, index+3
	}
	if tail := raw[start:]; len(tail) > 0 {
		chunks = append(chunks, append([]rune(nil), tail...))
	} else if len(chunks) > 0 {
		chunks[len(chunks)-1] = append(chunks[len(chunks)-1], '-')
	}
	for i := len(chunks) - 1; i > 0; i-- {
		left, right := chunks[i-1], chunks[i]
		if len(left) > 0 && len(right) > 0 && left[len(left)-1] > right[0] {
			chunks[i-1] = append(left[:len(left)-1], right[1:]...)
			chunks = append(chunks[:i], chunks[i+1:]...)
		}
	}
	negated := len(chunks) > 0 && len(chunks[0]) > 0 && chunks[0][0] == '!'
	if negated {
		chunks[0] = chunks[0][1:]
	}
	var body strings.Builder
	for i, chunk := range chunks {
		if i > 0 {
			body.WriteByte('-')
		}
		for _, c := range chunk {
			if strings.ContainsRune(`\-[]^`, c) {
				body.WriteByte('\\')
			}
			body.WriteRune(c)
		}
	}
	if body.Len() == 0 {
		if negated {
			return "."
		}
		return `\b\B`
	}
	if negated {
		return "[^" + body.String() + "]"
	}
	return "[" + body.String() + "]"
}

func applies(row rule, inst *instance) bool {
	data, _ := object(row.refusal["applies_to"])
	if data == nil {
		return true
	}
	if raw, exists := data["levels"]; exists {
		levels, ok := array(raw)
		if !ok || len(levels) == 0 {
			return false
		}
		found := false
		for _, value := range levels {
			level, _ := integer(value)
			if level == inst.level {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	var names []string
	if raw, exists := data["roles"]; exists {
		names, _ = stringList(raw, "applicable roles", false)
	} else if raw, exists := data["identities"]; exists {
		names, _ = stringList(raw, "applicable identities", false)
	}
	if len(names) == 0 {
		return true
	}
	for _, name := range names {
		if globMatch(inst.role, name) || globMatch(inst.name, name) {
			return true
		}
	}
	return false
}

func policyPaths(inst *instance) ([]string, error) {
	executable, err := hookExecutable()
	if err != nil {
		return nil, err
	}
	paths, err := hookpaths.List(inst.home, executable)
	if err != nil {
		return nil, err
	}
	// Targets and roots must use the same physical spelling, even when a
	// missing root lives below a symlinked parent. Never drop an unreadable root.
	for index, path := range paths {
		paths[index], err = pathAt(path, filepath.Dir(inst.home))
		if err != nil {
			return nil, err
		}
	}
	return paths, nil
}

func policyRoots(value any, inst *instance, managed ...bool) ([]string, error) {
	words, err := stringList(value, "write-scope paths", true)
	if err != nil {
		return nil, err
	}
	result := []string{}
	replacements := map[string]string{"org": filepath.Dir(inst.home), "laneboss": inst.home, "instance": inst.directory, "level": filepath.Join(inst.home, fmt.Sprintf("L%d", inst.level)), "worktree": inst.worktree}
	for _, word := range words {
		if word == "{writable_repos}" {
			result = append(result, inst.writableRepos...)
			continue
		}
		if word == "{hook_paths}" {
			paths, err := policyPaths(inst)
			if err != nil {
				return nil, err
			}
			state, err := hookpaths.StateDir()
			if err != nil {
				return nil, err
			}
			if state != "" {
				state, err = pathAt(state, filepath.Dir(inst.home))
				if err != nil {
					return nil, err
				}
			}
			for _, path := range paths {
				// This exception belongs only to the shared inventory expansion.
				// An owner's explicit deny of the state path still applies.
				if len(managed) == 1 && managed[0] && path == state {
					continue
				}
				result = append(result, path)
			}
			continue
		}
		for key, value := range replacements {
			word = strings.ReplaceAll(word, "{"+key+"}", value)
		}
		if strings.ContainsAny(word, "{}") {
			return nil, invalid("a write-scope path has an unknown placeholder")
		}
		path, err := pathAt(word, filepath.Dir(inst.home))
		if err != nil {
			return nil, err
		}
		result = append(result, path)
	}
	for i, path := range result {
		result[i], err = pathAt(path, filepath.Dir(inst.home))
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func policyWords(value any, inst *instance, key string) ([]string, error) {
	words, err := stringList(value, "policy words", true)
	if err != nil {
		return nil, err
	}
	result := []string{}
	for _, word := range words {
		if word == "{"+key+"}" {
			if key == "allowed_tools" {
				result = append(result, inst.allowedTools...)
			} else {
				result = append(result, inst.secretNames...)
			}
		} else if strings.ContainsAny(word, "{}") {
			return nil, invalid("a policy value has an unknown placeholder")
		} else {
			result = append(result, word)
		}
	}
	return result, nil
}

func inside(path, root string) bool {
	return path == root || strings.HasPrefix(path, strings.TrimRight(root, string(filepath.Separator))+string(filepath.Separator))
}
func multiplyLinked(path string) (bool, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, invalid("file metadata cannot be inspected")
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, invalid("file link metadata cannot be inspected")
	}
	return metadata.Nlink > 1, nil
}

func secretRead(word, directory string, names []string, inst *instance) (bool, error) {
	path, err := pathAt(word, directory)
	if err != nil {
		return false, err
	}
	matches := func(original, resolved string) (bool, error) { return secretNameMatch(original, resolved, names, inst) }
	matched, err := matches(word, path)
	if matched || err != nil {
		return matched, err
	}
	if !isDirectory(path) {
		return false, nil
	}
	seen := 0
	// Read entries in bounded batches instead of allocating an entire directory listing.
	var walk func(string) (bool, error)
	walk = func(root string) (bool, error) {
		stream, err := os.Open(root)
		if err != nil {
			return false, invalid("a directory read cannot be inspected")
		}
		defer stream.Close()
		for {
			entries, readErr := stream.ReadDir(128)
			if readErr != nil && readErr != io.EOF {
				return false, invalid("a directory read cannot be inspected")
			}
			for _, entry := range entries {
				seen++
				if seen > maxReadPaths {
					return false, invalid("a directory read exceeds the inspection limit")
				}
				child := filepath.Join(root, entry.Name())
				resolved, err := pathAt(child, directory)
				if err != nil {
					return false, err
				}
				if entry.Type()&os.ModeSymlink != 0 && isDirectory(resolved) {
					return false, invalid("a directory read contains a symlink directory")
				}
				matched, err := matches(child, resolved)
				if matched || err != nil {
					return matched, err
				}
				if entry.IsDir() {
					matched, err := walk(child)
					if matched || err != nil {
						return matched, err
					}
				}
			}
			if readErr == io.EOF {
				return false, nil
			}
		}
	}
	return walk(path)
}

func secretNameMatch(original, resolved string, names []string, inst *instance) (bool, error) {
	linked, err := multiplyLinked(resolved)
	if err != nil {
		return false, err
	}
	if linked {
		return false, invalid("a multiply linked file cannot be checked by a secret-name policy")
	}
	for _, name := range names {
		if globMatch(filepath.Base(original), name) || globMatch(filepath.Base(resolved), name) {
			return true, nil
		}
		if strings.Contains(name, "/") {
			secret, err := pathAt(name, filepath.Dir(inst.home))
			if err != nil {
				return false, err
			}
			if resolved == secret {
				return true, nil
			}
		}
	}
	return false, nil
}

func patchPaths(value any) ([]string, error) {
	text, ok := value.(string)
	if !ok || len(text) > maxBytes || !strings.HasPrefix(text, "*** Begin Patch\n") || !strings.HasSuffix(strings.TrimSpace(text), "*** End Patch") {
		return nil, invalid("apply_patch must contain a complete patch")
	}
	lines := strings.Split(strings.TrimRight(text, " \t\r\n"), "\n")
	paths := []string{}
	active := false
	for _, line := range lines[1 : len(lines)-1] {
		matched := false
		for _, operation := range []string{"Add File", "Update File", "Delete File", "Move to"} {
			prefix := "*** " + operation + ": "
			if strings.HasPrefix(line, prefix) {
				if operation == "Move to" && !active {
					return nil, invalid("apply_patch has a move without an update")
				}
				path := strings.TrimPrefix(line, prefix)
				if path == "" {
					return nil, invalid("apply_patch needs a file path")
				}
				paths = append(paths, path)
				active = true
				matched = true
				break
			}
		}
		if !matched && strings.HasPrefix(line, "*** ") && line != "*** End of File" {
			return nil, invalid("apply_patch has an unsupported file operation")
		}
		if !matched && line != "" && !active {
			return nil, invalid("apply_patch has content without a file operation")
		}
	}
	if len(paths) == 0 {
		return nil, invalid("apply_patch has no file operations")
	}
	return paths, nil
}

func shellInputText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	words, _ := array(value)
	parts := make([]string, 0, len(words))
	for _, word := range words {
		if text, ok := word.(string); ok {
			// This is a shell representation of literal argv, not a new
			// tokenization: preserve spaces and operators inside each word.
			parts = append(parts, shellQuote(text))
		}
	}
	return strings.Join(parts, " ")
}

func shellInput(data map[string]any) string {
	for _, key := range []string{"command", "cmd", "argv"} {
		if value, exists := data[key]; exists {
			return shellInputText(value)
		}
	}
	return ""
}

func eventAction(event map[string]any, runner, cwd string) (action, error) {
	if event["hook_event_name"] != "PreToolUse" {
		return action{}, invalid("the hook only accepts PreToolUse events")
	}
	tool, ok := event["tool_name"].(string)
	if !ok || tool == "" {
		return action{}, invalid("the hook event needs tool_name")
	}
	if runner == "codex" {
		tool = strings.TrimPrefix(tool, "functions.")
	}
	input := event["tool_input"]
	if text, ok := input.(string); ok && runner == "codex" {
		if tool == "apply_patch" {
			input = map[string]any{"input": text}
		} else {
			data, err := parseJSON([]byte(text), "tool_input")
			if err != nil {
				return action{}, err
			}
			input = data
		}
	}
	data, ok := object(input)
	if !ok {
		return action{}, invalid("the hook event needs an object tool_input")
	}
	if contains([]string{"Bash", "exec_command", "shell", "shell_command"}, tool) {
		fields := []string{}
		for _, key := range []string{"cmd", "command", "argv"} {
			if _, exists := data[key]; exists {
				fields = append(fields, key)
			}
		}
		if len(fields) != 1 {
			return action{}, invalid("a shell tool needs exactly one command or argv field")
		}
		directoryValue := any(cwd)
		workdir, hasWorkdir := data["workdir"]
		directory, hasCwd := data["cwd"]
		if hasWorkdir && hasCwd {
			return action{}, invalid("a shell tool has ambiguous working directories")
		}
		if hasWorkdir {
			directoryValue = workdir
		} else if hasCwd {
			directoryValue = directory
		}
		dir, err := pathAt(directoryValue, cwd)
		if err != nil {
			return action{}, err
		}
		value := data[fields[0]]
		environment := shellEnvironment(data)
		gap := func(err error) (action, error) {
			return action{tool: tool, raw: shellInput(data), rawDirectory: dir, rawDirectories: shellEnvDirectories(data, cwd), rawEnvironment: environment, gap: true}, observation(err)
		}
		// Resolve the tool's working directory before reporting any adapter gap. A
		// raw fallback must use the directory the runner actually selected, even
		// when env/additional_env or a non-standard shell prevents full parsing.
		if _, exists := data["env"]; exists {
			return gap(invalid("a shell tool's environment overrides cannot be inspected"))
		}
		if _, exists := data["additional_env"]; exists {
			return gap(invalid("a shell tool's environment overrides cannot be inspected"))
		}
		if shellValue, exists := data["shell"]; exists {
			shell, ok := shellValue.(string)
			if !ok || !contains([]string{"sh", "bash", "zsh", "/bin/sh", "/bin/bash", "/bin/zsh"}, shell) {
				return gap(invalid("a shell tool needs a standard system shell"))
			}
		}
		var commands []command
		if text, ok := value.(string); ok {
			if patch, matched := literalShellPatch(text); matched {
				paths, err := patchPaths(patch)
				return action{tool: tool, commands: []command{{argv: []string{"apply_patch"}, directory: dir, writes: paths}}}, err
			}
			if patch, tail, matched := literalShellPatchSequence(text); matched {
				paths, patchErr := patchPaths(patch)
				if patchErr != nil {
					return action{}, patchErr
				}
				commands, err = inspectShell(tail, dir, 0)
				commands = append([]command{{argv: []string{"apply_patch"}, directory: dir, writes: paths, opaque: true}}, commands...)
				return action{tool: tool, raw: text, rawDirectory: dir, rawEnvironment: environment, commands: commands, gap: err != nil}, observation(err)
			}
			commands, err = inspectShell(text, dir, 0)
			if err != nil {
				return action{tool: tool, raw: text, rawDirectory: dir, rawEnvironment: environment, commands: commands, gap: true}, observation(err)
			}
		} else {
			words, ok := array(value)
			if !ok {
				return action{}, invalid("command argv must be a nonempty array of words")
			}
			argv := make([]string, len(words))
			for i, word := range words {
				var ok bool
				argv[i], ok = word.(string)
				if !ok {
					return action{}, invalid("command argv must be a nonempty array of words")
				}
			}
			commands, err = inspectArgv(argv, dir, 0)
			if err != nil {
				return action{tool: tool, raw: shellInputText(value), rawDirectory: dir, rawEnvironment: environment, commands: commands, gap: true}, observation(err)
			}
		}
		return action{tool: tool, raw: shellInputText(value), rawDirectory: dir, rawEnvironment: environment, commands: commands}, nil
	}
	if contains([]string{"Glob", "LS"}, tool) {
		return action{tool: tool}, nil
	}
	if tool == "Grep" {
		search, err := contentSearchInput(data, cwd)
		return action{tool: tool, searches: []contentSearch{search}}, err
	}
	writeTool := contains([]string{"Write", "Edit", "MultiEdit", "NotebookEdit", "write_file", "edit_file"}, tool)
	readTool := contains([]string{"Read", "read_file"}, tool)
	if writeTool || readTool {
		fields := []string{}
		for _, key := range []string{"file_path", "notebook_path", "path"} {
			if _, exists := data[key]; exists {
				fields = append(fields, key)
			}
		}
		if len(fields) != 1 {
			return action{}, invalid("a file tool needs exactly one file path")
		}
		path, ok := data[fields[0]].(string)
		if !ok {
			return action{}, invalid("a file tool needs exactly one file path")
		}
		if writeTool {
			return action{tool: tool, writes: []string{path}}, nil
		}
		return action{tool: tool, reads: []string{path}}, nil
	}
	if tool == "apply_patch" {
		fields := []string{}
		for _, key := range []string{"input", "patch", "command"} {
			if _, exists := data[key]; exists {
				fields = append(fields, key)
			}
		}
		if len(fields) != 1 {
			return action{}, invalid("apply_patch needs exactly one patch field")
		}
		paths, err := patchPaths(data[fields[0]])
		return action{tool: tool, writes: paths}, err
	}
	if contains([]string{"WebFetch", "WebSearch", "request_user_input"}, tool) {
		return action{tool: tool}, nil
	}
	return action{tool: tool, commands: []command{{argv: []string{tool}, directory: cwd, opaque: true}}}, nil
}

func shellEnvDirectories(data map[string]any, cwd string) []string {
	directories := []string{}
	for _, key := range []string{"env", "additional_env"} {
		values, ok := object(data[key])
		if !ok {
			continue
		}
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				continue
			}
			if directory, err := pathAt(text, cwd); err == nil {
				directories = append(directories, directory)
			}
		}
	}
	return uniqueDirectories(directories...)
}

// policyContext carries the instance and the inspected action out of decide for the decision guard, which runs only
// after the org policy has allowed the call.
type policyContext struct {
	inst    *instance
	act     action
	context string
}

func uniqueDirectories(values ...string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func commandDirectories(cmd command) []string {
	if len(cmd.directories) > 0 {
		return uniqueDirectories(cmd.directories...)
	}
	return uniqueDirectories(cmd.directory)
}

// actionEffects is the single effect projection used by the hook and the
// blacklist preview. Keeping every candidate directory with its segment
// preserves conservative path decisions when shell state may have diverged.
func actionEffects(act action, cwd string) (writes, reads, metadata []fileEffect, opaque bool, err error) {
	for _, word := range act.writes {
		writes = append(writes, fileEffect{word: word, directory: cwd})
	}
	for _, word := range act.reads {
		reads = append(reads, fileEffect{word: word, directory: cwd})
	}
	for _, cmd := range act.commands {
		for _, directory := range commandDirectories(cmd) {
			for _, word := range cmd.writes {
				writes = append(writes, fileEffect{word: word, directory: directory})
			}
			for _, word := range cmd.managedWrites {
				path, pathErr := pathAt(word, directory)
				if pathErr != nil {
					return nil, nil, nil, false, pathErr
				}
				writes = append(writes, fileEffect{word: word, directory: directory, managedRoot: path, managed: true})
			}
			for _, word := range cmd.stateWrites {
				path, stateErr := pathAt(word, directory)
				if stateErr != nil || cmd.stateRoot == "" || !inside(path, cmd.stateRoot) {
					return nil, nil, nil, false, invalid("laneboss writes outside its configuration state directory")
				}
				writes = append(writes, fileEffect{word: word, directory: directory, managedRoot: cmd.stateRoot, managed: true})
			}
			for _, word := range cmd.reads {
				reads = append(reads, fileEffect{word: word, directory: directory})
			}
			for _, word := range cmd.metadata {
				metadata = append(metadata, fileEffect{word: word, directory: directory})
			}
		}
		opaque = opaque || cmd.opaque || cmd.changesState || cmd.directoryUncertain
	}
	for _, effect := range append(append(append([]fileEffect{}, writes...), reads...), metadata...) {
		if _, err = pathAt(effect.word, effect.directory); err != nil {
			if (act.gap || opaque) && faults.Get("orghook-bl-r26-opaque-refuse").Point == "" {
				continue
			}
			if faults.Get("orghook-bl-r26-opaque-refuse").Point != "" {
				_ = faults.Reach("orghook-bl-r26-opaque-refuse")
			}
			return nil, nil, nil, false, err
		}
	}
	for _, search := range act.searches {
		if _, err = pathAt(search.path, cwd); err != nil {
			return nil, nil, nil, false, err
		}
	}
	return writes, reads, metadata, opaque, nil
}

func hasLanebossInvocation(act action) bool {
	if act.raw != "" {
		// Parsed gap commands may include heredoc data mistaken for commands.
		// Read the original shell representation with its code/data boundaries.
		budget := 4 * maxCommand
		return shellCodeHasLaneboss(act.raw, 0, &budget)
	}
	for _, cmd := range act.commands {
		if len(cmd.argv) > 0 && filepath.Base(cmd.argv[0]) == "laneboss" {
			return true
		}
	}
	return false
}

func decide(event map[string]any, runner, pinned string, contexts ...*policyContext) (bool, string, error) {
	directory, err := currentDirectory()
	if err != nil {
		return false, "", err
	}
	cwdValue := any(directory)
	if value, exists := event["cwd"]; exists {
		cwdValue = value
	}
	cwd, err := pathAt(cwdValue, directory)
	if err != nil {
		return false, "", err
	}
	inst, err := findInstance(cwd, pinned)
	if err != nil {
		return false, "", err
	}
	rules, err := loadRules(inst)
	if err != nil {
		return false, "", err
	}
	act, err := eventAction(event, runner, cwd)
	if err != nil {
		if !isObservationGap(err) || hasLanebossInvocation(act) {
			return false, "", err
		}
		// Blacklist mode deliberately records an incomplete observation rather than
		// turning an adapter gap into a gate. The event still supplies its tool
		// identity, so the judge can see that this call was not inspected.
		tool, _ := event["tool_name"].(string)
		if runner == "codex" {
			tool = strings.TrimPrefix(tool, "functions.")
		}
		if len(act.commands) == 0 {
			act.commands = []command{{argv: []string{tool}, directory: cwd, opaque: true}}
		}
		for i := range act.commands {
			act.commands[i].opaque = true
		}
	}
	if act.gap {
		if faults.Get("orghook-bl-gap-swallow").Point != "" {
			_ = faults.Reach("orghook-bl-gap-swallow")
			act.commands = nil
			act.raw, act.gap = "", false
			err = nil
		} else if faults.Get("orghook-bl-stop-failed").Point != "" {
			_ = faults.Reach("orghook-bl-stop-failed")
			if len(act.commands) > 1 {
				act.commands = act.commands[:1]
			}
			act.raw, act.gap = "", false
			err = nil
		} else if faults.Get("orghook-bl-lexer-head-only").Point != "" && strings.Contains(act.raw, "$'") {
			_ = faults.Reach("orghook-bl-lexer-head-only")
			act.commands = nil
			act.raw, act.gap = "", false
			err = nil
		}
	}
	needsRaw := act.gap || err != nil
	for _, command := range act.commands {
		needsRaw = needsRaw || command.opaque || command.changesState || command.directoryUncertain
	}
	if needsRaw {
		act = projectRawWriteCommands(act, cwd)
		rawDirectory := cwd
		if act.rawDirectory != "" {
			rawDirectory = act.rawDirectory
		}
		if reason, rawErr := builtInRawWriteRefusal(inst, act.raw, rawDirectory, act.rawEnvironment, act.rawDirectories...); rawErr != nil {
			return false, "", rawErr
		} else if reason != "" {
			return false, reason, nil
		}
		if reason, readErr := ansiSecretReadRefusal(inst, act.raw, rawDirectory, rules); readErr != nil {
			return false, "", readErr
		} else if reason != "" {
			return false, reason, nil
		}
	}
	resolved, err := resolveHookCaller()
	if err != nil {
		return false, "", err
	}
	layered, err := layeredTools(inst, resolved)
	if err != nil {
		return false, "", err
	}
	for _, name := range settings.Strings(layered.Values["tool_deny_add"]) {
		if name == act.tool {
			if faults.Get("settings-tool-deny-skip").Point != "" {
				if err := faults.Reach("settings-tool-deny-skip"); err != nil {
					return false, "", err
				}
				continue
			}
			if faults.Get("settings-allow-beats-deny").Point != "" && contains(settings.Strings(layered.Values["tool_allow_add"]), name) {
				if err := faults.Reach("settings-allow-beats-deny"); err != nil {
					return false, "", err
				}
				continue
			}
			return false, "refused: resolved settings deny this tool\nInstead: report the tool request to the supervising level.", nil
		}
	}
	if len(contexts) > 0 && contexts[0] != nil {
		contexts[0].inst, contexts[0].act = inst, act
	}
	// The tagged mutant restores the old order at the real decision point.
	if faults.Get("orghook-boundary-before-policy").Point != "" {
		if err := faults.Reach("orghook-boundary-before-policy"); err != nil {
			return false, "", err
		}
		if reason, err := hookLaneBoundary(act, inst, cwd, resolved); err != nil {
			return false, "", err
		} else if reason != "" {
			return false, reason, nil
		}
	}
	writes, reads, metadata, opaque, err := actionEffects(act, cwd)
	if err != nil {
		return false, "", err
	}
	allowed, reason, err := decideBlacklist(inst, act, writes, reads, metadata, opaque, cwd, rules)
	if err != nil {
		return false, "", err
	}
	if !allowed {
		return false, reason, nil
	}
	if enriched, changed := projectArgumentFileWrites(act); changed {
		act = enriched
		writes, reads, metadata, opaque, err = actionEffects(act, cwd)
		if err != nil {
			return false, "", err
		}
		allowed, reason, err = decideBlacklist(inst, act, writes, reads, metadata, opaque, cwd, rules)
		if err != nil || !allowed {
			return allowed, reason, err
		}
		if len(contexts) > 0 && contexts[0] != nil {
			contexts[0].act = act
		}
	}
	// Matching deny entries speak first. Every surviving allow still passes
	// the recorded L3 worktree, network and process-identity boundaries.
	if boundary, err := hookLaneBoundary(act, inst, cwd, resolved); err != nil {
		return false, "", err
	} else if boundary != "" {
		return false, boundary, nil
	}
	if faults.Get("orghook-blacklist-default-strict").Point != "" && opaque {
		// Restoring the removed adapter allowlist must fail ordinary-work rows.
		_ = faults.Reach("orghook-blacklist-default-strict")
		return false, "", invalid("the tool or command has no file-effects adapter")
	}
	if len(contexts) > 0 && contexts[0] != nil && strings.Contains(reason, "] Warning:") {
		contexts[0].context = reason
	}
	return allowed, reason, nil
}

func scopeFromRefusal(refusal map[string]any) (levels []int, roles []string, identityScope bool) {
	scope, _ := object(refusal["applies_to"])
	if scope == nil {
		return nil, nil, false
	}
	if values, ok := array(scope["levels"]); ok {
		for _, value := range values {
			if level, ok := integer(value); ok {
				levels = append(levels, level)
			}
		}
	}
	value := scope["roles"]
	if value == nil {
		value = scope["identities"]
		identityScope = value != nil
	}
	if values, ok := array(value); ok {
		for _, value := range values {
			if role, ok := value.(string); ok {
				roles = append(roles, role)
			}
		}
	}
	return levels, roles, identityScope
}

func blacklistScopeApplies(row blacklistRule, inst *instance) bool {
	if len(row.levels) > 0 {
		found := false
		for _, level := range row.levels {
			if level == inst.level {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(row.roles) == 0 {
		return true
	}
	for _, role := range row.roles {
		if globMatch(inst.role, role) || row.identityScope && globMatch(inst.name, role) {
			return true
		}
	}
	return false
}

func legacyBlacklistRows(rules []rule, inst *instance) ([]blacklistRule, error) {
	rows := []blacklistRule{}
	for _, legacy := range rules {
		kind := fmt.Sprint(legacy.data["kind"])
		levels, roles, identityScope := scopeFromRefusal(legacy.refusal)
		base := blacklistRule{id: fmt.Sprint(legacy.data["id"]), description: fmt.Sprint(legacy.refusal["refuses"]),
			band: "refuse", instead: fmt.Sprint(legacy.refusal["instead"]), levels: levels, roles: roles, identityScope: identityScope}
		base.source = filepath.Join(inst.home, legacy.source)
		if legacy.source == "instance.toml hooks" {
			base.source = filepath.Join(inst.directory, "instance.toml")
		}
		base.why, _ = legacy.refusal["why"].(string)
		switch kind {
		case "command-pattern":
			patterns, _ := array(legacy.data["patterns"])
			for _, pattern := range patterns {
				words, err := stringList(pattern, "command pattern", false)
				if err != nil {
					return nil, err
				}
				row := base
				row.argv = [][]string{words}
				rows = append(rows, row)
			}
		case "secret-read":
			names, err := policyWords(legacy.data["names"], inst, "secret_names")
			if err != nil {
				return nil, err
			}
			row := base
			row.secretNames = names
			row.legacySecret = true
			rows = append(rows, row)
		case "write-scope":
			// The old allowlist is intentionally not a blacklist. Preserve only
			// its explicit deny_paths, while built-in protection covers the hook's
			// own files in every mode.
			value := legacy.data["deny_paths"]
			if value == nil {
				continue
			}
			words, err := stringList(value, "write-scope deny_paths", true)
			if err != nil {
				return nil, err
			}
			for _, word := range words {
				paths, err := policyRoots([]string{word}, inst)
				if err != nil {
					return nil, err
				}
				for _, path := range paths {
					row := base
					row.pathRoots = []string{path}
					row.hookPaths = word == "{hook_paths}"
					rows = append(rows, row)
				}
			}
		}
	}
	return rows, nil
}

func pathMatchesGlob(path, pattern string) bool {
	return globMatch(path, pattern) || globMatch(filepath.Base(path), pattern)
}

type rawSegment struct {
	words     []string
	tokens    []shellToken
	text      string
	directory string
	ansiC     bool
	following string
}

// rawEffectiveWords keeps the same useful prefix matching as inspectArgv when
// the command adapter stopped at an observation gap. Assignments and standard
// wrappers do not change the command a blacklist argv prefix describes.
func rawEffectiveWords(words []string) []string {
	words = append([]string(nil), words...)
	if faults.Get("orghook-bl-reserved-head").Point != "" {
		_ = faults.Reach("orghook-bl-reserved-head")
		return words
	}
	for len(words) > 0 {
		for len(words) > 0 && contains([]string{"{", "}", "(", ")", "!", "do", "then", "else", "elif", "if", "while", "until", "time"}, words[0]) {
			words = words[1:]
		}
		for index, word := range words {
			if word == "{" {
				words = words[index+1:]
				break
			}
		}
		for len(words) > 0 && assignment.MatchString(words[0]) {
			words = words[1:]
		}
		if len(words) == 0 {
			return words
		}
		name := filepath.Base(words[0])
		takes, wrapper := wrappers[name]
		if !wrapper {
			return words
		}
		index := 1
		for index < len(words) && strings.HasPrefix(words[index], "-") {
			option := words[index]
			index++
			if option == "--" {
				break
			}
			if contains(takes, option) && index < len(words) {
				index++
			}
		}
		if name == "timeout" && index < len(words) {
			index++
		}
		words = words[index:]
	}
	return words
}

func rawTextParts(text string) []string {
	if faults.Get("orghook-bl-lexer-head-only").Point != "" {
		_ = faults.Reach("orghook-bl-lexer-head-only")
		parts := strings.SplitN(text, ";", 2)
		return []string{parts[0]}
	}
	parts := []string{}
	start, quote := 0, byte(0)
	for index := 0; index < len(text); index++ {
		if quote != 0 {
			if text[index] == '\\' {
				index++
			} else if text[index] == quote {
				quote = 0
			}
			continue
		}
		switch text[index] {
		case '\'', '"':
			quote = text[index]
		case ';', '\n', '|', '&':
			if piece := strings.TrimSpace(text[start:index]); piece != "" {
				parts = append(parts, piece)
			}
			if index+1 < len(text) && ((text[index] == '&' && text[index+1] == '&') || (text[index] == '|' && text[index+1] == '|') || (text[index] == ';' && text[index+1] == ';')) {
				index++
			}
			start = index + 1
		}
	}
	if piece := strings.TrimSpace(text[start:]); piece != "" {
		parts = append(parts, piece)
	}
	return parts
}

// rawShellSegments retains each literal command and the directory established
// by earlier cd/pushd segments. It is deliberately more permissive than the
// full inspector: a gap still leaves enough literal argv and path context for
// deterministic blacklist rows and built-in protected-path checks.
func rawShellSegments(text, directory string) []rawSegment {
	return rawShellSegmentsTainted(text, directory, false)
}

func rawShellSegmentsTainted(text, directory string, tainted bool) []rawSegment {
	tokens, err := lexShell(text)
	if err != nil {
		segments := []rawSegment{}
		for _, part := range rawTextParts(text) {
			words := rawEffectiveWords(strings.Fields(part))
			segments = append(segments, rawSegment{words: words, text: part, directory: directory, ansiC: tainted || strings.Contains(part, "$'")})
		}
		if len(segments) == 0 {
			segments = append(segments, rawSegment{words: rawEffectiveWords(strings.Fields(text)), text: text, directory: directory, ansiC: tainted || strings.Contains(text, "$'")})
		}
		return segments
	}
	segments := []rawSegment{}
	current := []shellToken{}
	flush := func() {
		if len(current) == 0 {
			return
		}
		words := make([]string, 0, len(current))
		parts := make([]string, 0, len(current))
		for _, token := range current {
			if !token.operator {
				words = append(words, token.word)
			}
			parts = append(parts, token.word)
		}
		if len(words) == 0 {
			current = nil
			return
		}
		effective := rawEffectiveWords(words)
		segmentANSI := tainted
		for _, token := range current {
			segmentANSI = segmentANSI || token.ansiC
		}
		segment := rawSegment{words: effective, tokens: append([]shellToken(nil), current...), text: strings.Join(parts, " "), directory: directory, ansiC: segmentANSI}
		segments = append(segments, segment)
		if len(effective) > 0 && contains([]string{"cd", "pushd"}, filepath.Base(effective[0])) {
			operands := effective[1:]
			if len(operands) == 1 {
				if next, pathErr := pathAt(operands[0], directory); pathErr == nil {
					directory = next
				}
			}
		}
		current = nil
	}
	for _, token := range tokens {
		if token.operator && contains([]string{"&&", "||", ";", ";;", ";&", "|", "|&", "&", ")", "\n"}, token.word) {
			before := len(segments)
			flush()
			if len(segments) > before {
				segments[len(segments)-1].following = token.word
			}
			continue
		}
		current = append(current, token)
	}
	flush()
	return segments
}

func rawSegmentWriteIntent(segment rawSegment) bool {
	if _, writes := literalWriteCommand(rawEffectWords(segment), segment.directory); writes {
		return true
	}
	if segment.tokens == nil {
		if shellWriteIntent(segment.text) {
			return true
		}
	} else {
		for _, token := range segment.tokens {
			if token.operator && contains([]string{">", ">>", ">|", "<>", "&>", "&>>", ">&"}, strings.TrimLeft(token.word, "0123456789")) {
				return true
			}
		}
	}
	for _, word := range segment.words {
		name := filepath.Base(word)
		if _, ok := operandWriters[name]; ok {
			return true
		}
		if _, ok := copiers[name]; ok {
			return true
		}
		if contains([]string{"dd", "mkdir", "rmdir", "chmod", "chown", "chgrp"}, name) {
			return true
		}
	}
	if len(segment.words) > 0 {
		name := filepath.Base(segment.words[0])
		if name == "laneboss" {
			return true
		}
		if patchWord(name) {
			return true
		}
		for _, word := range segment.words[1:] {
			if (name == "sed" && strings.HasPrefix(word, "-") && strings.ContainsAny(word, "iI")) ||
				(name == "sort" && (word == "-o" || strings.HasPrefix(word, "--output"))) {
				return true
			}
		}
	}
	return false
}

// rawProtectedScript reports a protected candidate that appears inside an
// explicitly executed shell/eval body. It is the narrow literal fallback for
// ANSI-C or quoted bodies whose redirect operator is data in the outer lexer.
func rawProtectedScript(raw, directory, candidate string) bool {
	for _, segment := range rawShellSegments(raw, directory) {
		words := rawCommandWords(segment)
		for index, word := range words {
			name := filepath.Base(word)
			if contains([]string{"sh", "bash", "zsh", "dash", "ksh"}, name) && index+2 < len(words) &&
				contains([]string{"-c", "-lc", "-cl"}, words[index+1]) {
				body := words[index+2]
				if strings.Contains(body, candidate) && shellWriteIntent(body) {
					return true
				}
			}
		}
		effective := rawEffectiveWords(words)
		if len(effective) > 1 && filepath.Base(effective[0]) == "eval" {
			body := strings.Join(effective[1:], " ")
			if strings.Contains(body, candidate) && shellWriteIntent(body) {
				return true
			}
		}
	}
	return false
}

func rawArgvSegments(text string) [][]string {
	segments := rawShellSegments(text, "")
	if faults.Get("orghook-bl-head-only").Point != "" && len(segments) > 1 {
		_ = faults.Reach("orghook-bl-head-only")
		segments = segments[:1]
	}
	result := make([][]string, 0, len(segments))
	for _, segment := range segments {
		result = append(result, segment.words)
		if len(segment.words) > 0 && segment.words[0] == "alias" {
			for _, assignment := range segment.words[1:] {
				if index := strings.IndexByte(assignment, '='); index > 0 {
					result = append(result, rawEffectiveWords(strings.Fields(assignment[index+1:])))
				}
			}
		}
	}
	return result
}

func blacklistMatches(row blacklistRule, inst *instance, act action, writes, reads, metadata []fileEffect, searches []contentSearch, cwd string) (bool, error) {
	if row.toolGlob != "" && !globMatch(act.tool, row.toolGlob) {
		return false, nil
	}
	if len(row.argv) > 0 {
		matched := false
		commands := act.commands
		if faults.Get("orghook-bl-head-only").Point != "" && len(commands) > 1 {
			// The restoring mutant inspects only the first compound segment;
			// the segment rows must turn this regression red.
			_ = faults.Reach("orghook-bl-head-only")
			commands = commands[:1]
		}
		for _, command := range commands {
			for _, prefix := range row.argv {
				if len(command.argv) < len(prefix) {
					continue
				}
				matched = true
				for i, word := range prefix {
					if !globMatch(command.argv[i], word) {
						matched = false
						break
					}
				}
				if matched {
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched && act.raw != "" {
			for _, fields := range rawArgvSegments(act.raw) {
				for _, prefix := range row.argv {
					if len(fields) < len(prefix) {
						continue
					}
					matched = true
					for i, word := range prefix {
						if !globMatch(fields[i], word) {
							matched = false
							break
						}
					}
					if matched {
						break
					}
				}
				if matched {
					break
				}
			}
		}
		if !matched {
			return false, nil
		}
	}
	if len(row.argvWords) > 0 {
		matched := false
		commands := act.commands
		if faults.Get("orghook-bl-head-only").Point != "" && len(commands) > 1 {
			_ = faults.Reach("orghook-bl-head-only")
			commands = commands[:1]
		}
		for _, command := range commands {
			if argvWordsMatch(command.argv, row.argvWords) {
				matched = true
				break
			}
		}
		if !matched && act.raw != "" {
			for _, words := range rawArgvSegments(act.raw) {
				if argvWordsMatch(words, row.argvWords) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false, nil
		}
	}
	if len(row.pathRoots) > 0 {
		for _, effect := range writes {
			path, err := pathAt(effect.word, effect.directory)
			if err != nil {
				return false, err
			}
			if row.hookPaths && managedStateEffect(effect, path) {
				continue
			}
			linked, linkErr := multiplyLinked(path)
			if linkErr != nil {
				return false, linkErr
			}
			if linked && inside(path, filepath.Dir(inst.home)) {
				return false, invalid("a multiply linked file under the org cannot be checked by a blacklist path policy")
			}
			for _, root := range row.pathRoots {
				matched := inside(path, root) || inside(root, path)
				if faults.Get("orghook-bl-exact-root").Point != "" {
					_ = faults.Reach("orghook-bl-exact-root")
					matched = path == root
				}
				if matched {
					return true, nil
				}
			}
		}
		return false, nil
	}
	if row.legacySecret {
		if faults.Get("orghook-bl-secret-glob").Point != "" {
			_ = faults.Reach("orghook-bl-secret-glob")
			for _, effect := range append(append([]fileEffect{}, writes...), append(reads, metadata...)...) {
				path, err := pathAt(effect.word, effect.directory)
				if err == nil {
					for _, name := range row.secretNames {
						if pathMatchesGlob(path, name) {
							return true, nil
						}
					}
				}
			}
			return false, nil
		}
		for _, effect := range metadata {
			path, err := pathAt(effect.word, effect.directory)
			if err != nil {
				return false, err
			}
			matched, err := secretNameMatch(effect.word, path, row.secretNames, inst)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		for _, effect := range reads {
			matched, err := secretRead(effect.word, effect.directory, row.secretNames, inst)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		for _, search := range searches {
			matched, err := secretSearch(search, cwd, row.secretNames, inst)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		return false, nil
	}
	if row.pathGlob != "" {
		matched := false
		effects := append(append(append([]fileEffect{}, writes...), reads...), metadata...)
		for _, effect := range effects {
			path, err := pathAt(effect.word, effect.directory)
			if err == nil && pathMatchesGlob(path, row.pathGlob) {
				matched = true
				break
			}
		}
		if !matched {
			for _, search := range searches {
				path, err := pathAt(search.path, cwd)
				if err == nil && pathMatchesGlob(path, row.pathGlob) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false, nil
		}
	}
	return len(row.argv) > 0 || len(row.argvWords) > 0 || row.pathGlob != "" || row.toolGlob != "", nil
}

func blacklistText(row blacklistRule, warning bool, detail string) string {
	word := "Refuses"
	if warning {
		word = "Warning"
	}
	label := row.id
	if row.builtIn {
		label = "blacklist:" + label
	}
	text := fmt.Sprintf("[%s] %s: %s", label, word, row.description)
	if row.why != "" {
		text += "\nWhy: " + row.why
	}
	if detail != "" {
		text += "\nInspection: " + detail
	}
	return text + "\n" + routeScope + "\nInstead: " + strings.Join(strings.Fields(row.instead), " ")
}

func builtInWriteRefusal(inst *instance, writes []fileEffect) (string, error) {
	paths, err := policyPaths(inst)
	if err != nil {
		return "", err
	}
	for _, effect := range writes {
		path, err := pathAt(effect.word, effect.directory)
		if err != nil {
			return "", err
		}
		if managedStateEffect(effect, path) {
			continue
		}
		for _, protected := range paths {
			if inside(path, protected) || inside(protected, path) {
				row := blacklistRule{id: "laneboss-files", builtIn: true, description: "Writes to Laneboss's own hook settings, registry, org configuration, refusal catalog, records or state.", band: "refuse", instead: protectedWriteRoute(inst, path)}
				return blacklistText(row, false, "the path belongs to Laneboss's protected observation inputs"), nil
			}
		}
		if orgRootEntry(inst, path) {
			row := blacklistRule{id: "laneboss-files", builtIn: true, description: "Writes to Laneboss's own hook settings, registry, org configuration, refusal catalog, records or state.", band: "refuse", instead: protectedWriteRoute(inst, path)}
			return blacklistText(row, false, "the path is an entry in Laneboss's protected org namespace"), nil
		}
	}
	return "", nil
}

func orgRootEntry(inst *instance, path string) bool {
	home, err := pathAt(inst.home, filepath.Dir(inst.home))
	return err == nil && filepath.Dir(path) == home
}

func managedStateEffect(effect fileEffect, path string) bool {
	return effect.managed && effect.managedRoot != "" && path == effect.managedRoot
}
func hookLaneBoundary(act action, inst *instance, cwd string, resolved *hookCaller) (string, error) {
	writeBounded := inst.level == 3
	worktree := inst.worktree
	isLane := strings.HasPrefix(resolved.principal.ID, "lane:")
	if isLane {
		// Historical lanes have no recorded level; the protocol default is L3.
		writeBounded = resolved.principal.Level == 0 || resolved.principal.Level == 3
	}
	if isLane && writeBounded {
		var err error
		worktree, err = recordedLaneWorktree(resolved.record)
		if err != nil {
			return "", err
		}
		if faults.Get("orghook-boundary-repository-path").Point != "" {
			if err := faults.Reach("orghook-boundary-repository-path"); err != nil {
				return "", err
			}
			worktree = inst.worktree
		}
	}
	if !isLane && !writeBounded {
		return "", nil
	}
	if reason := rawLaneBoundaryRefusal(act.raw, cwd); reason != "" {
		return reason, nil
	}
	if !writeBounded {
		return laneProcessBoundary(act), nil
	}
	return laneBoundary(act, inst, cwd, worktree)
}

// configInvalid names the configuration field that failed to load, so the refusal says what to fix. The hook still
// fails closed: no tool call is allowed on a configuration it cannot load.
func configInvalid(err error) string {
	var failure *config.Error
	if errors.As(err, &failure) && failure.Field != "" {
		return "config invalid: " + failure.Field
	}
	return "config invalid: the bound configuration cannot be loaded"
}

func recordedLaneWorktree(record *caller.LaneRecord) (string, error) {
	if record == nil || !record.Open || !strings.HasPrefix(record.Principal.ID, "lane:") {
		return "", invalid("the hook has no authenticated open lane record")
	}
	worktree, ok := record.Payload["worktree"].(string)
	if !ok || !filepath.IsAbs(worktree) {
		return "", invalid("the hook's lane record has no absolute worktree")
	}
	path, err := pathAt(worktree, string(filepath.Separator))
	if err != nil {
		return "", invalid("the hook's recorded lane worktree cannot be resolved")
	}
	return path, nil
}

// boundaryGrant reads the one owner-controlled exception to the L3 worktree
// boundary. The file is under shared/hooks, which is in the protected policy
// set, so a lane cannot grant itself. The grant never covers network clients
// or detached process identities.
func boundaryGrant(inst *instance) (bool, error) {
	path := filepath.Join(inst.home, "shared", "hooks", "boundary.toml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, invalid("the boundary grant cannot be read")
	}
	data, err := readTOML(path, "boundary grant")
	if err != nil {
		return false, err
	}
	if !onlyKeys(data, "allow_worktree_writes") {
		return false, invalid("boundary grant has an unknown field")
	}
	value, ok := data["allow_worktree_writes"].(bool)
	if !ok {
		return false, invalid("boundary grant allow_worktree_writes must be true or false")
	}
	return value, nil
}

// Process and network boundaries apply to every recorded lane, at every level.
func laneProcessBoundary(act action) string {
	refusal := func(detail string) string {
		return "refused: " + detail + "\nInstead: report up with laneboss report, or use lane send for a permitted peer."
	}
	for _, cmd := range act.commands {
		if len(cmd.argv) == 0 {
			continue
		}
		name := filepath.Base(cmd.argv[0])
		if name == "setsid" || name == "nohup" {
			return refusal("lanes may not detach their process identity with setsid or nohup")
		}
		if name == "tmux" {
			for _, word := range cmd.argv[1:] {
				if word == "-S" || strings.HasPrefix(word, "-S") || word == "-L" || strings.HasPrefix(word, "-L") {
					return refusal("lanes may not access a lane tmux socket directly")
				}
			}
		}
		// All direct HTTP clients lack a file-effects adapter today. Refuse
		// them here with the message route, including dashboard-port requests
		// and attempts to use Discord outside the report command.
		if contains([]string{"curl", "wget", "http", "https", "httpie", "nc", "netcat"}, name) {
			return refusal("lanes may not request dashboard ports or send outbound messages with a raw network client")
		}
	}
	return ""
}

// Only L3 and historical unlevelled lanes have the worktree write boundary.
// Instance-only callers retain their existing L3 policy scope.
func laneBoundary(act action, inst *instance, cwd, worktree string) (string, error) {
	if reason := laneProcessBoundary(act); reason != "" {
		return reason, nil
	}
	refusal := func(detail string) string {
		return "refused: " + detail + "\nInstead: report up with laneboss report, or use lane send for a permitted peer."
	}
	writes := []fileEffect{}
	for _, word := range act.writes {
		writes = append(writes, fileEffect{word: word, directory: cwd})
	}
	for _, cmd := range act.commands {
		for _, directory := range commandDirectories(cmd) {
			for _, word := range cmd.writes {
				writes = append(writes, fileEffect{word: word, directory: directory})
			}
		}
	}
	grant, err := boundaryGrant(inst)
	if err != nil {
		return "", err
	}
	// A missing or temporarily unreadable inventory must not remove the
	// worktree check. The caller runs builtInWriteRefusal before this boundary,
	// so protected-path checks still fail closed at the policy decision point.
	protected, _ := policyPaths(inst)
	for _, effect := range writes {
		path, err := pathAt(effect.word, effect.directory)
		if err != nil {
			// R26 leaves unresolved ordinary targets incomplete. The raw
			// protected-path backstop runs separately for the known policy roots.
			if strings.ContainsAny(effect.word, "$`*?[]{}~") {
				continue
			}
			return "", err
		}
		protectedWrite := false
		for _, root := range protected {
			if inside(path, root) || inside(root, path) {
				protectedWrite = true
				break
			}
		}
		if protectedWrite {
			// Let the Laneboss protected-path refusal retain its more specific
			// reason below the boundary check.
			continue
		}
		if inside(path, filepath.Join(inst.home, "shared")) {
			return refusal("lanes may write only inside their recorded worktree; shared message files require the checked message path"), nil
		}
		if !inside(path, worktree) && !grant {
			return refusal("lanes may write only inside their recorded worktree; shared message files require the checked message path"), nil
		}
	}
	return "", nil
}

func rawLaneBoundaryRefusal(raw, cwd string) string {
	if raw == "" {
		return ""
	}
	refusal := func(detail string) string {
		return "refused: " + detail + "\nInstead: report up with laneboss report, or use lane send for a permitted peer."
	}
	for _, segment := range rawShellSegments(raw, cwd) {
		words := rawCommandWords(segment)
		words = rawBoundaryWords(words)
		if len(words) == 0 {
			continue
		}
		if laneIdentityAssignment(words[0]) {
			return refusal("lanes may not override their authenticated Laneboss identity")
		}
		name := filepath.Base(words[0])
		if name == "setsid" || name == "nohup" {
			return refusal("lanes may not detach their process identity with setsid or nohup")
		}
		if name == "tmux" {
			for _, word := range words[1:] {
				if word == "-S" || strings.HasPrefix(word, "-S") || word == "-L" || strings.HasPrefix(word, "-L") {
					return refusal("lanes may not access a lane tmux socket directly")
				}
			}
		}
		if contains([]string{"curl", "wget", "http", "https", "httpie", "nc", "netcat"}, name) {
			return refusal("lanes may not request dashboard ports or send outbound messages with a raw network client")
		}
	}
	return ""
}

func rawBoundaryWords(words []string) []string {
	words = append([]string(nil), words...)
	for len(words) > 0 {
		if laneIdentityAssignment(words[0]) {
			return words
		}
		for len(words) > 0 && assignment.MatchString(words[0]) {
			words = words[1:]
		}
		if len(words) == 0 {
			return nil
		}
		name := filepath.Base(words[0])
		if name == "setsid" || name == "nohup" {
			return words
		}
		takes, wrapper := wrappers[name]
		if !wrapper {
			return words
		}
		index := 1
		for index < len(words) && strings.HasPrefix(words[index], "-") {
			option := words[index]
			index++
			if option == "--" {
				break
			}
			if contains(takes, option) && index < len(words) {
				index++
			}
		}
		if name == "timeout" && index < len(words) {
			index++
		}
		if index >= len(words) {
			return nil
		}
		words = words[index:]
	}
	return nil
}
func builtInRawWriteRefusal(inst *instance, raw, cwd string, environment map[string]string, extraDirectories ...string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if faults.Get("orghook-bl-r26-opaque-refuse").Point != "" && strings.ContainsAny(raw, "$`") {
		_ = faults.Reach("orghook-bl-r26-opaque-refuse")
		return "", invalid("the raw command contains an opaque expansion")
	}
	if faults.Get("orghook-bl-cd-unconditional").Point != "" && strings.Contains(raw, "cd ") {
		_ = faults.Reach("orghook-bl-cd-unconditional")
		return "", nil
	}
	paths, err := policyPaths(inst)
	if err != nil {
		return "", err
	}
	orgParent := filepath.Dir(inst.home)
	baseSegments := rawShellSegments(raw, cwd)
	segments := append([]rawSegment{}, baseSegments...)
	frontier := append([]rawSegment{}, baseSegments...)
	for depth := 0; depth < 4 && len(frontier) > 0; depth++ {
		aliasInput := append(append([]rawSegment{}, baseSegments...), frontier...)
		nested := rawNestedShellSegments(frontier)
		aliases := rawAliasSegments(aliasInput)
		before := len(segments)
		segments = appendUniqueRawSegments(segments, nested, aliases)
		if len(segments) == before {
			break
		}
		frontier = append([]rawSegment{}, segments[before:]...)
	}
	depthExceeded := len(frontier) > 0 && len(rawNestedShellSegments(frontier)) > 0
	rawDirectories := append([]string{cwd}, extraDirectories...)
	relativeCDTargets := []string{}
	for _, segment := range segments {
		rawDirectories = append(rawDirectories, segment.directory)
		if len(segment.words) >= 2 && contains([]string{"cd", "pushd"}, filepath.Base(segment.words[0])) && !filepath.IsAbs(segment.words[1]) && !strings.ContainsAny(segment.words[1], "$`*?[]{}") {
			relativeCDTargets = append(relativeCDTargets, segment.words[1])
		}
	}
	fields := strings.Fields(raw)
	for index, word := range fields {
		if word == "-C" || word == "--chdir" {
			if index+1 < len(fields) {
				if candidate, pathErr := pathAt(fields[index+1], cwd); pathErr == nil {
					rawDirectories = append(rawDirectories, candidate)
				}
			}
		} else if strings.HasPrefix(word, "--chdir=") {
			if candidate, pathErr := pathAt(strings.TrimPrefix(word, "--chdir="), cwd); pathErr == nil {
				rawDirectories = append(rawDirectories, candidate)
			}
		}
	}
	for _, part := range rawTextParts(raw) {
		for _, word := range strings.Fields(part) {
			if !assignment.MatchString(word) {
				continue
			}
			if candidate, pathErr := pathAt(strings.SplitN(word, "=", 2)[1], cwd); pathErr == nil {
				rawDirectories = append(rawDirectories, candidate)
			}
		}
	}
	rawWrite := shellWriteIntent(raw)
	for _, segment := range segments {
		rawWrite = rawWrite || rawSegmentWriteIntent(segment)
	}
	assignments := map[string]string{}
	targets := []rawTarget{}
	for _, segment := range segments {
		segmentAssignments := copyTargetAssignments(assignments)
		recordTargetAssignments(segment, segmentAssignments)
		if !rawSegmentWriteIntent(segment) {
			assignments = segmentAssignments
			continue
		}
		for _, target := range rawWriteTargets(segment) {
			targets = append(targets, rawTarget{word: target, directory: segment.directory, assignments: segmentAssignments})
		}
		assignments = segmentAssignments
	}
	refusal := func(detail, target string) (string, error) {
		row := blacklistRule{id: "laneboss-files", builtIn: true, description: "Writes to Laneboss's own hook settings, registry, org configuration, refusal catalog, records or state.", band: "refuse", instead: protectedWriteRoute(inst, target)}
		return blacklistText(row, false, detail), nil
	}
	for _, protected := range paths {
		// This gate is a no-op while hookpaths.List excludes the whole home and
		// instances container; exact resolved protected files remain checked below.
		heuristic := filepath.Clean(protected) != filepath.Clean(inst.home) &&
			filepath.Clean(protected) != filepath.Clean(filepath.Join(inst.home, "instances"))
		relative, relErr := filepath.Rel(orgParent, protected)
		if relErr != nil {
			relative = ""
		}
		relative = filepath.ToSlash(relative)
		orgRelative, _ := filepath.Rel(filepath.Dir(inst.home), protected)
		lanebossRelative, _ := filepath.Rel(inst.home, protected)
		candidates := []string{protected, filepath.ToSlash(protected), filepath.ToSlash(relative), "./" + filepath.ToSlash(relative), "~/" + relative, "$HOME/" + relative, "${HOME}/" + relative}
		if orgRelative != "" {
			candidates = append(candidates, filepath.ToSlash(orgRelative))
		}
		if lanebossRelative != "" && lanebossRelative != ".." {
			candidates = append(candidates, ".laneboss/"+filepath.ToSlash(lanebossRelative))
		}
		candidateDirectories := append([]string{}, rawDirectories...)
		for _, target := range relativeCDTargets {
			candidateDirectories = append(candidateDirectories, filepath.Join(protected, target))
		}
		if depthExceeded {
			for _, candidate := range candidates {
				if candidate != "" && strings.Contains(raw, candidate) {
					return refusal("the raw command nests shells beyond the inspection depth while naming a protected Laneboss path", protected)
				}
			}
		}
		if heuristic && faults.Get("orghook-bl-raw-narrow").Point == "" {
			for _, candidate := range candidates {
				if candidate != "" && strings.Contains(raw, candidate) &&
					(rawWrite || rawProtectedScript(raw, cwd, candidate)) {
					return refusal("the raw command names a protected Laneboss path while its file effects are incomplete", rawProtectedRouteTarget(protected, targets))
				}
			}
		}
		for _, segment := range segments {
			if !rawSegmentWriteIntent(segment) {
				continue
			}
			if segment.directory != "" && inside(segment.directory, protected) {
				return refusal("the raw command changes into a protected Laneboss directory before writing while its file effects are incomplete", segment.directory)
			}
			joined := strings.Join(segment.words, " ")
			if heuristic {
				for _, candidate := range candidates {
					if candidate != "" && strings.Contains(joined, candidate) {
						return refusal("the raw command names a protected Laneboss path while its file effects are incomplete", rawProtectedRouteTarget(protected, targets))
					}
				}
			}
			base := filepath.Base(protected)
			if heuristic && base != ".laneboss" && strings.Contains(raw, base) {
				for _, candidateDirectory := range uniqueDirectories(candidateDirectories...) {
					if resolved, resolveErr := pathAt(base, candidateDirectory); resolveErr == nil && (inside(resolved, protected) || inside(protected, resolved)) {
						return refusal("the raw command names a protected Laneboss path while its file effects are incomplete", rawProtectedRouteTarget(protected, targets))
					}
				}
			}
		}
	}
	for _, target := range targets {
		if faults.Get("orghook-bl-raw-narrow").Point != "" {
			_ = faults.Reach("orghook-bl-raw-narrow")
			continue
		}
		resolution := resolveWriteTarget(target.word, targetLookup(target.assignments, environment))
		if faults.Get("orghook-bl-suffix-limb").Point != "" && strings.ContainsAny(target.word, "$`~") {
			_ = faults.Reach("orghook-bl-suffix-limb")
			continue
		}
		if !resolution.unresolved {
			if resolved, pathErr := pathAt(resolution.word, target.directory); pathErr == nil {
				for _, protected := range paths {
					if inside(resolved, protected) || inside(protected, resolved) {
						return refusal("the raw command targets a protected Laneboss path while its file effects are incomplete", resolved)
					}
				}
				if orgRootEntry(inst, resolved) {
					return refusal("the raw command targets Laneboss's protected org namespace", resolved)
				}
			} else {
				for _, protected := range paths {
					if rawTargetMatchesProtected(resolution.word, target.directory, protected) {
						return refusal("the raw command targets a protected path through an unresolved shell path pattern", resolution.word)
					}
				}
			}
			continue
		}
		for _, protected := range paths {
			if protectedRedirectSuffix(resolution.tail, protected, inst.home, orgParent) {
				return refusal("the raw command names a protected Laneboss path through an unresolved expansion", resolution.tail)
			}
		}
	}
	return "", nil
}

func decideBlacklist(inst *instance, act action, writes, reads, metadata []fileEffect, opaque bool, cwd string, rules []rule) (bool, string, error) {
	if reason, err := builtInWriteRefusal(inst, writes); err != nil {
		return false, "", err
	} else if reason != "" {
		return false, reason, nil
	}
	legacy, err := legacyBlacklistRows(rules, inst)
	if err != nil {
		return false, "", err
	}
	rows := append(legacy, inst.blacklist...)
	effects := append(append([]fileEffect{}, writes...), reads...)
	effects = append(effects, metadata...)
	for _, search := range act.searches {
		effects = append(effects, fileEffect{word: search.path, directory: cwd})
	}
	matchingRefuse, matchingWarn := []blacklistRule{}, []blacklistRule{}
	for _, row := range rows {
		if !blacklistScopeApplies(row, inst) || !blacklistHasDeterministic(row) {
			continue
		}
		if (row.decision != "" || row.job != "") && faults.Get("orghook-bl-skip-ref").Point != "" {
			_ = faults.Reach("orghook-bl-skip-ref")
			continue
		}
		matched, err := blacklistMatches(row, inst, act, writes, reads, metadata, act.searches, cwd)
		if err != nil {
			return false, "", err
		}
		if !matched {
			continue
		}
		if row.band == "warn" {
			matchingWarn = append(matchingWarn, row)
			continue
		}
		matchingRefuse = append(matchingRefuse, row)
	}
	if len(matchingRefuse) > 0 {
		if faults.Get("orghook-bl-warn-first").Point != "" && len(matchingWarn) > 0 {
			_ = faults.Reach("orghook-bl-warn-first")
			return true, blacklistText(matchingWarn[0], true, "the deterministic blacklist pattern matched"), nil
		}
		return false, blacklistText(matchingRefuse[0], false, "the deterministic blacklist pattern matched"), nil
	}
	if len(matchingWarn) > 0 {
		return true, blacklistText(matchingWarn[0], true, "the deterministic blacklist pattern matched"), nil
	}
	// An opaque command is allowed in blacklist mode. The receipt records its
	// incomplete inspection; the caller's permission decision stays a clean
	// allow so routine coding commands carry no warning.
	_ = opaque
	return true, "org policy permits this tool call", nil
}
