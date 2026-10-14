package orghook

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/hookpaths"
)

type action struct {
	tool          string
	commands      []command
	writes, reads []string
	searches      []contentSearch
}
type fileEffect struct{ word, directory string }

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
	levels, _ := array(data["levels"])
	levelMatch := false
	for _, value := range levels {
		level, _ := integer(value)
		if level == inst.level {
			levelMatch = true
		}
	}
	if !levelMatch {
		return false
	}
	names, _ := stringList(data["identities"], "applicable identities", false)
	for _, name := range names {
		if globMatch(inst.name, name) {
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
	return hookpaths.List(inst.home, executable)
}

func policyRoots(value any, inst *instance) ([]string, error) {
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
			result = append(result, paths...)
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
		if _, exists := data["env"]; exists {
			return action{}, invalid("a shell tool's environment overrides cannot be inspected")
		}
		if _, exists := data["additional_env"]; exists {
			return action{}, invalid("a shell tool's environment overrides cannot be inspected")
		}
		if value, exists := data["shell"]; exists {
			shell, ok := value.(string)
			if !ok || !contains([]string{"sh", "bash", "zsh", "/bin/sh", "/bin/bash", "/bin/zsh"}, shell) {
				return action{}, invalid("a shell tool needs a standard system shell")
			}
		}
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
		var commands []command
		if text, ok := value.(string); ok {
			if patch, matched := literalShellPatch(text); matched {
				paths, err := patchPaths(patch)
				return action{tool: tool, commands: []command{{argv: []string{"apply_patch"}, directory: dir, writes: paths}}}, err
			}
			commands, err = inspectShell(text, dir, 0)
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
		}
		return action{tool: tool, commands: commands}, err
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

func decide(event map[string]any, runner, pinned string) (bool, string, error) {
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
		return false, "", err
	}
	writes, reads, metadata := []fileEffect{}, []fileEffect{}, []fileEffect{}
	for _, word := range act.writes {
		writes = append(writes, fileEffect{word, cwd})
	}
	for _, word := range act.reads {
		reads = append(reads, fileEffect{word, cwd})
	}
	opaque := false
	for _, cmd := range act.commands {
		for _, word := range cmd.writes {
			writes = append(writes, fileEffect{word, cmd.directory})
		}
		for _, word := range cmd.reads {
			reads = append(reads, fileEffect{word, cmd.directory})
		}
		for _, word := range cmd.metadata {
			metadata = append(metadata, fileEffect{word, cmd.directory})
		}
		opaque = opaque || cmd.opaque
	}
	for _, effect := range append(append(append([]fileEffect{}, writes...), reads...), metadata...) {
		if _, err := pathAt(effect.word, effect.directory); err != nil {
			return false, "", err
		}
	}
	for _, search := range act.searches {
		if _, err := pathAt(search.path, cwd); err != nil {
			return false, "", err
		}
	}
	for _, row := range rules {
		if !applies(row, inst) {
			continue
		}
		detail := ""
		route := ruleRoute(fmt.Sprint(row.data["kind"]))
		switch row.data["kind"] {
		case "tool-allowlist":
			allowed, err := policyWords(row.data["tools"], inst, "allowed_tools")
			if err != nil {
				return false, "", err
			}
			found := false
			for _, name := range allowed {
				if globMatch(act.tool, name) {
					found = true
				}
			}
			if !found {
				detail = "the requested tool is outside this instance's allowlist"
			}
		case "command-pattern":
			patterns, _ := array(row.data["patterns"])
			for _, cmd := range act.commands {
				for _, pattern := range patterns {
					words, _ := stringList(pattern, "command pattern", false)
					matched := len(cmd.argv) >= len(words)
					if matched {
						for i, word := range words {
							if !globMatch(cmd.argv[i], word) {
								matched = false
								break
							}
						}
					}
					if matched {
						detail = "the parsed command words match a refused command pattern"
						if len(cmd.argv) > 1 && cmd.argv[0] == "git" && cmd.argv[1] == "push" {
							route = "leave the changes local for review and ask the supervising level to publish them."
						} else if len(cmd.argv) > 0 && (cmd.argv[0] == "codex" || cmd.argv[0] == "claude") {
							route = "ask the supervisor to start the instance through the checked launcher; do not launch an agent directly."
						}
						break
					}
				}
				if detail != "" {
					break
				}
			}
		case "write-scope":
			allowed, err := policyRoots(row.data["paths"], inst)
			if err != nil {
				return false, "", err
			}
			deniedValue := row.data["deny_paths"]
			if deniedValue == nil {
				deniedValue = []any{}
			}
			denied, err := policyRoots(deniedValue, inst)
			if err != nil {
				return false, "", err
			}
			for _, effect := range writes {
				path, err := pathAt(effect.word, effect.directory)
				if err != nil {
					return false, "", err
				}
				linked, err := multiplyLinked(path)
				if err != nil {
					return false, "", err
				}
				if linked {
					return false, "", invalid("a multiply linked file cannot be checked by a write-scope policy")
				}
				found := false
				for _, root := range allowed {
					if inside(path, root) {
						found = true
					}
				}
				for _, root := range denied {
					if inside(path, root) || inside(root, path) {
						found = false
						break
					}
				}
				if !found {
					detail = "the write is outside the allowed paths or touches protected hook settings"
					if strings.HasPrefix(path, "/dev/") {
						route = deviceRoute
					}
					break
				}
			}
			if opaque && detail == "" {
				detail = "the command's writes cannot be inspected"
				route = fileRoute
			}
		case "secret-read":
			names, err := policyWords(row.data["names"], inst, "secret_names")
			if err != nil {
				return false, "", err
			}
			// A test stats its literal operand; it does not read the contents of
			// every file below a directory. Still refuse protected names and aliases.
			for _, effect := range metadata {
				path, err := pathAt(effect.word, effect.directory)
				if err != nil {
					return false, "", err
				}
				matched, err := secretNameMatch(effect.word, path, names, inst)
				if err != nil {
					return false, "", err
				}
				if matched {
					detail = "the read names a protected secret file"
					break
				}
			}
			for _, effect := range reads {
				matched, err := secretRead(effect.word, effect.directory, names, inst)
				if err != nil {
					return false, "", err
				}
				if matched {
					detail = "the read names a protected secret file"
					break
				}
			}
			if detail == "" {
				for _, search := range act.searches {
					matched, err := secretSearch(search, cwd, names, inst)
					if err != nil {
						return false, "", fmt.Errorf("%w; %s", err, narrowSearchPath)
					}
					if matched {
						detail = "the search includes a protected secret file; " + narrowSearchPath
						route = searchRoute
						break
					}
				}
			}
			if opaque && detail == "" {
				detail = "the command's reads cannot be inspected"
				route = fileRoute
			}
		}
		if detail != "" {
			return false, refusalText(row.refusal, detail, route), nil
		}
	}
	if opaque {
		return false, "", invalid("the tool or command has no file-effects adapter")
	}
	return true, "org policy permits this tool call", nil
}
