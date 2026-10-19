package orgtree

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/jobcatalog"
	"laneboss.io/laneboss/internal/orghook"
	"laneboss.io/laneboss/internal/rolepolicy"
)

var roles = map[int]string{3: "executor", 4: "supervisor", 5: "top-supervisor", 6: "supervisor"}
var exampleNames = map[int]string{3: "L3-lane-example", 4: "L4-stream", 5: "L5-top", 6: "L6-super-top"}

const sharedRules = `# Shared org rules

- Start from a written brief with an outcome and a way to verify it.
- Keep secret values in the configured external store; config files hold names only.
- Record decisions and keep the evidence that supports each result.
- Report the refusal verbatim; if it names an Instead route, take exactly that route; otherwise stop.
- Keep working repositories and lane worktrees inside the org folder.
`

var levelRules = map[int]string{
	3: `# L3: executor

- Carry out one lane's brief in its assigned worktree.
- Verify the requested behavior and report evidence and remaining limits.
- Send decisions outside the brief's scope to the supervising stream.
`,
	4: `# L4: stream supervisor

- Break a stream's outcome into reviewable lane briefs.
- Check each executor's evidence before accepting its result.
- Keep the stream's board current and report decisions to the top supervisor.
`,
	5: `# L5: top supervisor

- Coordinate streams around the org's topic and current priorities.
- Resolve reversible choices and record decisions in the instance state.
- Send decisions reserved for the owner through the named owner channel.
`,
	6: `# L6: org supervisor

- Keep the org's goals, shared rules and supervision boundaries explicit.
- Give top supervisors clear outcomes and review their evidence.
- Record changes to org-wide policy and communicate them to the affected levels.
`,
}

func parseLevels(argument string) ([]int, error) {
	bad := errors.New("--levels must be a level, ascending range or comma list within 3-6")
	if argument == "" {
		return nil, bad
	}
	selected := map[int]bool{}
	for _, part := range strings.Split(argument, ",") {
		if len(part) != 1 && len(part) != 3 || part[0] < '3' || part[0] > '6' {
			return nil, bad
		}
		first, last := int(part[0]-'0'), int(part[0]-'0')
		if len(part) == 3 {
			if part[1] != '-' || part[2] < '3' || part[2] > '6' {
				return nil, bad
			}
			last = int(part[2] - '0')
		}
		if first > last {
			return nil, errors.New("--levels ranges must be ascending within 3-6")
		}
		for level := first; level <= last; level++ {
			selected[level] = true
		}
	}
	var result []int
	for level := 3; level <= 6; level++ {
		if selected[level] {
			result = append(result, level)
		}
	}
	return result, nil
}

func (t *tree) inline(source string, depth int) (string, error) {
	if !t.withinBudget() {
		return "", problemsError(t.problems)
	}
	if depth >= 64 {
		return "", errors.New("protocol import nesting exceeds 64 files")
	}
	if text, exists := t.expanded[source]; exists {
		return text, nil
	}
	text := t.files[source]
	var result strings.Builder
	cursor := 0
	for _, ref := range t.imports[source] {
		result.WriteString(text[cursor:ref.start])
		imported, err := t.inline(ref.target, depth+1)
		if err != nil {
			return "", err
		}
		result.WriteString(strings.TrimRight(imported, "\n"))
		if result.Len() > maxFileBytes {
			return "", errors.New("expanded protocol source exceeds the 2 MiB limit")
		}
		cursor = ref.end
	}
	result.WriteString(text[cursor:])
	if result.Len() > maxFileBytes {
		return "", errors.New("expanded protocol source exceeds the 2 MiB limit")
	}
	t.expanded[source] = result.String()
	return result.String(), nil
}

func claude(target string, sources []string) (string, error) {
	var lines []string
	for _, source := range sources {
		relative, err := filepath.Rel(filepath.FromSlash(path.Dir(target)), filepath.FromSlash(source))
		if err != nil {
			return "", errors.New("cannot resolve generated rule imports")
		}
		relative = filepath.ToSlash(relative)
		if strings.IndexFunc(relative, unicode.IsSpace) >= 0 {
			encoded, err := jsonText(relative, false)
			if err != nil {
				return "", errors.New("cannot encode generated rule imports")
			}
			relative = strings.TrimSuffix(encoded, "\n")
		}
		lines = append(lines, "@"+relative)
	}
	return header + strings.Join(lines, "\n") + "\n", nil
}

func (t *tree) agents(sources []string) (string, error) {
	parts := []string{strings.TrimSpace(header)}
	size := len(parts[0])
	for _, source := range sources {
		text, err := t.inline(source, 0)
		if err != nil {
			return "", err
		}
		part := "<!-- Source: " + label(source) + " -->\n\n" + strings.TrimRight(text, "\n")
		size += len(part) + 2
		if size+1 > maxFileBytes {
			return "", errors.New("generated rules exceed the 2 MiB limit; shorten the protocol sources")
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "\n\n") + "\n", nil
}

func (t *tree) renderPlan() (map[string]string, error) {
	shared := t.sources(home + "/shared/protocol")
	plan := map[string]string{}
	if jobcatalog.Available() {
		files := map[string]string{}
		for path, text := range t.files {
			files[strings.TrimPrefix(path, home+"/")] = text
		}
		catalog, err := jobcatalog.Build([]byte(t.files[home+"/org.toml"]), files)
		if err != nil {
			return nil, err
		}
		text, err := jsonText(catalog, true)
		if err != nil {
			return nil, err
		}
		plan[home+"/"+jobcatalog.RelativePath] = text
	}
	add := func(directory string, claudeSources, agentsSources []string) error {
		claudePath := path.Join(directory, "CLAUDE.md")
		agentsPath := path.Join(directory, "AGENTS.md")
		text, err := claude(claudePath, claudeSources)
		if err != nil {
			return err
		}
		plan[claudePath] = text
		text, err = t.agents(agentsSources)
		if err != nil {
			return err
		}
		plan[agentsPath] = text
		return nil
	}
	if err := add("", shared, shared); err != nil {
		return nil, err
	}
	levelSources := map[int][]string{}
	for _, level := range t.levels {
		directory := fmt.Sprintf("%s/L%d", home, level)
		sources := append(append([]string{}, shared...), t.sources(directory+"/protocol")...)
		levelSources[level] = sources
		if err := add(directory, sources, sources); err != nil {
			return nil, err
		}
	}
	for _, name := range sortedKeys(t.instances) {
		data := t.instances[name]
		level, _ := integer(data["level"])
		directory := home + "/instances/" + name
		notes := directory + "/state/notes.md"
		claudeSources := []string{fmt.Sprintf("%s/L%d/CLAUDE.md", home, level), notes}
		agentsSources := append(append([]string{}, levelSources[level]...), notes)
		role, _ := data["role"].(string)
		if err := rolepolicy.CheckName(role); err != nil {
			return nil, err
		}
		roleDirectory := fmt.Sprintf("%s/L%d/roles", home, level)
		rolePath := roleDirectory + "/" + role + ".md"
		_, ownMarkdown := t.files[rolePath]
		_, ownDrivers := t.files[roleDirectory+"/"+role+".toml"]
		var builtin *rolepolicy.Template
		if ownMarkdown || ownDrivers {
			if !ownMarkdown || !ownDrivers {
				return nil, errors.New("instance role needs paired Markdown and TOML org sources")
			}
			if err := rolepolicy.CheckSourcePair([]byte(t.files[rolePath]), []byte(t.files[roleDirectory+"/"+role+".toml"]), t.filename(roleDirectory+"/"+role+".toml")); err != nil {
				return nil, fmt.Errorf("instance role sources: %w", err)
			}
			claudeSources = []string{fmt.Sprintf("%s/L%d/CLAUDE.md", home, level), rolePath, notes}
			agentsSources = append(append(append([]string{}, levelSources[level]...), rolePath), notes)
		} else {
			var err error
			builtin, err = rolepolicy.Builtin(level, role)
			if err != nil {
				return nil, err
			}
			if builtin == nil {
				return nil, errors.New("instance role has no template at its level in the org or built-in library; add its Markdown and TOML role sources before rendering")
			}
		}
		if err := add(directory, claudeSources, agentsSources); err != nil {
			return nil, err
		}
		if builtin != nil {
			// Embedded sources have no on-disk import target. Keep the existing
			// level/notes imports and include the real role bytes in both drivers.
			section := "\n<!-- Source: " + builtin.Path + " -->\n\n" + string(builtin.Bytes) + "\n"
			plan[directory+"/CLAUDE.md"] += section
			plan[directory+"/AGENTS.md"] += section
		}
	}
	for _, relative := range sortedKeys(plan) {
		text := plan[relative]
		if len(text) > maxFileBytes {
			return nil, errors.New("generated rules exceed the 2 MiB limit; shorten the protocol sources")
		}
		t.scan(relative, text)
	}
	if err := problemsError(t.problems); err != nil {
		return nil, err
	}
	return plan, nil
}

func manifestText(plan map[string]string) (string, error) {
	recorded := map[string]string{}
	for relative, text := range plan {
		recorded[relative] = digest(text)
	}
	text, err := jsonText(map[string]any{"schema_version": 1, "files": recorded}, true)
	if err != nil {
		return "", errors.New("cannot encode the render manifest")
	}
	if len(text) > maxFileBytes {
		return "", errors.New("render manifest exceeds the 2 MiB limit")
	}
	return text, nil
}

type writeResult struct {
	OK      bool `json:"ok"`
	Changed int  `json:"changed"`
}

func (t *tree) write(relative, text string, create bool) (bool, error) {
	if !t.withinBudget() {
		return false, problemsError(t.problems)
	}
	if !t.parentsSafe(relative) {
		return false, problemsError(t.problems)
	}
	target := t.filename(relative)
	info, err := os.Lstat(target)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	exists := err == nil
	if exists && !info.Mode().IsRegular() {
		return false, errors.New("managed output must be a regular file, not a symbolic link or device")
	}
	if exists {
		stream, err := os.OpenFile(target, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return false, err
		}
		opened, openErr := stream.Stat()
		if openErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			stream.Close()
			return false, errors.New("managed output changed while opening")
		}
		current, readErr := io.ReadAll(io.LimitReader(stream, maxFileBytes+1))
		closeErr := stream.Close()
		if readErr != nil {
			return false, readErr
		}
		if closeErr != nil {
			return false, closeErr
		}
		if string(current) == text {
			return false, nil
		}
	}
	stream, err := os.CreateTemp(filepath.Dir(target), ".laneboss-render-")
	if err != nil {
		return false, err
	}
	temporary := stream.Name()
	defer os.Remove(temporary)
	_, writeErr := io.WriteString(stream, text)
	closeErr := stream.Close()
	if writeErr != nil {
		return false, writeErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	mode := os.FileMode(0644)
	if exists {
		mode = info.Mode().Perm()
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return false, err
	}
	if !t.withinBudget() {
		return false, problemsError(t.problems)
	}
	if create {
		if err := os.Link(temporary, target); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := os.Rename(temporary, target); err != nil {
		return false, err
	}
	return true, nil
}

func (t *tree) apply(files map[string]string, directories []string, newFiles map[string]bool) (writeResult, error) {
	failed := errors.New("org files could not be written; inspect the tree before retrying")
	// Preflight every destination before creating a directory or changing output.
	for _, relative := range append(append([]string{}, directories...), sortedKeys(files)...) {
		if !t.withinBudget() {
			return writeResult{}, problemsError(t.problems)
		}
		if !t.parentsSafe(relative) {
			return writeResult{}, problemsError(t.problems)
		}
		info, err := os.Lstat(t.filename(relative))
		if err != nil && !os.IsNotExist(err) {
			return writeResult{}, failed
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return writeResult{}, errors.New("managed output must not be a symbolic link")
		}
	}
	if err := os.MkdirAll(t.root, 0755); err != nil {
		return writeResult{}, failed
	}
	for _, relative := range directories {
		if !t.withinBudget() {
			return writeResult{}, problemsError(t.problems)
		}
		if err := os.MkdirAll(t.filename(relative), 0755); err != nil {
			return writeResult{}, failed
		}
	}
	result := writeResult{OK: true}
	order := sortedKeys(files)
	// Publish the new ownership record only after its generated files.
	for _, relative := range order {
		if relative == manifest {
			continue
		}
		changed, err := t.write(relative, files[relative], newFiles[relative])
		if err != nil {
			if problems := problemsError(t.problems); problems != nil {
				return writeResult{}, problems
			}
			return writeResult{}, failed
		}
		if changed {
			result.Changed++
		}
	}
	if text, exists := files[manifest]; exists {
		changed, err := t.write(manifest, text, newFiles[manifest])
		if err != nil {
			if problems := problemsError(t.problems); problems != nil {
				return writeResult{}, problems
			}
			return writeResult{}, failed
		}
		if changed {
			result.Changed++
		}
	}
	return result, nil
}

func instanceData(configuration map[string]any, name string, level int, role string, channel *string, secrets []string) (map[string]any, error) {
	defaults, _ := configuration["defaults"].(map[string]any)
	data := map[string]any{"schema_version": 1, "name": name, "level": level, "role": role}
	if level != 5 && level != 6 {
		if channel != nil {
			return nil, errors.New("only L5 and L6 instances talk to the owner; an L3 or L4 instance gets no Discord channel")
		}
	} else if channel != nil {
		data["discord_channel_id"] = *channel
	} else if value, exists := defaults["discord_channel_id"]; exists {
		data["discord_channel_id"] = value
	}
	for _, field := range []string{"services", "secrets", "writable_repos", "allowed_tools"} {
		if _, exists := defaults[field]; field == "allowed_tools" && !exists {
			continue
		}
		items, _ := array(defaults[field])
		data[field] = append([]any{}, items...)
	}
	for _, name := range secrets {
		data["secrets"] = append(data["secrets"].([]any), name)
	}
	return data, nil
}

func instanceFiles(data map[string]any) (map[string]string, []string, error) {
	directory := home + "/instances/" + data["name"].(string)
	text, err := encodeTOML(data, instanceOrder)
	if err != nil {
		return nil, nil, err
	}
	files := map[string]string{
		directory + "/instance.toml":      text,
		directory + "/state/notes.md":     "# Instance notes\n\nRecord this instance's current context here.\n",
		directory + "/state/ledger.jsonl": "",
		directory + "/state/board.md":     "# Board\n\nRecord queued, active and completed work here.\n",
	}
	return files, []string{directory + "/state", directory + "/state/inbox", directory + "/state/outbox"}, nil
}

func initOrg(argument, levelsArgument string, selectedName *string) (writeResult, error) {
	root, err := rootPath(argument)
	if err != nil {
		return writeResult{}, err
	}
	t := newTree(root)
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		return writeResult{}, errors.New("the org folder must be a directory")
	} else if err != nil && !os.IsNotExist(err) {
		return writeResult{}, errors.New("cannot inspect the org folder before initializing")
	}
	if info, err := os.Lstat(t.filename(home)); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return writeResult{}, errors.New("org init refuses an existing non-empty .laneboss or a symbolic link")
		}
		entries, err := os.ReadDir(t.filename(home))
		if err != nil {
			return writeResult{}, errors.New("cannot inspect the org folder before initializing")
		}
		if len(entries) > 0 {
			return writeResult{}, errors.New("org init refuses an existing non-empty .laneboss or a symbolic link")
		}
	} else if !os.IsNotExist(err) {
		return writeResult{}, errors.New("cannot inspect the org folder before initializing")
	}
	for _, filename := range []string{"CLAUDE.md", "AGENTS.md"} {
		if _, err := os.Lstat(t.filename(filename)); err == nil {
			return writeResult{}, errors.New("org init refuses existing root rules; keep them and move their content into protocol sources before initializing")
		} else if !os.IsNotExist(err) {
			return writeResult{}, errors.New("cannot inspect the org folder before initializing")
		}
	}
	if info, err := os.Lstat(t.filename("worktrees")); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return writeResult{}, errors.New("worktrees must be a directory inside the org")
		}
	} else if !os.IsNotExist(err) {
		return writeResult{}, errors.New("cannot inspect the org folder before initializing")
	}
	t.levels, err = parseLevels(levelsArgument)
	if err != nil {
		return writeResult{}, err
	}
	name := filepath.Base(root)
	if selectedName != nil {
		name = *selectedName
	}
	defaultLevel := t.levels[0]
	t.configuration = map[string]any{
		"schema_version": 1, "name": name, "company": name, "levels": t.levels, "owner_channel": "owner",
		"secret_store": map[string]any{"kind": "keychain", "path": "laneboss/" + name},
		"defaults":     map[string]any{"level": defaultLevel, "role": roles[defaultLevel], "services": []any{}, "secrets": []any{}, "writable_repos": []any{}},
		"hooks":        map[string]any{"mode": "blacklist", "blacklist": rawTaskBlacklist()},
	}
	if err := problemsError(checkOrg(t.configuration, home+"/org.toml", root)); err != nil {
		return writeResult{}, err
	}
	text, err := encodeTOML(t.configuration, orgOrder)
	if err != nil {
		return writeResult{}, err
	}
	files := map[string]string{
		home + "/org.toml":                 text,
		home + "/shared/protocol/rules.md": sharedRules,
	}
	directories := []string{"worktrees"}
	for _, part := range []string{"protocol", "hooks", "tools", "services"} {
		directories = append(directories, home+"/shared/"+part)
	}
	for _, level := range t.levels {
		directory := fmt.Sprintf("%s/L%d", home, level)
		for _, part := range []string{"protocol", "hooks", "tools"} {
			directories = append(directories, directory+"/"+part)
		}
		files[directory+"/protocol/role.md"] = levelRules[level]
		data, err := instanceData(t.configuration, exampleNames[level], level, roles[level], nil, nil)
		if err != nil {
			return writeResult{}, err
		}
		t.instances[exampleNames[level]] = data
		instanceFiles, instanceDirectories, err := instanceFiles(data)
		if err != nil {
			return writeResult{}, err
		}
		for relative, text := range instanceFiles {
			files[relative] = text
		}
		directories = append(directories, instanceDirectories...)
	}
	for _, relative := range sortedKeys(files) {
		t.files[relative] = files[relative]
		t.scan(relative, files[relative])
	}
	if err := problemsError(t.problems); err != nil {
		return writeResult{}, err
	}
	generated, err := t.renderPlan()
	if err != nil {
		return writeResult{}, err
	}
	for relative, text := range generated {
		files[relative] = text
	}
	files[manifest], err = manifestText(generated)
	if err != nil {
		return writeResult{}, err
	}
	newFiles := map[string]bool{}
	for relative := range files {
		newFiles[relative] = true
	}
	result, err := t.apply(files, directories, newFiles)
	if err != nil {
		return writeResult{}, err
	}
	if _, err := orghook.RenderHookSettings(root); err != nil {
		return writeResult{}, fmt.Errorf("(hooks): runner hook settings could not be rendered: %w", err)
	}
	return result, nil
}

func renderOrg(argument string) (writeResult, error) {
	t, err := inspect(argument, true)
	if err != nil {
		return writeResult{}, err
	}
	if err := problemsError(t.problems); err != nil {
		return writeResult{}, err
	}
	if _, err := rolepolicy.Load(t.root, config.ScreenSettings); err != nil {
		return writeResult{}, err
	}
	generated, err := t.renderPlan()
	if err != nil {
		return writeResult{}, err
	}
	text, err := manifestText(generated)
	if err != nil {
		return writeResult{}, err
	}
	generated[manifest] = text
	result, err := t.apply(generated, nil, nil)
	if err != nil {
		return writeResult{}, err
	}
	if _, err := orghook.RenderHookSettingsUntil(t.root, t.deadline); err != nil {
		return writeResult{}, fmt.Errorf("(hooks): runner hook settings could not be rendered: %w", err)
	}
	return result, nil
}

func addInstance(argument, name string, level int, role string, channel *string, secrets []string) (writeResult, error) {
	t, err := inspect(argument, true)
	if err != nil {
		return writeResult{}, err
	}
	if err := problemsError(t.problems); err != nil {
		return writeResult{}, err
	}
	data, err := instanceData(t.configuration, name, level, role, channel, secrets)
	if err != nil {
		return writeResult{}, err
	}
	if err := problemsError(checkInstance(data, home+"/instances/(new)/instance.toml", name, t.levels)); err != nil {
		return writeResult{}, err
	}
	if err := t.instanceRole(level, role); err != nil {
		return writeResult{}, err
	}
	credential, scanErr := credentialValueUntil(data, t.deadline)
	if scanErr != nil {
		return writeResult{}, scanErr
	}
	if credential {
		return writeResult{}, errors.New("instance data contains a secret value; --secret takes names only")
	}
	directory := home + "/instances/" + name
	if _, err := os.Lstat(t.filename(directory)); err == nil {
		return writeResult{}, errors.New("the instance directory already exists; choose a new instance name")
	} else if !os.IsNotExist(err) {
		return writeResult{}, errors.New("cannot inspect the instance directory")
	}
	files, directories, err := instanceFiles(data)
	if err != nil {
		return writeResult{}, err
	}
	newFiles := map[string]bool{}
	for _, relative := range sortedKeys(files) {
		t.files[relative] = files[relative]
		t.scan(relative, files[relative])
		newFiles[relative] = true
	}
	t.instances[name] = data
	if err := problemsError(t.problems); err != nil {
		return writeResult{}, err
	}
	generated, err := t.renderPlan()
	if err != nil {
		return writeResult{}, err
	}
	for relative, text := range generated {
		if _, err := os.Lstat(t.filename(relative)); os.IsNotExist(err) {
			newFiles[relative] = true
		}
		files[relative] = text
	}
	files[manifest], err = manifestText(generated)
	if err != nil {
		return writeResult{}, err
	}
	result, err := t.apply(files, directories, newFiles)
	if err != nil {
		return writeResult{}, err
	}
	if _, err := orghook.RenderHookSettingsUntil(t.root, t.deadline); err != nil {
		return writeResult{}, fmt.Errorf("(hooks): runner hook settings could not be rendered: %w", err)
	}
	return result, nil
}
