// Package bootstrap creates a named configuration and org as one CLI action.
package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"laneboss.io/laneboss/internal/cliargs"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/orghook"
	"laneboss.io/laneboss/internal/orgtree"
)

const usage = "usage: laneboss init ORG [--project PATH ...] " +
	"[--runner claudock|claude|codex] [--top-level N]"

type options struct {
	name     string
	projects []string
	runner   string
	level    int
	help     bool
}

type project struct {
	name       string
	repository string
}

func parse(args []string) (options, error) {
	o := options{level: 5}
	seen := map[string]bool{}
	positions := []string{}
	operands := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !operands && arg == "--" {
			operands = true
			continue
		}
		if !operands && (arg == "--help" || arg == "-h") {
			o.help = true
			continue
		}
		if operands || !strings.HasPrefix(arg, "-") {
			positions = append(positions, arg)
			continue
		}
		flag, value, inline := strings.Cut(arg, "=")
		if flag != "--project" && flag != "--runner" && flag != "--top-level" {
			return o, errors.New(cliargs.Reject(""))
		}
		if seen[flag] && flag != "--project" {
			return o, errors.New(cliargs.Reject(flag))
		}
		seen[flag] = true
		if !inline {
			i++
			if i >= len(args) || strings.HasPrefix(args[i], "-") {
				return o, errors.New(cliargs.Expected(flag))
			}
			value = args[i]
		}
		if value == "" {
			return o, errors.New(cliargs.Expected(flag))
		}
		switch flag {
		case "--project":
			o.projects = append(o.projects, value)
		case "--runner":
			if value != "claudock" && value != "claude" && value != "codex" {
				return o, errors.New(cliargs.Reject(flag))
			}
			o.runner = value
		case "--top-level":
			level, err := strconv.Atoi(value)
			if err != nil || (level != 5 && level != 6) {
				return o, errors.New("--top-level must be 5 or 6")
			}
			o.level = level
		}
	}
	if o.help {
		return o, nil
	}
	if len(positions) == 0 {
		return o, errors.New(cliargs.Required("ORG"))
	}
	if len(positions) != 1 {
		return o, errors.New(cliargs.Reject(""))
	}
	o.name = positions[0]
	if err := config.CheckName(o.name); err != nil {
		return o, err
	}
	if bound := os.Getenv("LANEBOSS_CONFIG"); bound != "" && bound != o.name {
		return o, errors.New("session is bound to another configuration; use a separate unbound shell")
	}
	return o, nil
}

func chooseRunner(requested string) (string, error) {
	if requested != "" {
		if _, err := exec.LookPath(requested); err != nil {
			return "", fmt.Errorf("selected runner %s is not executable on PATH", requested)
		}
		return requested, nil
	}
	for _, name := range []string{"claudock", "claude", "codex"} {
		if _, err := exec.LookPath(name); err == nil {
			return name, nil
		}
	}
	return "", errors.New("no runner found on PATH: install claudock, claude or codex")
}

// Git is the only subprocess. No runner, account, network or secret is probed.
func gitRoot(argument string) (string, error) {
	if strings.HasPrefix(argument, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.New("cannot resolve --project path")
		}
		argument = filepath.Join(home, argument[2:])
	}
	if argument == "" {
		return "", errors.New("--project must name a Git work tree")
	}
	absolute, err := filepath.Abs(argument)
	if err != nil {
		return "", errors.New("cannot resolve --project path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "-C", absolute,
		"rev-parse", "--show-toplevel")
	// Inherited Git overrides must not make an unrelated directory look valid.
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "GIT_") {
			command.Env = append(command.Env, item)
		}
	}
	output, err := command.Output()
	if err != nil {
		return "", errors.New("--project must name a Git work tree; git rev-parse failed")
	}
	root, err := filepath.EvalSymlinks(strings.TrimSuffix(string(output), "\n"))
	if err != nil || !filepath.IsAbs(root) {
		return "", errors.New("cannot resolve the Git work tree")
	}
	return root, nil
}

func projects(arguments []string) ([]project, error) {
	result := []project{}
	names, roots := map[string]bool{}, map[string]bool{}
	for _, argument := range arguments {
		root, err := gitRoot(argument)
		if err != nil {
			return nil, err
		}
		name := filepath.Base(root)
		if err := config.CheckName(name); err != nil {
			return nil, errors.New("project directory name must match " + config.NameRule)
		}
		if names[name] || roots[root] {
			return nil, errors.New("duplicate project: repeated repository or directory name")
		}
		names[name], roots[root] = true, true
		result = append(result, project{name, root})
	}
	return result, nil
}

const standing = `# Standing rules

- Read the whole brief and keep evidence for the requested checks.
- Keep secret values outside configuration and source files.
- Stop at a refused action and report its exact refusal to the supervisor.
- A supervisor reviews the diff and required checks before accepting a lane.
`

func runnerData(runner, instance string) map[string]any {
	brief := "Read the file {brief} completely and carry out its task."
	message := "Read the file {message} completely and carry on from it."
	if runner == "codex" {
		return map[string]any{
			"command": []string{"env", "CODEX_HOME=" + filepath.Join(instance, ".codex"),
				"codex", "-c", "features.hooks=true", "exec", "--model", "{model}", brief},
			"records": []map[string]any{{"format": "text", "paths": []string{"{log}"}}},
		}
	}
	prefix := []string{"claude"}
	if runner == "claudock" {
		prefix = []string{"claudock", "run", "{account}", "--"}
	}
	start := append(append([]string{}, prefix...), "-p", "--settings",
		filepath.Join(instance, ".claude", "settings.json"),
		"--session-id", "{session}", "--model", "{model}", brief)
	resume := append(append([]string{}, prefix...), "-p", "--settings",
		filepath.Join(instance, ".claude", "settings.json"),
		"--resume", "{session}", "--model", "{model}", message)
	return map[string]any{
		"command": start, "resume": resume,
		"records": []map[string]any{
			{"format": "claude-code", "paths": []string{"~/.claude/projects/*/{session}.jsonl"}},
			{"format": "text", "paths": []string{"{log}"}},
		},
	}
}

func writeTOML(path string, value any) error {
	var buffer bytes.Buffer
	if err := toml.NewEncoder(&buffer).Encode(value); err != nil {
		return errors.New("cannot encode bootstrap TOML")
	}
	return os.WriteFile(path, buffer.Bytes(), 0600)
}

func writeConfig(directory string, o options, items []project, org string) error {
	if err := os.MkdirAll(filepath.Join(directory, "rules"), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(directory, "projects"), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "rules", "standing.md"), []byte(standing), 0600); err != nil {
		return err
	}
	names := []string{}
	for _, item := range items {
		names = append(names, item.name)
		data := map[string]any{"schema_version": 1, "name": item.name,
			"repository": item.repository, "workers": []string{o.runner}, "landing_authority": "top"}
		if err := writeTOML(filepath.Join(directory, "projects", item.name+".toml"), data); err != nil {
			return err
		}
	}
	instanceName := "L5-top"
	if o.level == 6 {
		instanceName = "L6-super-top"
	}
	instance := filepath.Join(org, ".laneboss", "instances", instanceName)
	model := "claude-sonnet-5-5"
	if o.runner == "codex" {
		model = "gpt-6.1-sol"
	}
	routing := map[string]any{}
	for _, difficulty := range []string{"mechanical", "standard", "hard", "review"} {
		routing[difficulty] = []map[string]any{{"runner": o.runner, "model": model}}
	}
	data := map[string]any{
		"schema_version": 1, "name": o.name, "organisation": o.name,
		"rules": []string{"rules/standing.md"},
		"lanes": map[string]any{"budget_minutes": 60,
			"quiet_seconds": 900, "stop_grace_seconds": 10},
		"runners": map[string]any{o.runner: runnerData(o.runner, instance)},
		"supervisors": map[string]any{"top": map[string]any{
			"level": o.level, "runner": o.runner, "projects": names}},
		"routing": routing,
	}
	return writeTOML(filepath.Join(directory, "config.toml"), data)
}

func absent(path, kind string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return fmt.Errorf("existing %s: init refuses to overwrite it", kind)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("cannot inspect the %s destination", kind)
	}
	return nil
}

// Tagged instrumentation injects a failure at a real transaction boundary.
func failAt(point string) error {
	if faults.Get(point).Point == "" {
		return nil
	}
	if err := faults.Reach(point); err != nil {
		return err
	}
	return errors.New("injected init failure at " + point)
}

func createdFiles(root, destination string) ([]string, error) {
	files := []string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.Join(destination, relative))
		return nil
	})
	sort.Strings(files)
	return files, err
}

func initialize(o options) (files []string, err error) {
	home, err := config.Home()
	if err != nil {
		return nil, err
	}
	states, err := config.StateHome()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		return nil, errors.New("cannot create the configuration home")
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		return nil, errors.New("cannot resolve the configuration home")
	}
	configuration := filepath.Join(home, "configs", o.name)
	org := filepath.Join(home, "orgs", o.name)
	if err := absent(configuration, "configuration"); err != nil {
		return nil, err
	}
	if err := absent(org, "org"); err != nil {
		return nil, err
	}
	items, err := projects(o.projects)
	if err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(home, ".laneboss-init-")
	if err != nil {
		return nil, errors.New("cannot create the init stage")
	}
	configPublished, orgPublished, complete := false, false, false
	defer func() {
		var cleanup []error
		if !complete {
			if configPublished {
				cleanup = append(cleanup, os.RemoveAll(configuration))
			}
			// The restoring mutant reinstates a partial org after a failed init.
			keep := faults.Get("init-after-org").Continue == "keep-org"
			if orgPublished && !keep {
				cleanup = append(cleanup, os.RemoveAll(org))
			}
		}
		cleanup = append(cleanup, os.RemoveAll(stage))
		if errors.Join(cleanup...) != nil {
			err = errors.Join(err, errors.New("init cleanup failed; inspect destinations before retrying"))
		}
	}()
	stagedConfig := filepath.Join(stage, "configs", o.name)
	stagedOrg := filepath.Join(stage, "orgs", o.name)
	if err := writeConfig(stagedConfig, o, items, org); err != nil {
		return nil, errors.New("cannot write the staged configuration")
	}
	if err := failAt("init-stage"); err != nil {
		return nil, err
	}
	if err := orgtree.Init(stagedOrg, o.name); err != nil {
		return nil, err
	}
	// doctor expects the conventional organisation tools directory.
	if err := os.Mkdir(filepath.Join(stagedOrg, "tools"), 0700); err != nil {
		return nil, errors.New("cannot create org tools directory")
	}
	if err := config.Validate(o.name, config.Options{Home: stage, StateHome: states}); err != nil {
		return nil, err
	}
	if err := orgtree.Validate(stagedOrg); err != nil {
		return nil, err
	}
	if err := orghook.RenderHookSettingsFor(stagedOrg, org); err != nil {
		return nil, err
	}
	for _, pair := range [][2]string{{stagedConfig, configuration}, {stagedOrg, org}} {
		created, err := createdFiles(pair[0], pair[1])
		if err != nil {
			return nil, errors.New("cannot inventory the staged files")
		}
		files = append(files, created...)
	}
	for _, parent := range []string{filepath.Dir(configuration), filepath.Dir(org)} {
		if err := os.MkdirAll(parent, 0700); err != nil {
			return nil, errors.New("cannot create an init destination parent")
		}
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("init destination parents must be directories without symlinks")
		}
	}
	if err := publishDirectory(stagedOrg, org); err != nil {
		return nil, errors.New("cannot publish org; an existing destination is never replaced")
	}
	orgPublished = true
	if err := failAt("init-after-org"); err != nil {
		return nil, err
	}
	if err := publishDirectory(stagedConfig, configuration); err != nil {
		return nil, errors.New("cannot publish configuration; an existing destination is never replaced")
	}
	configPublished = true
	if err := config.Validate(o.name); err != nil {
		return nil, err
	}
	if err := orgtree.Validate(org); err != nil {
		return nil, err
	}
	complete = true
	return files, nil
}

// Run implements init; stdout reports the chosen runner, every path and next step.
func Run(args []string, _ io.Reader, stdout, stderr io.Writer) int {
	o, err := parse(args)
	if err != nil {
		fmt.Fprintln(stderr, usage)
		fmt.Fprintln(stderr, "laneboss init: "+err.Error())
		return 2
	}
	if o.help {
		fmt.Fprintln(stdout, usage)
		fmt.Fprintln(stdout, "Creates a configuration, projects, L3-L6 org and generated hooks.")
		fmt.Fprintln(stdout, "Runner order: claudock, claude, codex. Top level: 5 (default) or 6.")
		return 0
	}
	o.runner, err = chooseRunner(o.runner)
	if err != nil {
		fmt.Fprintln(stderr, "laneboss init: "+err.Error())
		return 2
	}
	files, err := initialize(o)
	if err != nil {
		fmt.Fprintln(stderr, "laneboss init: "+err.Error())
		return 2
	}
	var output strings.Builder
	fmt.Fprintf(&output, "Chosen runner: %s\n", o.runner)
	for _, file := range files {
		fmt.Fprintf(&output, "Created: %q\n", file)
	}
	if o.runner == "claudock" {
		fmt.Fprintln(&output, "Before dispatch: add your own Claudock profile names to runners.claudock.accounts.")
	}
	fmt.Fprintf(&output, "Next: laneboss start --config %s --role top\n", o.name)
	if _, err := io.WriteString(stdout, output.String()); err != nil {
		fmt.Fprintln(stderr, "cannot write the init report")
		return 2
	}
	return 0
}
