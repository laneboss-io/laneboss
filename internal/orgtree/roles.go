package orgtree

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/orghook"
	"laneboss.io/laneboss/internal/rolepolicy"
)

func (t *tree) instanceRole(level int, role string) error {
	if err := rolepolicy.CheckName(role); err != nil {
		return err
	}
	catalog, err := rolepolicy.Load(t.root, config.ScreenSettings)
	if err != nil {
		return err
	}
	policy := catalog.Levels[level]
	if policy == nil || policy.Roles[role] == nil {
		return fmt.Errorf("instance role has no template at L%d\nInstead: choose an L%d role: %s", level, level, strings.Join(catalog.Roles(level), ", "))
	}
	return nil
}

func (t *tree) roleReport(laneUses map[string]bool, lanesChecked bool) ([]problem, []problem) {
	problems, warnings := []problem{}, []problem{}
	if len(t.levels) == 0 || len(t.problems) > 0 {
		return problems, warnings
	}
	catalog, err := rolepolicy.Load(t.root, config.ScreenSettings)
	if err != nil {
		return []problem{{"(roles)", err.Error()}}, warnings
	}
	used := map[string]bool{}
	for key := range laneUses {
		used[key] = true
	}
	for _, name := range sortedKeys(t.instances) {
		data := t.instances[name]
		level, _ := integer(data["level"])
		role, _ := data["role"].(string)
		used[fmt.Sprintf("L%d/%s", level, role)] = true
		if policy := catalog.Levels[level]; policy == nil || policy.Roles[role] == nil {
			problems = append(problems, problem{label(home + "/instances/" + name + "/instance.toml"), fmt.Sprintf("role has no template at L%d; available roles: %s", level, strings.Join(catalog.Roles(level), ", "))})
		}
	}
	for _, level := range t.levels {
		if len(catalog.Roles(level)) == 0 {
			warnings = append(warnings, problem{fmt.Sprintf("%s/L%d/roles", home, level), rolepolicy.Missing(level).Error()})
		}
		for _, role := range catalog.Roles(level) {
			if !strings.HasPrefix(catalog.Levels[level].Roles[role].Path, home+"/") {
				continue // Unused embedded fallbacks are not editable org sources.
			}
			if !used[fmt.Sprintf("L%d/%s", level, role)] {
				message := "no instance uses this template; use --config NAME to include lane usage"
				if lanesChecked {
					message = "no instance or lane in the named configuration uses this template"
				}
				warnings = append(warnings, problem{label(fmt.Sprintf("%s/L%d/roles/%s.md", home, level, role)), message})
			}
		}
	}
	return problems, warnings
}

func rolesInit(argument string, update bool, stderr io.Writer) (writeResult, error) {
	t, err := inspect(argument, true)
	if err != nil {
		return writeResult{}, err
	}
	if err := problemsError(t.problems); err != nil {
		return writeResult{}, err
	}
	library, err := rolepolicy.LibraryFiles(t.levels)
	if err != nil {
		return writeResult{}, err
	}
	// Keep the previous generator's example identities usable after migration.
	aliases := map[int][2]string{4: {"stream-supervisor", "supervisor"}, 5: {"top-supervisor", "top"}, 6: {"org-supervisor", "supervisor"}}
	for _, data := range t.instances {
		level, _ := integer(data["level"])
		role, _ := data["role"].(string)
		alias := aliases[level]
		if role == alias[0] && role != "" {
			for _, extension := range []string{".md", ".toml"} {
				library[fmt.Sprintf("L%d/roles/%s%s", level, role, extension)] = library[fmt.Sprintf("L%d/roles/%s%s", level, alias[1], extension)]
			}
		}
	}
	files, create := map[string]string{}, map[string]bool{}
	directories := []string{}
	for _, level := range t.levels {
		directories = append(directories, fmt.Sprintf("%s/L%d/roles", home, level))
	}
	for _, relative := range sortedKeys(library) {
		filename, next := home+"/"+relative, library[relative]
		current, exists := t.files[filename]
		if exists && !update {
			continue
		}
		if exists && current != next {
			// --update authorizes these replacements; show all changed bytes
			// before apply writes any source or generated file.
			if _, err := fmt.Fprintf(stderr, "--- %s (current)\n+++ %s (library)\n@@\n", filename, filename); err != nil {
				return writeResult{}, err
			}
			for _, line := range strings.Split(strings.TrimSuffix(current, "\n"), "\n") {
				if _, err := fmt.Fprintln(stderr, "-"+line); err != nil {
					return writeResult{}, err
				}
			}
			for _, line := range strings.Split(strings.TrimSuffix(next, "\n"), "\n") {
				if _, err := fmt.Fprintln(stderr, "+"+line); err != nil {
					return writeResult{}, err
				}
			}
		}
		files[filename], t.files[filename], create[filename] = next, next, !exists
		t.scan(filename, next)
	}
	if err := problemsError(t.problems); err != nil {
		return writeResult{}, err
	}
	t.imports = map[string][]importRef{}
	t.expanded = map[string]string{}
	t.checkImports(true)
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
	result, err := t.apply(files, directories, create)
	if err != nil {
		return writeResult{}, err
	}
	if _, err := orghook.RenderHookSettingsUntil(t.root, t.deadline); err != nil {
		return writeResult{}, errors.New("(hooks): runner hook settings could not be rendered")
	}
	return result, nil
}

func runRoles(args []string, stdout, stderr io.Writer) int {
	usage := "usage: laneboss org roles {init ORG_DIR [--update],list ORG_DIR}"
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	if len(args) == 0 || (args[0] != "init" && args[0] != "list") {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	action, update := args[0], false
	rest := []string{}
	for _, argument := range args[1:] {
		if action == "init" && argument == "--update" {
			update = true
		} else {
			rest = append(rest, argument)
		}
	}
	parsed, err := parseArgs(rest, nil)
	if err == nil && parsed.help {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	if err != nil || len(parsed.positionals) != 1 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var result any
	if action == "init" {
		result, err = rolesInit(parsed.positionals[0], update, stderr)
	} else {
		var t *tree
		t, err = inspect(parsed.positionals[0], true)
		if err == nil {
			err = problemsError(t.problems)
		}
		if err == nil {
			var catalog *rolepolicy.Catalog
			catalog, err = rolepolicy.Load(t.root, config.ScreenSettings)
			if err == nil {
				own := []map[string]any{}
				for _, level := range t.levels {
					for _, name := range catalog.Roles(level) {
						role := catalog.Levels[level].Roles[name]
						own = append(own, map[string]any{"level": level, "role": name, "drivers": role.Drivers, "sha256": rolepolicy.Hash(role.Bytes), "path": role.Path})
					}
				}
				var library []map[string]any
				library, err = rolepolicy.Library()
				result = map[string]any{"library": library, "roles": own}
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	text, err := jsonText(result, false)
	if err != nil {
		return 2
	}
	if _, err = io.WriteString(stdout, text); err != nil {
		return 2
	}
	return 0
}
