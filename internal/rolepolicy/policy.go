package rolepolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/hookblacklist"
	"laneboss.io/laneboss/internal/settings"
)

const maxBytes = 2 * 1024 * 1024

type Input struct {
	Path  string
	Bytes []byte
}

type Template struct {
	Name, Path, DriverPath string
	Bytes, DriverBytes     []byte
	Drivers                []string
	Blacklist              []hookblacklist.Rule
}

type Level struct {
	Roles                 map[string]*Template
	AllowHumanWithoutRole bool
	HasRolesDirectory     bool
	DriverInputs          []Input
}

type Catalog struct {
	Root        string
	Levels      map[int]*Level
	ConfigBytes []byte
}

type Selection struct {
	Catalog        *Catalog
	Level          int
	Role           *Template
	Principal      string
	Inputs         []Input
	BlacklistPaths []string
}

func Hash(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// CheckName preserves the instance role's text grammar, with a single-filename
// restriction. No caller can turn a role into a source path.
func CheckName(name string) error {
	if !utf8.ValidString(name) || strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > 128 {
		return errors.New("role must be nonempty UTF-8 text of at most 128 characters")
	}
	if name == "." || name == ".." || strings.ContainsAny(name, "/\\") || strings.IndexFunc(name, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return errors.New("role must be one safe filename without separators or controls")
	}
	return nil
}

func CheckTemplate(data []byte) error {
	err := checkTemplate(data)
	if err != nil && faults.Get("roles-source-error-open").Point != "" {
		return faults.Reach("roles-source-error-open")
	}
	return err
}

func checkTemplate(data []byte) error {
	if !utf8.Valid(data) || len(data) == 0 || len(data) > maxBytes {
		return errors.New("role template must be nonempty UTF-8 text within 2 MiB")
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if strings.HasPrefix(strings.TrimSpace(text), "---\n") {
		return errors.New("role template must not have front matter")
	}
	for _, heading := range []string{"Scope", "Responsibilities", "Deliverable", "Must not"} {
		if !regexp.MustCompile(`(?m)^#{1,6}[ \t]+` + heading + `[ \t]*#*[ \t]*$`).MatchString(text) {
			return fmt.Errorf("role template needs a %s section", heading)
		}
	}
	return nil
}

// CheckSourcePair validates all role bytes before an org render can publish
// them. TOML decoding errors and incomplete settings are never partial success.
func CheckSourcePair(body, driverBytes []byte, filename string) error {
	if err := CheckTemplate(body); err != nil {
		return err
	}
	if _, err := parseDrivers(driverBytes); err != nil {
		return err
	}
	_, err := settings.ParseFile(driverBytes, filename, "role", "settings", nil)
	return err
}

var driverPattern = regexp.MustCompile(`^[A-Za-z0-9_+.-]{1,128}$`)

func parseDrivers(data []byte) ([]string, error) {
	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err != nil {
		return nil, errors.New("role driver file must contain drivers and optional settings or blacklist")
	}
	for key := range document {
		if key != "drivers" && key != "settings" && key != "blacklist" {
			return nil, errors.New("role driver file must contain drivers and optional settings or blacklist")
		}
	}
	if _, err := hookblacklist.Parse(document["blacklist"], "role blacklist"); err != nil {
		return nil, err
	}
	if value, exists := document["settings"]; exists {
		if err := settings.ValidateTable(value); err != nil {
			return nil, err
		}
	}
	items, ok := document["drivers"].([]any)
	if !ok || len(items) == 0 || len(items) > 32 {
		return nil, errors.New("role drivers must be an array of 1 to 32 command basenames")
	}
	result := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		name, ok := item.(string)
		if !ok || !driverPattern.MatchString(name) || name == "." || name == ".." || seen[name] {
			return nil, errors.New("role drivers must be distinct command basenames without paths")
		}
		seen[name] = true
		result = append(result, name)
	}
	return result, nil
}

func directory(root *os.Root, relative string) error {
	for current := relative; current != "."; current = path.Dir(current) {
		info, err := root.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("org policy directories must be ordinary directories without symbolic links")
		}
	}
	return nil
}

func read(root *os.Root, relative string) ([]byte, error) {
	if err := directory(root, path.Dir(relative)); err != nil {
		return nil, err
	}
	file, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, errors.New("org policy sources must be regular files within 2 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || len(data) > maxBytes || !utf8.Valid(data) {
		return nil, errors.New("org policy sources must be bounded UTF-8 text")
	}
	return data, nil
}

func entries(root *os.Root, relative string) ([]os.DirEntry, error) {
	if err := directory(root, relative); err != nil {
		return nil, err
	}
	file, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	items, err := file.ReadDir(4097)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(items) > 4096 {
		return nil, errors.New("org policy directory exceeds its entry limit")
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name() < items[j].Name() })
	return items, nil
}

func Missing(level int) error {
	return fmt.Errorf("role templates are missing at L%d\nInstead: run laneboss org roles init ORG_DIR", level)
}

// ConfigRoot uses configuration-owned data, never a lane-supplied file or path.
func ConfigRoot(home string, data map[string]any) (string, error) {
	if value, exists := data["org_dir"]; exists {
		root, ok := value.(string)
		if !ok || !filepath.IsAbs(root) || len(root) > 4096 || strings.IndexFunc(root, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return "", errors.New("org_dir must be an absolute org folder path without controls")
		}
		return filepath.Clean(root), nil
	}
	if name, _ := data["organisation"].(string); name != "" {
		return filepath.Join(home, "orgs", name), nil
	}
	return "", nil
}

func number(value any) (int, bool) {
	switch value := value.(type) {
	case int:
		return value, true
	case int64:
		return int(value), value == int64(int(value))
	case json.Number:
		n, err := strconv.Atoi(string(value))
		return n, err == nil
	case float64:
		if value >= 3 && value <= 6 && value == float64(int(value)) {
			return int(value), true
		}
	}
	return 0, false
}

// Settings validates the optional per-level human exception in org.toml. The
// value is accepted and recorded but grants nothing: selectRole refuses every
// role-free start until identity binding can tell a human from a supervisor.
func Settings(document map[string]any, levels []int) (map[int]bool, error) {
	result := map[int]bool{}
	value, exists := document["lane_roles"]
	if !exists {
		return result, nil
	}
	tables, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("lane_roles must be a table of enabled levels")
	}
	for key, value := range tables {
		level := 0
		for _, enabled := range levels {
			if key == fmt.Sprintf("L%d", enabled) {
				level = enabled
			}
		}
		fields, ok := value.(map[string]any)
		allowed, boolean := fields["allow_human_without_role"].(bool)
		if level == 0 || !ok || len(fields) != 1 || !boolean {
			return nil, errors.New("lane_roles needs an enabled L3-L6 table containing only allow_human_without_role = true|false")
		}
		result[level] = allowed
	}
	return result, nil
}

// Load resolves each role from the org first, then the embedded library. An
// incomplete or unsafe org source is an error, never a request for fallback.
func Load(folder string, screens ...func([]byte) error) (*Catalog, error) {
	screen := func(data []byte) error {
		if len(screens) > 0 && screens[0] != nil {
			return screens[0](data)
		}
		return nil
	}
	if folder == "" {
		return nil, errors.New("the configuration has no org folder\nInstead: run laneboss org init ORG_DIR and set org_dir in config.toml")
	}
	resolved, err := filepath.EvalSymlinks(folder)
	if err != nil {
		return nil, errors.New("the configured org folder cannot be opened")
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, errors.New("the configured org folder cannot be opened")
	}
	defer root.Close()
	if err := settings.CheckSources(resolved, screen); err != nil {
		return nil, err
	}
	data, err := read(root, ".laneboss/org.toml")
	if err != nil {
		return nil, errors.New("the org configuration cannot be read\nInstead: run laneboss org roles init ORG_DIR after restoring org.toml")
	}
	if err := screen(data); err != nil {
		return nil, err
	}
	var document map[string]any
	if _, err = toml.Decode(string(data), &document); err != nil {
		return nil, errors.New("the org configuration must be valid TOML")
	}
	version, ok := number(document["schema_version"])
	values, array := document["levels"].([]any)
	if !ok || version != 1 || !array || len(values) == 0 || len(values) > 4 {
		return nil, errors.New("the org configuration needs schema_version = 1 and distinct enabled levels within 3-6")
	}
	levels := []int{}
	seen := map[int]bool{}
	for _, value := range values {
		level, ok := number(value)
		if !ok || level < 3 || level > 6 || seen[level] {
			return nil, errors.New("the org configuration needs distinct enabled levels within 3-6")
		}
		levels = append(levels, level)
		seen[level] = true
	}
	humanAllowed, err := Settings(document, levels)
	if err != nil {
		return nil, err
	}
	catalog := &Catalog{Root: resolved, Levels: map[int]*Level{}, ConfigBytes: data}
	blacklistIDs := map[string]bool{}
	if hooks, ok := document["hooks"].(map[string]any); ok {
		rows, err := hookblacklist.Parse(hooks["blacklist"], "org.toml hooks.blacklist")
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			blacklistIDs[row.ID] = true
		}
	}
	roleBytes := 0
	for _, level := range levels {
		builtins, err := builtinTemplates(level)
		if err != nil {
			return nil, err
		}
		policy := &Level{Roles: builtins, AllowHumanWithoutRole: humanAllowed[level]}
		catalog.Levels[level] = policy
		dir := fmt.Sprintf(".laneboss/L%d/roles", level)
		if err := directory(root, dir); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("L%d role directories must be ordinary directories without links", level)
		}
		before, err := root.Lstat(dir)
		if err != nil {
			return nil, fmt.Errorf("L%d role directory cannot be inspected", level)
		}
		roleRoot, err := root.OpenRoot(dir)
		if err != nil {
			return nil, fmt.Errorf("L%d role directory cannot be opened safely", level)
		}
		defer roleRoot.Close()
		after, err := roleRoot.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			return nil, fmt.Errorf("L%d role directory changed while opening", level)
		}
		items, err := entries(roleRoot, ".")
		if err != nil {
			return nil, fmt.Errorf("L%d roles must be readable ordinary files inside the roles directory", level)
		}
		policy.HasRolesDirectory = true
		if len(items) > 512 {
			return nil, errors.New("org role directory exceeds its template count limit")
		}
		for _, entry := range items {
			ext := path.Ext(entry.Name())
			if ext != ".md" && ext != ".toml" {
				return nil, fmt.Errorf("L%d roles directory accepts paired Markdown and TOML files only", level)
			}
			name := strings.TrimSuffix(entry.Name(), ext)
			if builtins[name] != nil && faults.Get("roles-entry-fallback-open").Point != "" {
				if err := faults.Reach("roles-entry-fallback-open"); err != nil {
					return nil, err
				}
				continue
			}
			if err := screen([]byte(entry.Name())); err != nil {
				return nil, err
			}
			if CheckName(name) != nil || !entry.Type().IsRegular() {
				return nil, fmt.Errorf("L%d role sources must be safe regular filenames, never links or directories", level)
			}
			if ext == ".toml" {
				if _, err := roleRoot.Lstat(name + ".md"); err != nil {
					return nil, fmt.Errorf("L%d driver file has no Markdown role template", level)
				}
				continue
			}
			filename := path.Join(dir, entry.Name())
			body, err := read(roleRoot, entry.Name())
			if err != nil {
				return nil, fmt.Errorf("L%d role template cannot be read safely", level)
			}
			if err = CheckTemplate(body); err != nil {
				return nil, fmt.Errorf("L%d role template: %w", level, err)
			}
			if err := screen(body); err != nil {
				return nil, err
			}
			driverPath := path.Join(dir, name+".toml")
			driverBytes, err := read(roleRoot, name+".toml")
			if err != nil {
				return nil, fmt.Errorf("L%d role template needs its ordinary TOML driver file", level)
			}
			if err := screen(driverBytes); err != nil {
				return nil, err
			}
			drivers, err := parseDrivers(driverBytes)
			if err != nil {
				return nil, fmt.Errorf("L%d role driver file: %w", level, err)
			}
			blacklistRows, err := roleBlacklist(driverBytes, driverPath)
			if err != nil {
				return nil, err
			}
			for _, row := range blacklistRows {
				if blacklistIDs[row.ID] {
					return nil, fmt.Errorf("%s blacklist id %q must be unique per org", driverPath, row.ID)
				}
				blacklistIDs[row.ID] = true
			}
			if _, err := settings.ParseFile(driverBytes, filepath.Join(resolved, driverPath), "role", "settings", screen); err != nil {
				return nil, err
			}
			roleBytes += len(body) + len(driverBytes)
			if roleBytes > 8*1024*1024 {
				return nil, errors.New("org role sources exceed their total byte limit")
			}
			policy.Roles[name] = &Template{Name: name, Path: filename, DriverPath: driverPath, Bytes: body, DriverBytes: driverBytes, Drivers: drivers, Blacklist: blacklistRows}
			policy.DriverInputs = append(policy.DriverInputs, Input{driverPath, driverBytes})
		}
		// An existing roles directory is explicit org policy, including when
		// empty. Missing roles may supply text, never additional drivers.
		ceiling := map[string]bool{}
		for _, role := range policy.Roles {
			if strings.HasPrefix(role.Path, ".laneboss/") {
				for _, driver := range role.Drivers {
					ceiling[driver] = true
				}
			}
		}
		for _, role := range policy.Roles {
			if !strings.HasPrefix(role.Path, "builtin/") {
				continue
			}
			if faults.Get("roles-fallback-union").Point != "" {
				if err := faults.Reach("roles-fallback-union"); err != nil {
					return nil, err
				}
				continue
			}
			allowed := []string{}
			for _, driver := range role.Drivers {
				if ceiling[driver] {
					allowed = append(allowed, driver)
				}
			}
			role.Drivers = allowed
		}
	}
	return catalog, nil
}

const supervisedHuman = "a supervised session cannot select a human principal\nInstead: select --role from the lane level's roles"

// Principal accepts the requested principal and refuses human only when one of
// three environment variables marks a launcher-bound lane. A process that clears
// them, or an org instance identified only by its working directory, passes as
// human, so no start is admitted on this value alone.
func Principal(requested string) (string, error) {
	if requested == "" {
		requested = "supervisor"
	}
	if requested != "human" && requested != "supervisor" {
		return "", errors.New("principal must be human or supervisor")
	}
	if requested == "human" && (os.Getenv("LANEBOSS_LANE") != "" || os.Getenv("LANEBOSS_INSTANCE") != "" || os.Getenv("LANEBOSS_PRINCIPAL") == "supervisor") {
		return "", errors.New(supervisedHuman)
	}
	return requested, nil
}

// Authenticated applies the caller's authenticated identity to a declared --principal. caller is the principal id
// that internal/caller resolves from recorded processes ("human", "lane:NAME", "supervisor:NAME", "instance:NAME"),
// or "" when nothing proves who is calling. Principal can only read environment variables, which a caller controls,
// so the human principal is declared only by a caller authenticated as the human (a real controlling terminal with
// no recorded identity). A lane, a supervisor, an instance and a caller that nothing identifies are refused here,
// before the role policy runs, so no unproven "human" reaches the lane's role_context. Principal's own environment
// check stays as a second check for the authenticated human.
func Authenticated(requested, caller string) error {
	if requested == "human" && caller != "human" {
		return errors.New(supervisedHuman)
	}
	return nil
}

// ParseLevel reads --level; an absent flag is the protocol's own lane level, L3.
func ParseLevel(text string) (int, error) {
	if text == "" {
		return 3, nil
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 3 || n > 6 {
		return 0, errors.New("level must be an integer from 3 to 6")
	}
	return n, nil
}

func (c *Catalog) Roles(level int) []string {
	if policy := c.Levels[level]; policy != nil {
		return sortedKeys(policy.Roles)
	}
	return []string{}
}

func (c *Catalog) Drivers(level int) []string {
	set := map[string]bool{}
	if policy := c.Levels[level]; policy != nil {
		for _, role := range policy.Roles {
			for _, driver := range role.Drivers {
				set[driver] = true
			}
		}
	}
	return sortedKeys(set)
}

func (c *Catalog) selectRole(level int, name, principal string) (*Selection, error) {
	policy := c.Levels[level]
	if policy == nil {
		return nil, errors.New("the lane level is not enabled in the configured org\nInstead: choose an enabled --level from org.toml")
	}
	roles := c.Roles(level)
	if len(roles) == 0 {
		return nil, Missing(level)
	}
	selection := &Selection{Catalog: c, Level: level, Principal: principal}
	if name == "" {
		optional := faults.Get("roles-supervisor-optional").Point != ""
		if optional {
			if err := faults.Reach("roles-supervisor-optional"); err != nil {
				return nil, err
			}
		}
		// No principal starts role-free: the human principal is a declaration read
		// from the caller's environment, which a supervisor can make as well.
		if !optional {
			return nil, fmt.Errorf("a role is required at L%d for this principal\nInstead: choose --role from L%d roles: %s", level, level, strings.Join(roles, ", "))
		}
	} else {
		if err := CheckName(name); err != nil {
			return nil, fmt.Errorf("%s\nInstead: choose --role from L%d roles: %s", err, level, strings.Join(roles, ", "))
		}
		selection.Role = policy.Roles[name]
		if selection.Role == nil {
			return nil, fmt.Errorf("unknown role at L%d\nInstead: choose --role from L%d roles: %s", level, level, strings.Join(roles, ", "))
		}
	}
	return selection, nil
}

// CheckStartName keeps early settings resolution from replacing a role-name
// refusal with a generic path error. Valid and absent names still reach the
// ordinary role gate after caller authentication and runner selection.
func CheckStartName(home string, data map[string]any, levelText, name string, screens ...func([]byte) error) error {
	if name == "" || CheckName(name) == nil {
		return nil
	}
	level, err := ParseLevel(levelText)
	if err != nil {
		return err
	}
	folder, err := ConfigRoot(home, data)
	if err != nil {
		return err
	}
	catalog, err := Load(folder, screens...)
	if err != nil {
		return err
	}
	_, err = catalog.selectRole(level, name, "supervisor")
	return err
}

func Start(home string, data map[string]any, levelText, name, requestedPrincipal string, argv []string, screens ...func([]byte) error) (*Selection, error) {
	level, err := ParseLevel(levelText)
	if err != nil {
		return nil, err
	}
	principal, err := Principal(requestedPrincipal)
	if err != nil {
		return nil, err
	}
	folder, err := ConfigRoot(home, data)
	if err != nil {
		return nil, err
	}
	catalog, err := Load(folder, screens...)
	if err != nil {
		return nil, err
	}
	selection, err := catalog.selectRole(level, name, principal)
	if err != nil {
		return nil, err
	}
	if err = selection.CheckDriver(argv); err != nil {
		return nil, err
	}
	if err = selection.loadInputs(); err != nil {
		return nil, err
	}
	return selection, nil
}

func Previous(home string, data, payload map[string]any, argv []string, screens ...func([]byte) error) (*Selection, error) {
	if err := ValidateEvent(payload); err != nil {
		return nil, err
	}
	context, exists := payload["role_context"].(map[string]any)
	if !exists {
		return nil, errors.New("the lane has no recorded org role\nInstead: start a new lane with --role after laneboss org roles init ORG_DIR")
	}
	folder, err := ConfigRoot(home, data)
	if err != nil {
		return nil, err
	}
	catalog, err := Load(folder, screens...)
	if err != nil {
		return nil, err
	}
	if catalog.Root != context["org_dir"] {
		return nil, errors.New("the lane's recorded org differs from the configuration\nInstead: restore the lane's original configured org folder")
	}
	level, _ := number(context["level"])
	name, _ := payload["role"].(string)
	principal, _ := context["principal"].(string)
	selection, err := catalog.selectRole(level, name, principal)
	if err != nil {
		return nil, err
	}
	if err = selection.CheckDriver(argv); err != nil {
		return nil, err
	}
	if err = selection.loadInputs(); err != nil {
		return nil, err
	}
	return selection, nil
}

func (s *Selection) CheckDriver(argv []string) error {
	if len(argv) == 0 {
		return errors.New("a role driver needs a nonempty argument vector")
	}
	allowed := s.Catalog.Drivers(s.Level)
	if s.Role != nil {
		allowed = s.Role.Drivers
	}
	if faults.Get("roles-skip-driver").Point != "" {
		return faults.Reach("roles-skip-driver")
	}
	if faults.Get("roles-level-only").Point != "" {
		if err := faults.Reach("roles-level-only"); err != nil {
			return err
		}
		allowed = s.Catalog.Drivers(s.Level)
	}
	names := []string{argv[0]}
	if program, looked := envProgram(argv); looked {
		names = append(names, program)
	}
	// The roles-env-skip-any mutant passes over every word after env, whatever its shape.
	if faults.Get("roles-env-skip-any").Point != "" && filepath.Base(argv[0]) == "env" {
		if err := faults.Reach("roles-env-skip-any"); err != nil {
			return err
		}
		names = append(names, argv[1:]...)
	}
	for _, name := range names {
		base := filepath.Base(name)
		for _, driver := range allowed {
			if base == driver {
				return nil
			}
		}
	}
	return fmt.Errorf("runner driver is not allowed for this role at L%d%s\nInstead: use an allowed driver: %s", s.Level, envHint(argv), strings.Join(allowed, ", "))
}

// plainAssignment is a NAME=VALUE word that env applies verbatim: a shell-style
// NAME, and a VALUE of ASCII letters, digits and the punctuation of ordinary
// paths. A substitution ($ or a backtick), a quote or backslash, a launcher
// placeholder ({ }), whitespace and controls are never plain.
var plainAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_./:,+@%=-]*$`)

// envProgram returns the program that a bare leading env runs when nothing but
// plain NAME=VALUE words stand between them. Every word with an "=" must be
// plain, since env takes any such word as an assignment. It reports false for
// env with an option or any word starting with "-", no assignment, no program,
// a program that is another env, or env given by a path: such a command keeps
// env as its driver.
func envProgram(argv []string) (string, bool) {
	if len(argv) < 3 || argv[0] != "env" {
		return "", false
	}
	index := 1
	for index < len(argv) && strings.Contains(argv[index], "=") {
		if !plainAssignment.MatchString(argv[index]) {
			return "", false
		}
		index++
	}
	if index == 1 || index == len(argv) || strings.HasPrefix(argv[index], "-") || filepath.Base(argv[index]) == "env" {
		return "", false
	}
	return argv[index], true
}

// envHint explains a refusal of an env command that was not looked through.
func envHint(argv []string) string {
	if _, looked := envProgram(argv); !looked && filepath.Base(argv[0]) == "env" {
		return " (a bare env is looked through only when plain NAME=VALUE words alone precede the program)"
	}
	return ""
}

func protocolInputs(root *os.Root, dir string, depth int, count, usedBytes *int) ([]Input, error) {
	if depth > 32 || *count > 4096 {
		return nil, errors.New("org protocol exceeds its nesting or entry limit")
	}
	items, err := entries(root, dir)
	if err != nil {
		return nil, errors.New("org protocol directory cannot be read safely")
	}
	inputs := []Input{}
	for _, item := range items {
		*count++
		if *count > 4096 || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(item.Name()) {
			return nil, errors.New("org protocol source count or filename is invalid")
		}
		filename := path.Join(dir, item.Name())
		if item.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("org protocol sources must not be symbolic links")
		}
		if item.IsDir() {
			children, err := protocolInputs(root, filename, depth+1, count, usedBytes)
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, children...)
		} else if strings.HasSuffix(item.Name(), ".md") {
			data, err := read(root, filename)
			if err != nil {
				return nil, errors.New("org protocol source cannot be read safely")
			}
			*usedBytes += len(data)
			if *usedBytes > 4*1024*1024 {
				return nil, errors.New("org protocol sources exceed their total byte limit")
			}
			inputs = append(inputs, Input{filename, data})
		}
	}
	return inputs, nil
}

func (s *Selection) loadInputs() error {
	root, err := os.OpenRoot(s.Catalog.Root)
	if err != nil {
		return errors.New("the selected org folder cannot be reopened")
	}
	defer root.Close()
	s.Inputs = append(s.Inputs, Input{".laneboss/org.toml", s.Catalog.ConfigBytes})
	role := ""
	if s.Role != nil {
		role = s.Role.Name
	}
	sources, err := s.Catalog.EffectiveBlacklist(s.Level, role)
	if err != nil {
		return err
	}
	s.BlacklistPaths = BlacklistSourcePaths(s.Catalog.Root, sources)
	for _, source := range sources {
		if s.Role != nil && source.Path == filepath.Join(s.Catalog.Root, s.Role.DriverPath) {
			continue // the selected role pair remains the last inputs
		}
		relative, err := filepath.Rel(s.Catalog.Root, source.Path)
		if err != nil {
			return err
		}
		s.Inputs = append(s.Inputs, Input{filepath.ToSlash(relative), source.Bytes})
	}
	count, usedBytes := 0, 0
	for _, dir := range []string{".laneboss/shared/protocol", fmt.Sprintf(".laneboss/L%d/protocol", s.Level)} {
		inputs, err := protocolInputs(root, dir, 0, &count, &usedBytes)
		if err != nil {
			return err
		}
		if len(inputs) == 0 {
			return errors.New("org protocol directory needs a Markdown source")
		}
		s.Inputs = append(s.Inputs, inputs...)
	}
	if s.Role != nil {
		s.Inputs = append(s.Inputs, Input{s.Role.Path, s.Role.Bytes}, Input{s.Role.DriverPath, s.Role.DriverBytes})
		if strings.HasPrefix(s.Role.Path, "builtin/") {
			s.Inputs = append(s.Inputs, s.Catalog.Levels[s.Level].DriverInputs...)
		}
	}
	return nil
}

func (s *Selection) Prefix() ([]byte, error) { return s.PrefixWith("") }

// PrefixWith is Prefix with a section of recorded decisions between the role and the task: Markdown that starts with
// its own heading and ends with a blank line, or empty when no decision applies.
func (s *Selection) PrefixWith(decisions string) ([]byte, error) {
	return s.policyWith(decisions, true)
}

// PolicyWith renders the same protocol, role and decisions without introducing
// a task. Automatic idle turns append it after their byte-exact payload in one message.
func (s *Selection) PolicyWith(decisions string) ([]byte, error) {
	return s.policyWith(decisions, false)
}

func (s *Selection) policyWith(decisions string, task bool) ([]byte, error) {
	var output bytes.Buffer
	for _, input := range s.Inputs {
		if strings.HasSuffix(input.Path, ".toml") {
			continue
		}
		if s.Role != nil && (input.Path == s.Role.Path || input.Path == s.Role.DriverPath) {
			continue
		}
		fmt.Fprintf(&output, "## Org protocol: %s\n\n", input.Path)
		output.Write(input.Bytes)
		output.WriteString("\n\n")
	}
	if s.Role != nil {
		if faults.Get("roles-omit-section").Point != "" {
			if err := faults.Reach("roles-omit-section"); err != nil {
				return nil, err
			}
		} else {
			fmt.Fprintf(&output, "## Your role: %s (L%d)\n\n", s.Role.Name, s.Level)
			output.Write(s.Role.Bytes)
			output.WriteString("\n\n")
		}
	}
	output.WriteString(decisions)
	output.WriteString("## What your org hook refuses\n\nRun `laneboss org blacklist list` first and follow the rules it lists; if a call is refused, take its Instead route.\n")
	output.WriteString("Built-in checks also protect Laneboss files and state, L3 worktree boundaries, every lane's network/process-identity/tmux backstops and obscured laneboss calls; secret files require an applicable org rule.\n")
	output.WriteString("Blacklist source files, in hook order (current at the start of this run; hooks read current sources):\n\n")
	for _, filename := range s.BlacklistPaths {
		fmt.Fprintf(&output, "- `%s`\n", filename)
	}
	output.WriteByte('\n')
	if task {
		output.WriteString("## Your task\n\n")
	}
	if output.Len() > 4*1024*1024 {
		return nil, errors.New("org policy prefix exceeds its rendered byte limit")
	}
	return output.Bytes(), nil
}

func (s *Selection) Record(payload map[string]any) {
	var name, hash, driverHash any
	if s.Role != nil {
		name, hash, driverHash = s.Role.Name, Hash(s.Role.Bytes), Hash(s.Role.DriverBytes)
		if strings.HasPrefix(s.Role.Path, "builtin/") && len(s.Catalog.Levels[s.Level].DriverInputs) > 0 {
			bound := append([]byte{}, s.Role.DriverBytes...)
			for _, input := range s.Catalog.Levels[s.Level].DriverInputs {
				bound = append(bound, []byte("\x00"+input.Path+"\x00")...)
				bound = append(bound, input.Bytes...)
			}
			driverHash = Hash(bound)
		}
	}
	payload["role"] = name
	payload["role_context"] = map[string]any{"org_dir": s.Catalog.Root, "level": s.Level, "sha256": hash, "drivers_sha256": driverHash, "org_sha256": Hash(s.Catalog.ConfigBytes), "principal": s.Principal}
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidateEvent keeps historic events readable and checks the optional role
// extension identically in every event reader. Permission is decided by Select.
func ValidateEvent(payload map[string]any) error {
	role, hasRole := payload["role"]
	value, hasContext := payload["role_context"]
	if !hasRole && !hasContext {
		return nil
	}
	context, ok := value.(map[string]any)
	level, levelOK := number(context["level"])
	org, _ := context["org_dir"].(string)
	principal, _ := context["principal"].(string)
	orgHash, _ := context["org_sha256"].(string)
	if !hasRole || !hasContext || !ok || len(context) != 6 || !digestPattern.MatchString(orgHash) || !levelOK || level < 3 || level > 6 || !filepath.IsAbs(org) || len(org) > 4096 || strings.IndexFunc(org, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || (principal != "human" && principal != "supervisor") {
		return errors.New("lane role context has invalid fields")
	}
	for _, key := range []string{"org_dir", "level", "sha256", "drivers_sha256", "org_sha256", "principal"} {
		if _, exists := context[key]; !exists {
			return errors.New("lane role context is incomplete")
		}
	}
	if role == nil {
		if context["sha256"] != nil || context["drivers_sha256"] != nil {
			return errors.New("a lane without a role has no role source hashes")
		}
	} else {
		name, ok := role.(string)
		hash, _ := context["sha256"].(string)
		driverHash, _ := context["drivers_sha256"].(string)
		if !ok || CheckName(name) != nil || !digestPattern.MatchString(hash) || !digestPattern.MatchString(driverHash) {
			return errors.New("lane role or its source hashes are invalid")
		}
	}
	return nil
}

// EventField adapts the shared extension validator to the event stores' field
// validators. It validates the value supplied by the reader, including both
// fields' relationship, rather than assuming the captured payload is valid.
func EventField(payload map[string]any, field string) func(any, string) error {
	return func(value any, _ string) error {
		candidate := map[string]any{"role": payload["role"], "role_context": payload["role_context"]}
		candidate[field] = value
		return ValidateEvent(candidate)
	}
}

// Revet repeats policy at the execution boundary and refuses changed source
// bytes after planning. The worker never runs with a stale rendered policy.
func Revet(home string, data, payload map[string]any, argv []string, screens ...func([]byte) error) error {
	selection, err := Previous(home, data, payload, argv, screens...)
	if err != nil {
		return err
	}
	current := map[string]any{}
	selection.Record(current)
	before, err := json.Marshal(payload["role_context"])
	if err != nil {
		return errors.New("the recorded role context cannot be checked")
	}
	after, err := json.Marshal(current["role_context"])
	if err != nil || !bytes.Equal(before, after) {
		return errors.New("org role sources changed after the run was planned\nInstead: review the edited role sources and start the run again")
	}
	return nil
}

// RunnerProblems reports configured commands that no role at any enabled level
// permits. Start still checks the exact selected pair, rather than this union.
func (c *Catalog) RunnerProblems(runners map[string]any) []string {
	allowed := map[string]bool{}
	for level := range c.Levels {
		for _, driver := range c.Drivers(level) {
			allowed[driver] = true
		}
	}
	problems := []string{}
	for _, name := range sortedKeys(runners) {
		runner, _ := runners[name].(map[string]any)
		for _, kind := range []string{"command", "resume"} {
			var argv []string
			switch words := runner[kind].(type) {
			case []any:
				for _, word := range words {
					text, _ := word.(string)
					argv = append(argv, text)
				}
			case []string:
				argv = words
			}
			if len(argv) == 0 || argv[0] == "" {
				continue
			}
			program, looked := envProgram(argv)
			if !allowed[filepath.Base(argv[0])] && !(looked && allowed[filepath.Base(program)]) {
				problems = append(problems, "runners."+name+"."+kind+": no (level, role) permits its driver"+envHint(argv))
			}
		}
	}
	return problems
}
