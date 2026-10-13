// Package config loads schema-version-1 configurations shared with the Python
// launcher. It never runs configured commands or changes on-disk state.
//
// Home (also ConfigHome) resolves LANEBOSS_HOME, or ~/.config/laneboss;
// StateHome resolves LANEBOSS_STATE_HOME, or ~/.local/state/laneboss. Overrides
// must be absolute. BoundName resolves --config and LANEBOSS_CONFIG, refusing
// conflicts. Load, Validate and Path accept a name (empty uses BoundName) and
// optional Options containing explicit homes. Named reads respect LANEBOSS_CONFIG;
// ValidateAll refuses a bound session.
//
// Load returns a fully validated Configuration. Data and Projects contain TOML
// values (integers are int64); legacy supervisor roles become levels. Optional
// defaults are not inserted into Data. Rules and IdleMessage retain the exact
// bytes checked during loading. Paths and Describe produce the CLI JSON objects.
// TableKeys preserves the file's table-entry order for callers selecting runners
// or rendering briefings; Go maps themselves do not preserve that order.
// Errors have a safe Prefix and exit Code and never include rejected values.
// Files must be regular, bounded, UTF-8 and contained in their configuration or
// organisation directory, including through symlinks. A configuration directory
// itself may be a symlink. State overlap is checked by filesystem identity,
// including missing paths below existing ancestors.
// Load checks state against the homes and reserved default state locations;
// ValidateAll additionally compares every configuration's state location. State
// readers and writers must separately check cross-configuration isolation and
// ownership markers, as the Python Zones and StateDir implementations do.
//
// Regular expressions use Go's bounded regexp syntax. Unsupported Python-only
// constructs are refused. Guards still reject nested unbounded repetitions.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/cliargs"
	"laneboss.io/laneboss/internal/identity"
)

const (
	Program             = identity.Program
	Version             = identity.Version
	EnvPrefix           = identity.EnvPrefix
	SchemaVersion       = 1
	NameRule            = "[a-z0-9][a-z0-9-]{0,31}"
	MaxFileBytes        = 1024 * 1024
	MaxIdleMessageBytes = 64 * 1024
	StoreFile           = "events.sqlite"
	Marker              = ".laneboss-state"
	DefaultWarnPercent  = 85
	DefaultStopPercent  = 90
)

// Error is a safe refusal or invalid-configuration error.
type Error struct {
	Code    int
	Prefix  string
	Message string
}

func (e *Error) Error() string     { return e.Message }
func refused(message string) error { return &Error{2, "refused", message} }
func invalid(message string) error { return &Error{2, "invalid configuration", message} }

// EnvName returns the launcher's environment-variable name for suffix.
func EnvName(suffix string) string { return EnvPrefix + suffix }

// Options supplies explicit homes. Empty fields use environment/defaults.
type Options struct {
	Home      string
	StateHome string
}

// Home resolves the configuration home without creating directories.
func Home() (string, error) { return resolveHome("HOME", ".config") }

// ConfigHome is an alias for Home.
func ConfigHome() (string, error) { return Home() }

// StateHome resolves the state home without creating directories.
func StateHome() (string, error) { return resolveHome("STATE_HOME", ".local", "state") }

func resolveHome(suffix string, parts ...string) (string, error) {
	if value := os.Getenv(EnvName(suffix)); value != "" {
		if !filepath.IsAbs(value) {
			return "", refused(EnvName(suffix) + " must be an absolute path")
		}
		return filepath.Clean(value), nil
	}
	user, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(user) {
		return "", refused("cannot resolve the user's home directory")
	}
	parts = append([]string{user}, parts...)
	return filepath.Join(append(parts, Program)...), nil
}

func homes(options []Options) (string, string, error) {
	if len(options) > 1 {
		return "", "", refused("only one set of configuration-home options is allowed")
	}
	var option Options
	if len(options) == 1 {
		option = options[0]
	}
	home, states := option.Home, option.StateHome
	var err error
	if home == "" {
		home, err = Home()
	}
	if err != nil {
		return "", "", err
	}
	if states == "" {
		states, err = StateHome()
	}
	if err != nil {
		return "", "", err
	}
	if !filepath.IsAbs(home) || !filepath.IsAbs(states) {
		return "", "", refused("configuration and state homes must be absolute paths")
	}
	return filepath.Clean(home), filepath.Clean(states), nil
}

// CheckName checks a name without echoing its value.
func CheckName(name string) error {
	if !namePattern.MatchString(name) {
		return refused("the configuration name must match " + NameRule)
	}
	return nil
}

func shownName(name string) string {
	if detectText(name) != nil {
		return "[withheld]"
	}
	return name
}

// BoundName resolves --config and LANEBOSS_CONFIG without guessing. An empty
// cliValue means that no explicit --config option was supplied.
func BoundName(cliValue string) (string, error) {
	environment := os.Getenv(EnvName("CONFIG"))
	if cliValue != "" && environment != "" {
		if !namePattern.MatchString(cliValue) {
			return "", refused("the configuration name given by --config must match " + NameRule)
		}
		if !namePattern.MatchString(environment) {
			return "", refused("the configuration name in LANEBOSS_CONFIG must match " + NameRule)
		}
		if cliValue != environment {
			return "", refused("--config " + shownName(cliValue) + " conflicts with LANEBOSS_CONFIG=" + shownName(environment) + "; a session is bound to exactly one configuration")
		}
	}
	name := cliValue
	if name == "" {
		name = environment
	}
	if name == "" {
		home, err := Home()
		if err != nil {
			return "", err
		}
		description, err := describeNames(home)
		if err != nil {
			return "", err
		}
		return "", refused("no configuration is bound: pass --config NAME or set LANEBOSS_CONFIG; " + description)
	}
	return name, CheckName(name)
}

// GuardNamed refuses a named read outside the bound configuration.
func GuardNamed(name string) error {
	if err := CheckName(name); err != nil {
		return err
	}
	environment := os.Getenv(EnvName("CONFIG"))
	if environment != "" && environment != name {
		if !namePattern.MatchString(environment) {
			return refused("the configuration name in LANEBOSS_CONFIG must match " + NameRule)
		}
		return refused("this session is bound to LANEBOSS_CONFIG=" + shownName(environment) + "; reading configuration " + shownName(name) + " is refused")
	}
	return nil
}

// ListNames lists valid names that contain config.toml, in lexical order.
// Listing is allowed in a bound session and does not depend on STATE_HOME.
func ListNames(options ...Options) ([]string, error) {
	if len(options) > 1 {
		return nil, refused("only one set of configuration-home options is allowed")
	}
	var home string
	if len(options) == 1 {
		home = options[0].Home
	}
	if home == "" {
		var err error
		home, err = Home()
		if err != nil {
			return nil, err
		}
	}
	if !filepath.IsAbs(home) {
		return nil, refused("the configuration home must be an absolute path")
	}
	return listNames(filepath.Clean(home))
}

func listNames(home string) ([]string, error) {
	configs := filepath.Join(home, "configs")
	entries, err := os.ReadDir(configs)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, refused("cannot list " + safePath(configs))
	}
	names := []string{}
	for _, entry := range entries {
		if !namePattern.MatchString(entry.Name()) {
			continue
		}
		info, err := os.Stat(filepath.Join(configs, entry.Name(), "config.toml"))
		if err == nil && info.Mode().IsRegular() {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

func describeNames(home string) (string, error) {
	names, err := listNames(home)
	if err != nil {
		return "", err
	}
	for i, name := range names {
		names[i] = shownName(name)
	}
	if len(names) > 0 {
		return "configurations: " + strings.Join(names, ", "), nil
	}
	return "no configuration exists under " + safePath(filepath.Join(home, "configs")), nil
}

// RuleFile holds a validated file's public label and exact bytes.
type RuleFile struct {
	Path  string
	Bytes []byte
}

// Configuration contains validated data and every derived path.
type Configuration struct {
	Name              string
	Home              string
	StateHome         string
	ConfigDir         string
	ConfigFile        string
	StateDir          string
	Store             string
	Data              map[string]any
	Projects          map[string]map[string]any
	RuleBytes         map[string][]byte
	Organisation      string
	OrganisationTools string
	OrganisationBytes map[string][]byte
	IdleMessage       *RuleFile
	tableOrder        map[string][]string
}

// TableKeys returns a copy of a table's keys in their original TOML order. Pass
// no path for the top level, "runners" for runner names, or "supervisors", name
// for one supervisor's fields. Legacy role keys are returned as level keys.
func (c *Configuration) TableKeys(path ...string) []string {
	return append([]string(nil), c.tableOrder[strings.Join(path, ".")]...)
}

// Paths returns the directories, store and Python-compatible tmux socket.
func (c *Configuration) Paths() map[string]string {
	digest := sha256.Sum256([]byte(realPath(c.StateDir)))
	socket := filepath.Join(fmt.Sprintf("/tmp/%s-%d", Program, os.Getuid()), c.Name+"-"+hex.EncodeToString(digest[:])[:12])
	return map[string]string{"name": c.Name, "config_dir": c.ConfigDir, "config_file": c.ConfigFile, "state_dir": c.StateDir, "store": c.Store, "socket": socket}
}

// Describe returns the config show's JSON object without adding defaults.
func (c *Configuration) Describe() map[string]any {
	return map[string]any{"name": c.Name, "config_dir": c.ConfigDir, "state_dir": c.StateDir, "config": c.Data, "projects": c.Projects}
}

// Rules returns organisation, configuration and project rules, in that order.
// An empty project selects configuration rules only.
func (c *Configuration) Rules(project string) ([]RuleFile, error) {
	listed := stringsOf(c.Data["rules"])
	if project != "" {
		data, exists := c.Projects[project]
		if !exists {
			return nil, refused("the project is not defined in the configuration")
		}
		for _, path := range stringsOf(data["rules"]) {
			if !contains(listed, path) {
				listed = append(listed, path)
			}
		}
	}
	result := []RuleFile{}
	for _, path := range stringsOf(c.Data["organisation_rules"]) {
		result = append(result, RuleFile{Path: "orgs/" + c.Organisation + "/" + path, Bytes: append([]byte(nil), c.OrganisationBytes[path]...)})
	}
	for _, path := range listed {
		result = append(result, RuleFile{Path: path, Bytes: append([]byte(nil), c.RuleBytes[path]...)})
	}
	return result, nil
}

// Validate validates one configuration without creating state.
func Validate(name string, options ...Options) error { _, err := Load(name, options...); return err }

// Path loads a configuration and returns its derived paths.
func Path(name string, options ...Options) (map[string]string, error) {
	c, err := Load(name, options...)
	if err != nil {
		return nil, err
	}
	return c.Paths(), nil
}

// DiskSettings applies disk defaults without modifying configuration data.
func (c *Configuration) DiskSettings() (path string, warn, stop int64, err error) {
	disk := tableOf(c.Data["disk"])
	path = stringOf(disk["path"])
	if path == "" {
		path, err = os.UserHomeDir()
		if err != nil {
			return "", 0, 0, refused("cannot resolve the user's home directory")
		}
	}
	return path, intDefault(disk, "warn_percent", DefaultWarnPercent), intDefault(disk, "stop_percent", DefaultStopPercent), nil
}

func printError(err error, stderr io.Writer) int {
	var failure *Error
	if errors.As(err, &failure) {
		for _, line := range strings.Split(failure.Message, "\n") {
			fmt.Fprintln(stderr, failure.Prefix+": "+line)
		}
		return failure.Code
	}
	if errors.Is(err, syscall.EPIPE) {
		return 0
	}
	fmt.Fprintln(stderr, "internal error: configuration operation failed")
	return 70
}

const usage = "usage: laneboss config {list,show,validate,path} ..."

// Run executes laneboss config ARGS and returns the exit code. Usage errors omit
// supplied tokens, which might themselves contain credentials.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	_ = stdin
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return printError(refused(cliargs.Required("ACTION")), stderr)
	}
	if args[0] == "--help" || args[0] == "-h" {
		if len(args) != 1 {
			return printError(refused(cliargs.Reject("")), stderr)
		}
		fmt.Fprintln(stdout, usage+"\n\nlist\nshow NAME\nvalidate NAME | --all\npath NAME")
		return 0
	}
	action := args[0]
	if action != "list" && action != "show" && action != "validate" && action != "path" {
		return printError(refused(cliargs.Reject("ACTION")), stderr)
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	var result any
	var err error
	if action == "list" && len(args) == 1 {
		result, err = ListNames()
	} else if action == "validate" && len(args) == 2 && args[1] == "--all" {
		var names []string
		names, err = ValidateAll()
		if err == nil {
			result = map[string]any{"valid": true, "configs": names}
		}
	} else {
		remaining := args[1:]
		if len(remaining) == 2 && remaining[0] == "--" {
			remaining = remaining[1:]
		}
		if action == "list" || len(remaining) != 1 || strings.HasPrefix(remaining[0], "-") {
			fmt.Fprintln(stderr, usage)
			return printError(refused(cliargs.Reject("")), stderr)
		}
		// An explicitly empty CLI name is invalid, even though Load("") lets
		// library callers request the environment binding.
		if err := GuardNamed(remaining[0]); err != nil {
			return printError(err, stderr)
		}
		var configuration *Configuration
		configuration, err = Load(remaining[0])
		if err == nil {
			switch action {
			case "show":
				result = configuration.Describe()
			case "validate":
				result = map[string]any{"valid": true, "configs": []string{configuration.Name}}
			case "path":
				result = configuration.Paths()
			}
		}
	}
	if err != nil {
		return printError(err, stderr)
	}
	if where, rule := detectValue(result); rule != "" {
		return printError(refused("configuration output: "+where+": looks like a credential ("+rule+"); output was withheld"), stderr)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(result); err != nil {
		return printError(err, stderr)
	}
	return 0
}
