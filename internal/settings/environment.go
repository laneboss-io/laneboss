package settings

import (
	"errors"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/faults"
)

var BaseEnv = []string{"PATH", "HOME", "LANG", "TERM", "TMPDIR"}
var LauncherEnv = []string{"LANEBOSS_HOME", "LANEBOSS_STATE_HOME", "LANEBOSS_PROCESSES", "LANEBOSS_TEST_CLAIMS_DIR"}

func ReservedEnv(name string) bool {
	return strings.HasPrefix(name, "LANEBOSS_") || name == "TMUX" || name == "TMUX_PANE" || strings.HasPrefix(name, "TMUX_")
}

// Environment filters an explicit launch-time environment snapshot. Fixed
// launcher identity replaces inherited labels, and tmux names never survive.
// The fault is an actual inheritance mutation, available only in tagged builds.
func Environment(input []string, snapshot any, fixed map[string]string) ([]string, error) {
	allowed := map[string]bool{}
	for _, name := range BaseEnv {
		allowed[name] = true
	}
	for _, name := range LauncherEnv {
		allowed[name] = true
	}
	if snapshot != nil {
		s, err := Decode(snapshot)
		if err != nil {
			return nil, err
		}
		for _, name := range Strings(s.Values["env_allow"]) {
			allowed[name] = true
		}
	}
	mutant := faults.Get("settings-inherit-env").Point != ""
	if mutant {
		if err := faults.Reach("settings-inherit-env"); err != nil {
			return nil, err
		}
	}
	values := map[string]string{}
	for _, item := range input {
		name, value, ok := strings.Cut(item, "=")
		if !ok || !envName.MatchString(name) {
			continue
		}
		if mutant || allowed[name] {
			values[name] = value
		}
	}
	for name := range values {
		if ReservedEnv(name) && !allowed[name] {
			delete(values, name)
		}
	}
	for name, value := range fixed {
		if !envName.MatchString(name) || !strings.HasPrefix(name, "LANEBOSS_") {
			return nil, errors.New("invalid fixed launcher environment name")
		}
		values[name] = value
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+values[name])
	}
	return result, nil
}
