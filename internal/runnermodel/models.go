// Package runnermodel translates declared full model names only at invocation.
package runnermodel

import (
	"errors"
	"regexp"
	"sort"
)

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}$`)
var versionDigit = regexp.MustCompile(`[0-9]`)

// Validate checks the optional api_models table without relaxing model fields.
func Validate(value any) error {
	models, ok := value.(map[string]any)
	if !ok {
		return errors.New("must be a table")
	}
	keys := make([]string, 0, len(models))
	for key := range models {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !safeName.MatchString(key) || !versionDigit.MatchString(key) {
			return errors.New("keys must be a full model name that includes its version, not a family alias")
		}
		api, ok := models[key].(string)
		if !ok || !safeName.MatchString(api) {
			return errors.New("values must use the safe model-name character set and contain 1 to 128 characters")
		}
	}
	return nil
}

// API is used only when filling a runner's command or resume template.
// Callers retain fullName in lane metadata, events and record templates.
func API(runner map[string]any, fullName string) string {
	models, _ := runner["api_models"].(map[string]any)
	if api, ok := models[fullName].(string); ok {
		return api
	}
	return fullName
}
