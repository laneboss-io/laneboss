package orghook

import (
	"fmt"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/hookblacklist"
	"laneboss.io/laneboss/internal/rolepolicy"
)

func hookBlacklistRows(rows []hookblacklist.Rule, source, filename string) []blacklistRule {
	result := make([]blacklistRule, 0, len(rows))
	for _, row := range rows {
		description := row.Description
		if source != "" {
			description += " [source: " + source + "]"
		}
		result = append(result, blacklistRule{id: row.ID, description: description, band: row.Band, instead: row.Instead, source: filename,
			argv: row.Argv, argvWords: row.ArgvWords, pathGlob: row.PathGlob, toolGlob: row.ToolGlob, decision: row.Decision, job: row.Job,
			levels: row.Levels, roles: row.Roles, identityScope: row.IdentityScope, patternOnly: row.PatternOnly,
			examplesNotOK: row.ExamplesNotOK, examplesOK: row.ExamplesOK})
	}
	return result
}

func effectiveHookBlacklist(home string, level int, role string, orgRows []blacklistRule) ([]blacklistRule, []string, error) {
	// Historic hook-only orgs need not have a role catalog. If there are any org
	// role sources, load the complete catalog so malformed or duplicate entries
	// at an unrelated pair cannot silently disappear from validation.
	hasRoles := false
	for n := 3; n <= 6; n++ {
		_, err := os.Lstat(filepath.Join(home, fmt.Sprintf("L%d", n), "roles"))
		if err == nil {
			hasRoles = true
		} else if !os.IsNotExist(err) {
			return nil, nil, err
		}
	}
	result := append([]blacklistRule{}, orgRows...)
	if !hasRoles {
		return result, rolepolicy.BlacklistSourcePaths(filepath.Dir(home), nil), nil
	}
	catalog, err := rolepolicy.Load(filepath.Dir(home))
	if err != nil {
		return nil, nil, err
	}
	sources, err := catalog.EffectiveBlacklist(level, role)
	if err != nil {
		return nil, nil, err
	}
	for _, source := range sources {
		result = append(result, hookBlacklistRows(source.Rows, fmt.Sprintf("(L%d, %s)", source.Level, source.Role), source.Path)...)
	}
	return result, rolepolicy.BlacklistSourcePaths(catalog.Root, sources), nil
}
