package migration

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

var legacySessionPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var legacyBasePattern = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
var legacyBranchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)

func legacyArgument(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && !strings.HasPrefix(value, "-") &&
		strings.IndexFunc(value, func(r rune) bool { return r <= 32 || r == 127 }) < 0
}

func validateLegacyRelaunch(target LegacyUnfinishedSession) error {
	if !ValidID(api.ID(target.Lane)) || !legacyArgument(target.Lane) {
		return invalidErr("legacy.lane is invalid")
	}
	if !legacySessionPattern.MatchString(target.SessionID) {
		return invalidErr("legacy.session_id is invalid")
	}
	branch := target.Branch
	if branch == "" {
		branch = target.Lane
	}
	if !legacyBranchPattern.MatchString(branch) || validateRelativePath(branch) != nil || strings.Contains(branch, "..") || strings.Contains(branch, "@{") || strings.HasSuffix(branch, ".lock") || strings.HasSuffix(branch, ".") {
		return invalidErr("legacy.branch is invalid")
	}
	for _, part := range strings.Split(branch, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return invalidErr("legacy.branch component is invalid")
		}
	}
	if !legacyBasePattern.MatchString(target.Base) {
		return invalidErr("legacy.base is invalid")
	}
	if !legacyArgument(target.Model) {
		return invalidErr("legacy.model is invalid")
	}
	if !legacyEffort(target.Driver, target.Effort) {
		return invalidErr("legacy.effort is invalid")
	}
	if target.Driver != api.DriverClaudock && target.Driver != api.DriverCodex {
		return invalidErr("legacy.runner is invalid")
	}
	return nil
}

func legacyEffort(driver api.Driver, effort string) bool {
	if effort == "" {
		return true
	}
	if driver == api.DriverClaudock {
		return effort == "low" || effort == "medium" || effort == "high" || effort == "max"
	}
	switch effort {
	case "minimal", "low", "medium", "high", "xhigh", "max", "ultra":
		return true
	}
	return false
}
