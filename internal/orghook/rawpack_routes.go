package orghook

import (
	"path/filepath"
	"strings"
)

// protectedWriteRoute selects wording only, after the existing protected-path
// gate has refused. It grants no write scope and changes no refusal boundary.
func protectedWriteRoute(inst *instance, target string) string {
	path := filepath.ToSlash(filepath.Clean(target))
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "lanes" && i+2 < len(parts) && parts[i+2] == "mail" {
			return "laneboss lane send"
		}
		if part == "reports" {
			return "laneboss report"
		}
	}
	base := filepath.Base(target)
	if inside(target, filepath.Join(inst.home, "shared", "state")) ||
		strings.HasPrefix(base, "owner-discord.") || strings.HasPrefix(base, "owner-form.") {
		return "laneboss report"
	}
	return "Leave Laneboss policy and records unchanged and report the requested change to the supervisor."
}

// A raw backstop may match a whole protected root before the parsed write gate
// sees the leaf. Retain that gate's decision and use its literal leaf for text.
func rawProtectedRouteTarget(protected string, targets []rawTarget) string {
	for _, target := range targets {
		path, err := pathAt(target.word, target.directory)
		if err == nil && inside(path, protected) {
			return path
		}
	}
	return protected
}
