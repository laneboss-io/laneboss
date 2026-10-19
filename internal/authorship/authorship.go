// Package authorship reserves human provenance for internal dashboard writes.
package authorship

import "strings"

func Reserved(value string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "human")
}
