package api

import (
	"path"
	"strings"
)

// A CA certificate may have a measured PEM name and measured hash names.
// They share one immutable content pin; no directory is an alias target.
func RuntimeAliasesValid(object RuntimeObject) bool {
	if len(object.Aliases) == 0 {
		return true
	}
	if object.Role != "runtime-cert" || object.Mode != 0444 ||
		!strings.HasPrefix(object.RelativePath, "etc/ssl/") || len(object.Aliases) > 8 {
		return false
	}
	seen := map[string]bool{"/" + object.RelativePath: true}
	for _, name := range object.Aliases {
		leaf := strings.TrimPrefix(name, "/etc/ssl/certs/")
		if name != "/etc/ssl/cert.pem" && (leaf == name || leaf == "" || strings.Contains(leaf, "/")) ||
			path.Clean(name) != name || strings.ContainsRune(name, 0) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}
