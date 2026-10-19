package orgtree

import "strings"

const hookDeprecation = "strict mode and tool allowlists were removed in 1.0.0; the org hook enforces only blacklist entries, obscured forms and protected files"

// Report one warning for the ignored legacy policy, without changing its bytes.
func (t *tree) hookDeprecations() []problem {
	_, versioned := t.configuration["schema_version"]
	legacy := !versioned
	if hooks, ok := t.configuration["hooks"].(map[string]any); ok {
		legacy = legacy || hooks["mode"] == "strict"
	}
	var hasAllowlist func(any) bool
	hasAllowlist = func(value any) bool {
		if table, ok := value.(map[string]any); ok {
			if table["kind"] == "tool-allowlist" {
				return true
			}
			for key, child := range table {
				if key == "allowed_tools" || key == "tool_allow_add" {
					if values, ok := array(child); ok && len(values) > 0 {
						return true
					}
				}
				if hasAllowlist(child) {
					return true
				}
			}
		} else if values, ok := array(value); ok {
			for _, child := range values {
				if hasAllowlist(child) {
					return true
				}
			}
		}
		return false
	}
	for name, text := range t.files {
		if strings.HasSuffix(name, ".toml") {
			if data, err := decodeTOML(text); err == nil && hasAllowlist(data) {
				legacy = true
			}
		}
	}
	if !legacy {
		return nil
	}
	return []problem{{"(hooks: ignored allowed_tools, tool_allow_add and tool-allowlist rules)", hookDeprecation}}
}
