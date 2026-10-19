package wire

import (
	"encoding/json"
	"sort"
	"strings"
)

// Independent ownership oracle: only frozen grammar and standard JSON. These
// literal JSON paths intentionally do not import production's path table.
func frozenCallerScreen(root map[string]any, key string) (bool, []string) {
	state, stateOK := root["state"].(map[string]any)
	_, modelOK := root["model"].(string)
	_, questionsOK := root["questions"].(map[string]any)
	commands, commandsOK := state["commands"].([]any)
	if !stateOK || !modelOK || !questionsOK || !commandsOK || len(commands) > 1 {
		return fix1Sensitive(root, key), nil
	}
	schema := map[string]string{
		"$":                              "model questions state",
		"$.state":                        "commands rules context task decisions",
		"$.state.commands[]":             "command cwd argv declared_paths tool raw_sha256",
		"$.state.context":                "config cwd grant_set_id grants_sha256 logical_turn_id policy_generation target role",
		"$.state.context.target":         "life_id run",
		"$.state.context.role":           "level role instance_id",
		"$.state.rules[]":                "id text source_sha256 criteria_version",
		"$.state.decisions[]":            "id text source authority effective_at applies_to binding",
		"$.state.decisions[].source":     "id path sha256 generation",
		"$.state.decisions[].authority":  "kind receipt_id org_generation source_seq",
		"$.state.decisions[].applies_to": "levels roles project_ids life_ids",
		"$.questions.*":                  "instructions type criteria",
		"$.questions.*.criteria":         "true false",
	}
	metadata := map[string]bool{}
	// Decision IDs/receipts are store-generated. Org-authored paths, UTC
	// timestamps and applicability come from the authoritative store snapshot;
	// resolveQuestions requires full candidate equality. Text stays joined.
	for _, path := range []string{
		"$.model", "$.state.commands[].raw_sha256",
		"$.state.context.config", "$.state.context.grant_set_id", "$.state.context.grants_sha256",
		"$.state.context.logical_turn_id", "$.state.context.policy_generation",
		"$.state.context.target.life_id", "$.state.context.target.run",
		"$.state.context.role.level", "$.state.context.role.role", "$.state.context.role.instance_id",
		"$.state.rules[].id", "$.state.rules[].text", "$.state.rules[].source_sha256", "$.state.rules[].criteria_version",
		"$.state.decisions[].id", "$.state.decisions[].effective_at",
		"$.state.decisions[].source.id", "$.state.decisions[].source.path",
		"$.state.decisions[].source.sha256", "$.state.decisions[].source.generation",
		"$.state.decisions[].authority.kind", "$.state.decisions[].authority.receipt_id",
		"$.state.decisions[].authority.org_generation", "$.state.decisions[].authority.source_seq",
		"$.state.decisions[].applies_to.roles[]", "$.state.decisions[].applies_to.project_ids[]",
		"$.state.decisions[].applies_to.life_ids[]",
		"$.questions.*.instructions", "$.questions.*.type",
		"$.questions.*.criteria.true", "$.questions.*.criteria.false",
	} {
		metadata[path] = true
	}
	var names, values, combined, excluded []string
	individual := false
	phase := 0
	check := func(text string) bool {
		return key != "" && strings.Contains(text, key) || fix1SecretText(text)
	}
	var walk func(any, string, bool)
	walk = func(value any, path string, join bool) {
		switch v := value.(type) {
		case string:
			individual = individual || check(v)
			trimmed := strings.TrimSpace(v)
			encoded := len(trimmed) > 0 && strings.ContainsRune("{[\"", rune(trimmed[0])) && json.Valid([]byte(trimmed))
			if join && !(phase == 1 && encoded) {
				values = append(values, v)
				combined = append(combined, v)
			} else if !join {
				excluded = append(excluded, path)
			}
			if encoded {
				var decoded any
				if json.Unmarshal([]byte(trimmed), &decoded) != nil {
					individual = true
					return
				}
				if !join {
					individual = individual || fix1Sensitive(decoded, key)
				}
				walk(decoded, "#", join)
			}
		case map[string]any:
			keys := make([]string, 0, len(v))
			for name := range v {
				keys = append(keys, name)
			}
			sort.Strings(keys)
			if phase == 1 && path == "$.state.commands[]" {
				rank := map[string]int{"cwd": 0, "command": 1, "argv": 2, "declared_paths": 3, "tool": 4, "raw_sha256": 5}
				sort.SliceStable(keys, func(i, j int) bool {
					a, first := rank[keys[i]]
					b, second := rank[keys[j]]
					return first && (!second || a < b)
				})
			}
			for _, name := range keys {
				individual = individual || check(name)
				next, known := "#", false
				if path == "$.questions" {
					next, known = "$.questions.*", true
				} else {
					for _, field := range strings.Fields(schema[path]) {
						if name == field {
							next, known = path+"."+name, true
							break
						}
					}
				}
				if known {
					excluded = append(excluded, next+" (key)")
				} else if join {
					names = append(names, name)
					combined = append(combined, name)
				}
				if text, ok := v[name].(string); ok && fix1SensitiveName.MatchString(name) && fix1LiteralQuoted(text) {
					individual = true
				}
				childJoin := join
				if _, scalar := v[name].(string); scalar && metadata[next] {
					childJoin = false
				}
				walk(v[name], next, childJoin)
			}
		case []any:
			next := "#"
			if path == "$.state.commands" || path == "$.state.rules" || path == "$.state.decisions" ||
				path == "$.state.decisions[].applies_to.roles" || path == "$.state.decisions[].applies_to.project_ids" ||
				path == "$.state.decisions[].applies_to.life_ids" {
				next = path + "[]"
			}
			for _, child := range v {
				childJoin := join
				if _, scalar := child.(string); scalar && metadata[next] {
					childJoin = false
				}
				walk(child, next, childJoin)
			}
		}
	}
	for phase = 0; phase < 2; phase++ {
		names, values, combined = nil, nil, nil
		walk(root, "$", true)
		if individual {
			return true, excluded
		}
		for _, parts := range [][]string{names, values, combined} {
			for _, separator := range []string{"", " "} {
				text := strings.Join(parts, separator)
				if key != "" && strings.Contains(text, key) || fix1CredentialText(text) {
					return true, excluded
				}
			}
		}
	}
	return false, excluded
}
