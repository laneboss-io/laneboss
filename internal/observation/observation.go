// Package observation defines the independent command-observation contract.
// General event validators still check identifiers, excerpts and record bounds.
package observation

import "fmt"

const Kind = "shell-substitution-in-text"

// Payload is shared by the ordinary and live-turn scanners. All numbers are
// emitted as JSON integers; readers must preserve that distinction on replay.
func Payload(run int, suspicion string, tool, at any, command map[string]any, id any, record map[string]any) map[string]any {
	return map[string]any{
		"run": int64(run), "suspicion": suspicion, "refusal": nil,
		"how": []any{Kind}, "paths": []any{"(command)"}, "tool": tool,
		"at": at, "command": command,
		"call": map[string]any{"id": id, "record": record}, "similarity": nil,
	}
}

func Position(path string, line int, offset int64, item int) map[string]any {
	return map[string]any{"path": path, "line": int64(line), "offset": offset, "item": int64(item)}
}

func stringsIn(value any) []string {
	switch values := value.(type) {
	case []string:
		return values
	case []any:
		out := make([]string, len(values))
		for i, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil
			}
			out[i] = text
		}
		return out
	}
	return nil
}

// Check distinguishes observations from refusal-linked suspicions after the
// reader's field validation. It reports field names, never stored values.
func Check(payload map[string]any) error {
	how := stringsIn(payload["how"])
	independent := false
	for _, way := range how {
		independent = independent || way == Kind
	}
	paths := stringsIn(payload["paths"])
	if independent != (payload["refusal"] == nil) || independent && (len(how) != 1 || len(paths) != 1 || paths[0] != "(command)") {
		return fmt.Errorf("payload.refusal: only %s is an independent command observation", Kind)
	}
	if independent && payload["similarity"] != nil {
		return fmt.Errorf("payload.similarity: is null for an independent command observation")
	}
	return nil
}
