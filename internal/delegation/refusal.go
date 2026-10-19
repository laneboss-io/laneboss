package delegation

import (
	"crypto/sha256"
	"fmt"
)

// Unresolved refuses names whose starter no longer resolves and which have no
// independent current owner grant. Its cause stays out of the displayed error.
type Unresolved struct {
	Starter string
	cause   error
}

func (e *Unresolved) Error() string {
	return fmt.Sprintf("delegation starter %s cannot be resolved; delegated names have no current owner grant\nInstead: re-attach the starter instance, or have the owner grant the names at org, role or instance level, then resume.", e.Starter)
}

func (e *Unresolved) Unwrap() error { return e.cause }

// Record describes the launcher's own refusal log, never a runner session
// record. Callers retain the bytes at path before appending this lane.refusal.
func (e *Unresolved) Record(run int, path string) ([]byte, map[string]any) {
	message := "refused: " + e.Error()
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(message)))
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(path)))
	payload := map[string]any{
		"run": run, "refusal": "rf-" + id[:24], "guard": "settings-delegation", "kind": "permission",
		"format": "text", "via": "log", "hook": nil, "tool": nil, "at": nil, "command": nil,
		"message": map[string]any{"text": message, "withheld": false, "length": len(message), "sha256": hash},
		"targets": []string{}, "call": nil,
		"record": map[string]any{"path": path, "line": 1, "offset": 0, "item": 0}, "workarounds_checked": false,
	}
	return []byte(message + "\n"), payload
}
