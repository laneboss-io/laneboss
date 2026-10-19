package lifecycle

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// captureAllowed points allowAndLog's journal at a buffer for one test and returns a reader of the journaled checks.
func captureAllowed(t *testing.T) func() []string {
	t.Helper()
	var buf bytes.Buffer
	allowedLog.Lock()
	previous := allowedLog.w
	allowedLog.w = &buf
	allowedLog.Unlock()
	t.Cleanup(func() {
		allowedLog.Lock()
		allowedLog.w = previous
		allowedLog.Unlock()
	})
	return func() []string {
		allowedLog.Lock()
		defer allowedLog.Unlock()
		var checks []string
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			var entry struct{ Event, Check string }
			if line != "" && json.Unmarshal([]byte(line), &entry) == nil && entry.Event == "check_allowed" {
				checks = append(checks, entry.Check)
			}
		}
		return checks
	}
}
