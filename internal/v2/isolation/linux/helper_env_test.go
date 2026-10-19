package linux

import (
	"testing"
)

// Fixed helper state must not be replaceable through task-secret injection.
func TestHelperNames(t *testing.T) {
	for _, name := range []string{"HOME", "PATH", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
		"XDG_STATE_HOME", "CLAUDE_CONFIG_DIR", "CLAUDOCK_CREDENTIAL_STORE", "CLAUDOCK_REGISTRY_DIR"} {
		t.Run(name, func(t *testing.T) {
			if err := validateEnvironmentNames([]string{name}); err == nil {
				t.Fatal("task injection can replace fixed helper state")
			}
		})
	}
}
