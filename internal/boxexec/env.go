package boxexec

import (
	"os"
	"sort"
	"strings"
)

// CleanEnv copies only five basic variables and then adds sorted extra keys.
func CleanEnv(extra map[string]string) []string {
	env := make([]string, 0, 5+len(extra))
	copied := make(map[string]bool, 5)
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "LANG", "TERM"} {
		value, set := os.LookupEnv(key)
		if !set {
			continue
		}
		if override, ok := extra[key]; ok {
			value = override
		}
		env = append(env, key+"="+value)
		copied[key] = true
	}
	keys := make([]string, 0, len(extra))
	for key := range extra {
		if key != "" && !strings.Contains(key, "=") && !copied[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+extra[key])
	}
	return env
}
