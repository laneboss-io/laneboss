package caller

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"laneboss.io/laneboss/internal/config"
)

// ConfiguredOrgRoot selects the protected org named by the loaded configuration.
// Credential-bearing report channels must not discover an org from a lane's
// working directory or an environment-supplied path.
func ConfiguredOrgRoot(c *config.Configuration) string {
	if c == nil || !filepath.IsAbs(c.Home) {
		return ""
	}
	name, _ := c.Data["organisation"].(string)
	if !roleName.MatchString(name) {
		return ""
	}
	root := filepath.Join(c.Home, "orgs", name)
	if _, err := os.Lstat(filepath.Join(root, ".laneboss", "org.toml")); os.IsNotExist(err) {
		return ""
	}
	// Existing malformed metadata and inspection errors still reach the
	// checked org reader, which refuses them instead of hiding a failure.
	return root
}

// ProcessStart gives terminal-ticket writers the same identity format used by
// ProcessAlive, including the configured portable process-table reader.
func ProcessStart(pid int) (string, error) {
	if pid < 1 {
		return "", fmt.Errorf("invalid terminal process identity")
	}
	table, err := processTable()
	if err != nil {
		return "", err
	}
	p, ok := table[pid]
	if !ok || strings.HasPrefix(p.State, "Z") {
		return "", nil
	}
	return p.Start, nil
}
