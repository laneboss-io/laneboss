//go:build linux && laneboss_root_canary

package admin

import (
	"os"
	"runtime"
)

// Assert the actual runtime setting before any real fixed bootstrap entry.
// This enrolled artifact still executes the production bootstrap and worker.
func init() {
	if len(os.Args) > 2 && os.Args[1] == FixedBootstrapEntry && runtime.GOMAXPROCS(0) != 1 {
		os.Stderr.WriteString("fixed bootstrap runtime bound absent\n")
		os.Exit(85)
	}
}
