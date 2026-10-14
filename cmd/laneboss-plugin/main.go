// Command laneboss-plugin is retained for the GO_GROUPS migration harness.
// The installed laneboss binary calls the same internal command entry points.
package main

import (
	"os"

	"laneboss.io/laneboss/internal/plugin"
)

func main() {
	os.Exit(plugin.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
