// Command laneboss-plugin is the Go implementation of `laneboss plugin`. The Python launcher forwards
// `laneboss plugin ...` here, unchanged, when LANEBOSS_PLUGIN_GO_BIN names this binary.
package main

import (
	"os"

	"laneboss.io/laneboss/internal/plugin"
)

func main() {
	os.Exit(plugin.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
