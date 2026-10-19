// Command laneboss-org is retained for the GO_GROUPS migration harness.
package main

import (
	"os"

	_ "laneboss.io/laneboss/internal/cli" // Initialize the embedded hook grammar.
	"laneboss.io/laneboss/internal/org"
)

func main() {
	os.Exit(org.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
