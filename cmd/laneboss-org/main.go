// Command laneboss-org is retained for the GO_GROUPS migration harness.
package main

import (
	"os"

	"laneboss.io/laneboss/internal/org"
)

func main() {
	os.Exit(org.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
