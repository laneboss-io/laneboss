// Command laneboss-brief is the Go implementation of `laneboss brief`. The Python launcher forwards
// `laneboss brief ...` here, unchanged, when LANEBOSS_BRIEF_GO_BIN names this binary.
package main

import (
	"os"

	"laneboss.io/laneboss/internal/brief"
)

func main() {
	os.Exit(brief.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
