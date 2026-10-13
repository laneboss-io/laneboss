// Command laneboss-start is the Go implementation of `laneboss start`. The Python launcher forwards
// `laneboss start ...` here, unchanged, when LANEBOSS_START_GO_BIN names this binary.
package main

import (
	"os"

	"laneboss.io/laneboss/internal/start"
)

func main() {
	os.Exit(start.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
